# Vue SPA 深度源码分析 — 实战案例

> 目标: 223.109.241.56:8080
> 框架: Vue 3 + Vite
> JS 大小: 1.2MB (index-BdEkOaE1.js)
> 后端: 自定义 HTTP API (非标准 JSON 响应)
> 系统: 代理出口业务管理平台

---

## 一、发现阶段

### 1.1 区分 Vite vs Webpack 构建产物

| 特征 | Vite (Vue 3) | Webpack (Vue 2) |
|------|-------------|----------------|
| JS 文件名 | `assets/index-xxx.js` | `js/chunk-xxx.js` / `js/app.xxx.js` |
| CSS 文件名 | `assets/index-xxx.css` | `css/app.xxx.css` |
| HTML 入口 | `index.html` 引用 `<script type="module">` | `index.html` 引用 `<script src=...>` |
| 构建大小 | 通常 1-2MB (Vite 默认不拆分) | 按路由拆分多个 chunk |

### 1.2 Vue 版本快速判断

```bash
# 在浏览器 Console 中
document.querySelector('#app')       # Vue 2 & 3 都有
document.__vue_app__                  # Vue 3 专有

# 从 JS 文件名
# assets/index-xxx.js         → Vite + Vue 3
# js/chunk-vendors.xxx.js    → Webpack + Vue 2
```

---

## 二、JS 源码分析技术

### 2.1 下载与格式化

```bash
# 先找到主页中的 JS 引用
curl -sk http://target:8080/ | grep -oP 'src="[^"]*\.js[^"]*"' 
# → src="./assets/index-BdEkOaE1.js"

# 下载 JS 文件
curl -sk "http://target:8080/assets/index-BdEkOaE1.js" -o bundle.js
ls -lh bundle.js  # 1.2M
```

### 2.2 提取所有 API 端点

```bash
# 基础 API 路径提取
grep -oP '/[a-z_]+/[a-z_/0-9.-]+' bundle.js | sort -u | head -50

# 提取完整的 Axios 调用 (能显示 HTTP 方法和路径)
grep -oP '(be\.(get|post|put|delete))\([^)]+\)' bundle.js | sort -u

# 输出示例:
# be.get("/auth/me")
# be.get("/dashboard/bandwidth")
# be.get("/dashboard/daily",{params:{days:r}})
# be.get("/dashboard/disk")
# be.post("/auth/login",{username:r,password:t})
# be.post("/auth/logout")
# be.post("/keys",{name:r})
# be.delete("/keys",{params:{name:r}})
```

### 2.3 提取 Vue Router 路由结构

```bash
# 路由路径提取 (path:"/xxx" 模式)
grep -oP 'path:"[^"]*"' bundle.js | sort -u

# 输出示例:
# path:"/"
# path:"/login"
# path:"/proxies"
# path:"/keys"
# path:"/whitelist"
# path:"/history"
```

### 2.4 提取 Axios 配置 (baseURL/认证/拦截器)

```bash
# 找到 Axios 实例创建代码
grep -oP '(Ae\.create|axios\.create)\([^}]+\)' bundle.js | head -5

# 输出示例:
# Ae.create({baseURL:"/api",timeout:1e4,withCredentials:!0})

# 提取拦截器行为
grep -oP '.{0,40}interceptors.response.use.{0,100}' bundle.js | head -3

# 提取 401 处理逻辑
grep -oP '.{0,30}status===401.{0,80}' bundle.js

# 提取轮询间隔
grep -oP 'setInterval\([^,]+,\s*[0-9]+' bundle.js | sort -u

# 输出:
# setInterval(b,30000)
# setInterval(S,5000)
```

### 2.5 提取中文 UI 文本 (功能推测)

```bash
# 提取中文文本理解系统功能
grep -oP '[\x{4e00}-\x{9fa5}][\x{4e00}-\x{9fa5}]{1,10}' bundle.js | sort -u | head -50

# 典型输出:
# 业务密钥  → CRUD 密钥管理
# 节点列表  → 代理节点管理
# 白名单    → IP 白名单 (带 TTL 过期)
# 今日峰值   → 流量统计
# 上行/下行  → 带宽统计
# 仅白名单内的 → 权限控制描述
```

---

## 三、API 前缀发现

### 3.1 确认真实 API 前缀

```bash
# JS 中写的是 "/auth/login"，但实际 API 可能在 /api/auth/login
# 通过 POST 测试不同前缀

# 测试 /api/auth/login
curl -s -X POST http://target:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# → "invalid credentials" ✅ 这是真实 API

# 测试 /v1/auth/login
curl -s -X POST http://target:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# → "404 page not found" ❌ 不是这个前缀
```

### 3.2 完整 API 认证测试

```bash
# 测试所有已发现端点的 GET/POST/无认证状态
BASE="http://target:8080/api"

for endpoint in /auth/login /auth/me /auth/logout \
  /dashboard/summary /dashboard/bandwidth /dashboard/nginx \
  /dashboard/servers /dashboard/regions /dashboard/disk \
  /dashboard/daily /dashboard/history \
  /proxies /proxies/test /keys /whitelist /cleanup/trigger; do
  
  # GET
  code=$(curl -sk --connect-timeout 3 -o /dev/null -w "%{http_code}" "${BASE}${endpoint}" 2>/dev/null)
  echo "GET $endpoint -> $code"
  
  # POST
  code=$(curl -sk --connect-timeout 3 -X POST -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" -d '{}' "${BASE}${endpoint}" 2>/dev/null)
  echo "POST $endpoint -> $code"
done
```

---

## 四、后端类型推断

### 4.1 从错误响应推断

```bash
# 关键特征对比

# JSON 格式错误 (Spring Boot/Express/Django)
# {"timestamp":"...","status":401,"error":"Unauthorized","path":"..."}
# → Java / Node.js

# 纯文本错误 (自定义)
# "invalid credentials" / "unauthorized" / "bad request"
# → Go / 自定义轻量框架

# HTML 格式错误
# <html><body>401 Unauthorized</body></html>
# → nginx 内置认证 / Java 容器

# XML 格式错误
# <error><code>401</code><message>Unauthorized</message></error>
# → 老式 Java / ASP.NET
```

### 4.2 Null 字节注入测试 (Go 后端检测)

Go 的 `net/http` 路由在遇到 URL 路径中的 `\x00` (null 字节) 时会导致 panic，返回 500。

```bash
# 测试方法：在任意 API 路径后加 %00
curl -sk --connect-timeout 3 "http://target:8080/api/auth/me%00"
# → 500 Internal Server Error → 高度疑似 Go 后端

curl -sk --connect-timeout 3 -X POST "http://target:8080/api/auth/login%00" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# → 500 Internal Server Error → 确认 Go 后端

# 如果返回 404 或 400 → 不是 Go，可能是 Java/Node/Python
```

### 4.3 更多后端指纹

```bash
# 检查 Server 头是否隐藏
curl -skI "http://target:8080/" | grep -i server

# 检查 X-Powered-By
curl -skI "http://target:8080/" | grep -i powered

# 检查 401 响应的完整头
curl -skv -X POST "http://target:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{}' 2>&1 | grep -E '< HTTP|< X-|< Set-Cookie|content-type'

# Go 后端典型特征:
# - 纯文本错误响应 ("unauthorized" / "invalid credentials")
# - 无 Server 头或自定义
# - 500 on %00 null byte
# - X-Content-Type-Options: nosniff 头存在
```

---

## 五、Vite 生产构建 CVE 分析

### 重要：Vite CVEs 仅影响开发服务器

| CVE | 影响范围 | 备注 |
|-----|---------|------|
| CVE-2023-34092 | Dev server only | `server.open` 参数注入 |
| CVE-2024-23331 | Dev server only | `fs.deny` 绕过 |
| CVE-2025-30205 | Dev server only | `allowedList` 路径穿越 |
| CVE-2025-31125 | Dev server only | `__internal__` 绕过 |

**所有已知 Vite CVE 只影响 `vite dev` 开发服务器**。生产构建产物 (nginx 托管的静态文件) 不受影响。

```bash
# 验证是否为生产构建（检查是否有 /@vite/ 路径）
curl -sk --connect-timeout 3 "http://target:8080/@vite/client"
# → 404 → 生产构建，Vite 漏洞不可用

# 检查是否有 __open-in-editor
curl -sk --connect-timeout 3 "http://target:8080/__open-in-editor"
# → 404 → 生产构建

# 检查 /@fs/ 路径遍历
curl -sk --connect-timeout 3 "http://target:8080/@fs/etc/passwd"
# → 404 → 生产构建
```

---

## 六、完整文件/路径探测清单

发现 Vue SPA 后，按以下清单系统化探测：

```bash
for path in \
  # Vite 开发服务器
  /@vite/client /@vite/env /@fs/ /__open-in-editor /__vite_ping \
  # 环境文件
  /.env /.env.local /.env.development /.env.production \
  /.git/config /.git/HEAD \
  # 构建配置
  /vite.config.js /vite.config.ts /package.json \
  # Source Map
  /assets/index-*.js.map /assets/*.css.map \
  # 敏感路径
  /api/actuator/health /api/swagger-ui.html /api/v2/api-docs \
  /api/.env /api/config /api/status /api/version /api/health \
  # API 路径遍历
  /api/auth/me%00 /api/auth/login%00 \
  /api/auth/login?debug=1 /api/auth/login?bypass=true \
  # CORS 探测
  # (OPTIONS + Origin: https://evil.com)
; do
  curl -sk -o /dev/null -w "%{http_code}" "http://target:8080${path}"
done
```

---

## 实战案例: 223.109.241.56

### 资产概要

| 端口 | 服务 | 发现方法 |
|------|------|---------|
| 8080 | Vue 3 管理后台 | dddd 全端口扫描 |
| 22022 | SSH (OpenSSH 8.9p1) | dddd 全端口扫描 |
| 7732 | nginx (备用) | dddd 全端口扫描 |
| 7758 | TLS 自定义协议 | dddd 全端口扫描 |

### 系统推测

从 JS 中提取的中文 UI 文本 (`业务密钥`, `节点列表`, `白名单`, `仅白名单内的`, `上行`, `下行`, `今日峰值`) 和设备 API 结构 (`/api/dashboard/servers`, `/api/dashboard/nginx`, `/api/proxies`, `/api/keys`, `/api/whitelist`) 确认这是一个 **代理出口业务管理平台**。

### 关键发现

1. **baseURL: "/api"** — Axios 实例配置：`{baseURL:"/api",timeout:10000,withCredentials:true}`
2. **认证机制** — 基于 Session Cookie (withCredentials: true)，非 JWT
3. **401 拦截器** — 响应状态码 401 时自动跳转登录页
4. **轮询间隔** — 30s (主要) + 5s (部分面板)
5. **后端语言** — Go (null byte %00 导致 500, 纯文本错误响应)
6. **Vite CVE** — 全部不可用 (生产构建)
7. **CORS** — 未配置 (无 Access-Control-Allow-Origin)
