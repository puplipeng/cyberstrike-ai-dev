# Cold-IP Reconnaissance & Vue SPA API Discovery

## Cold-IP Recon (无空间搜索引擎记录的情况)

当 Quake/Shodan 等空间搜索引擎对目标 IP 无记录时，采用纯主动探测策略：

### 流程

```
1. dddd 全端口扫描 (1-65535) → 发现所有开放端口
2. 按端口分组探测
   ├── HTTP/HTTPS → curl 获取标题/Server头/基础路径
   ├── SSH → ssh-keyscan 获取指纹/版本
   └── TLS非HTTP → openssl s_client 获取证书
3. 对发现的 HTTP 服务做路径枚举
4. 如果发现 Vue/React SPA → 下载 JS 提取 API 端点
5. 确认 API 前缀（通过对比 404 响应区分 SPA fallback vs real API）
```

### 特征判断：SPA Fallback vs 真实 API

```bash
# 方法1: 对比响应体大小
HOME=$(curl -s -o /dev/null -w "%{size_download}" http://target:port/)
FAKE=$(curl -s -o /dev/null -w "%{size_download}" http://target:port/randompath123)
# HOME == FAKE → SPA fallback (所有路径返回首页)
# HOME != FAKE → 真实 404

# 方法2: 用不同 API 前缀探错误消息差异
for prefix in /api /v1 /auth /admin; do
  curl -s -X POST http://target:port${prefix}/auth/login \
    -H "Content-Type: application/json" \
    -d '{"user":"admin","pass":"admin"}'
  # "invalid credentials" → 真实 API
  # "404 page not found" → 这个前缀不是咱的
done
```

## Vue SPA API 发现

从 Vue 3 (Vite) 或 Vue 2 (Webpack) 的 JS 产物中提取 API 端点：

### JS 中提取 API 端点的技巧

```bash
# 1. 下载主 JS chunk
curl -sk http://target:port/assets/index-xxx.js -o bundle.js

# 2. 提取 API 路径（匹配 /xxx/xxx 模式）
grep -oP '/[a-z_]+/[a-z_/0-9.-]+' bundle.js | sort -u | head -30

# 3. 提取硬编码字符串（apiKey, token, baseUrl等）
grep -oP '(apiKey|token|secret|baseUrl|password)[^,;}\"]+' bundle.js

# 4. 提取内网地址
grep -oP '"https?://[^"]+"' bundle.js | sort -u

# 5. 提取 axios/fetch 调用中的路径
grep -oP "(get|post|put|delete)\(['\"][^'\"]+" bundle.js | sort -u
```

### API 前缀发现（关键技巧）

Vue SPA 的前端代码中的路径可能是 `auth/login` 而实际 API 在 `/api/auth/login` 或 `/v1/auth/login`。通过 POST 不同前缀的 /auth/login 并看错误消息来确认：

```bash
# 发送登录请求测试不同前缀
curl -s -X POST http://target:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' 
# 响应 "invalid credentials" = 这个前缀对了
# 响应 "404 page not found" = 前缀不对

curl -s -X POST http://target:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' 
# 响应 "404 page not found" = 这个前缀不对
```

### API 后端类型推测

| 错误消息格式 | 可能的后端 |
|-------------|-----------|
| JSON: `{"error":"...","code":401}` | Spring Boot / Express / Django |
| 纯文本: `"invalid credentials"` | 自定义 Go / Node.js / 轻量框架 |
| XML: `<error>...</error>` | 老式 Java / ASP.NET |
| HTML: `<html>...401...</html>` | nginx 内置认证或 Java 容器 |