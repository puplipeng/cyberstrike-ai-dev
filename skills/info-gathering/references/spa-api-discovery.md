# SPA API Discovery & Authentication Analysis

> 从 Vue.js/React SPA 中逆向发现真实 API 端点、认证机制和硬编码凭据的方法论

## 一、SPA Fallback 识别

Vue.js/React SPA 的 nginx 配置通常为 `try_files $uri /index.html`，导致所有未匹配路径的请求返回 SPA 首页（200 OK `text/html`），掩盖了真实端点状态。

### 检测方法

**方法一：响应体大小对比**
```bash
# 获取首页大小（基准）
curl -s -o /dev/null -w "首页: %{size_download} bytes\n" https://target.com/

# 对比可疑路径
for p in /actuator /druid/ /swagger-ui.html /api; do
  size=$(curl -s -k -o /dev/null -w "%{size_download}" --connect-timeout 3 "https://target.com$p")
  echo "$p -> $size bytes"
done
# 与首页一致 = SPA fallback
```

**方法二：Content-Type 区分**
```bash
# SPA fallback 始终返回 text/html
# 真实 REST API 返回 application/json
curl -s -k -o /dev/null -w "%{content_type}\n" https://target.com/actuator
curl -s -k -H "Accept: application/json" -o /dev/null -w "%{content_type}\n" https://target.com/actuator
```

**方法三：静态文件时间戳**
```nginx
# SPA fallback 响应包含 Last-Modified 头（静态文件）
# 真实 API 响应不包含 Last-Modified
Last-Modified: Fri, 29 May 2026 08:21:22 GMT  ← SPA fallback
```

**方法四：Spring Boot 后端识别**
```json
# 真实 Spring Boot 后端返回 JSON 格式的 404：
{"timestamp":"2026-06-11T07:22:34.751+0000","path":"/bio_platform/xxx","status":404,"error":"Not Found"}

# 而 SPA fallback 返回 HTML（含 <!DOCTYPE html>）
```

## 二、API 前缀发现

SPA 通常通过 nginx 将 `/api/` 或类似前缀反代到 Java/Python 后端：

```bash
# 常见 API 前缀爆破
for prefix in /api /v1 /v2 /system /sys /admin /manage /portal \
              /bio_platform /bio /face /auth /user /register /open; do
  code=$(curl -s -k -o /dev/null -w "%{http_code}" --connect-timeout 3 \
    "https://target.com${prefix}/health" 2>/dev/null)
  size=$(curl -s -k -o /dev/null -w "%{size_download}" --connect-timeout 3 \
    "https://target.com${prefix}/health" 2>/dev/null)
  echo "$prefix -> $code ($size bytes)"
done
# 筛选出 size != 首页大小的 → 真实后端
```

## 三、config.js 分析

SPA 项目的 `config.js`（通常在根目录）经常硬编码敏感信息：

```js
// 典型内容
window.g = {
  baseUrl: window.location.origin,
  // dev: "http://192.168.20.12:9277",  ← 内网地址泄露
  token: "a6ab335afb73b3b9bab59e8d5c09d695",  // 硬编码token
  //token: "7af73340c0ad82e25fcfd51a4f9a3feb",  // 其他版本token
  appid: "ww4f2633c7e1ea23bd",    // 企业微信appid
  agentid: "1000213",
}
```

### 发现线索

| 线索类型 | 价值 | 利用方向 |
|---------|------|---------|
| 硬编码 token | 🔴 高 | 直接作为 Authorization 尝试 |
| 内网地址 | 🟠 中 | Quake 搜索对应公网IP，或 SSRF 利用 |
| 企业微信 appid | 🟠 中 | 企业微信 API 调用、OAuth 伪造 |
| 注释掉的其他学校配置 | 🟢 低 | 发现同厂商的其他部署实例 |

## 四、JWT Token 分析

从 API 响应中获得的 JWT Token 需要进行完整分析：

```python
import base64, json, datetime

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    def b64d(s):
        s = s + '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)
    
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    
    return header, payload
```

### 分析要点

| JWT 字段 | 分析方向 |
|---------|---------|
| `iss` (issuer) | 开发商身份，如 rongbang（荣邦科技） |
| `sub` (subject) | 32位 hex → 设备MD5标识；用户ID |
| `iat` / `exp` | 有效期，如 43000s（12h）→ 长期有效 |
| `alg` | HS256 → 可尝试爆破签名密钥；none → 绕过 |

### 认证方式枚举

```python
# 常见 JWT 传输方式
auth_methods = [
    ("Authorization: Bearer ***", lambda t: {"Authorization": f"Bearer {t}"}),
    ("Token: <token>", lambda t: {"Token": t}),
    ("X-Token: <token>", lambda t: {"X-Token": t}),
    ("accessToken: <token>", lambda t: {"accessToken": t}),
]

# 尝试每种认证方式访问受保护端点
for name, make_headers in auth_methods:
    resp = requests.get(f"{base}/api/user/info", headers=make_headers(token))
    if resp.status_code == 200:
        print(f"✅ {name} works!")
        break
```

## 五、CAS 单点登录分析

### CAS 识别特征
- URL 路径含 `/cas/`
- 登录表单使用 Spring Security 默认字段名
- `/cas/serviceValidate` 返回标准 XML

### 表单分析
```bash
curl -s -k https://cas.target.edu.cn/cas/login | \
  grep -oP '(name="[^"]*")'
# 典型输出：
# name="username"
# name="password"
# name="imageCodeName"  ← 验证码字段
# name="lt"             ← Login Ticket（防重放）
# name="_eventId"
# name="rememberMe"
```

### 验证码绕过检测
```html
<!-- 验证码默认隐藏（CSS display:none），登录失败后才显示 -->
<tr id="imageCode" style="display:none;">
    <input id="errors" name="errors" type="hidden" value="0" />
    <input id="imageCodeName" name="imageCodeName" type="text" />
    <img src='/datawarn/codeimage' />
</tr>
```

隐藏验证码意味着前 N 次登录尝试无需验证码，可进行有限次数暴力破解。

### CAS 协议验证接口
```bash
# 标准 CAS serviceValidate
curl -s -k "https://cas.target.edu.cn/cas/serviceValidate?service=<service_url>&ticket=<ticket>"
# 返回 XML：
# <cas:serviceResponse>
#   <cas:authenticationFailure code="INVALID_TICKET">
#     Ticket 'ST-xxx' not recognized
#   </cas:authenticationFailure>
# </cas:serviceResponse>
```

## 六、实战案例：xawl.edu.cn

| 系统 | 端口 | 技术栈 | 认证方式 | 发现 |
|------|------|--------|---------|------|
| 访客预约 | 9520 | Vue.js + Spring Boot | getStaticToken → JWT | apiKey/secret 固定，但仅限系统级 |
| 人像采集 | 9526 | Vue.js + Spring Boot | CAS SSO | config.js 暴露硬编码 token 和企业微信 appid |
| CAS 认证 | 443 | Apereo CAS | username+password+验证码 | 验证码默认隐藏，前N次可绕过 |
| 大数据平台 | 80 | Spring Security | j_spring_security_check | 验证码 CSS display:none 条件绕过 |

## 七、常见 Pitfalls

1. **JWT token 截断问题** — 在 shell 变量中存储 JWT 时，`.` 和特殊字符可能导致截断。使用 Python 脚本处理，避免 shell 变量传递
2. **CAS 锁策略** — CAS 通常在多次失败后锁定账号，需在爆破前了解锁策略
3. **SPA 和 API 同域** — nginx 同域反代时，API 前缀（如 `/api/`）和 SPA 通过同一个 nginx 暴露，区分需通过响应体大小和 Content-Type
4. **双 WAF 部署** — 安全狗 + 铱迅WAF 等组合部署可能存在规则冲突，某些绕过技巧对不同 WAF 效果不同
