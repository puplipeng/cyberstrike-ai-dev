# CAS 登录自动化流程

CAS (Central Authentication Service) 统一认证系统的登录自动化方法，以西安文理学院（xawl.edu.cn）为例。

## 识别 CAS 系统

```bash
# 特征 URL
curl -sk -o /dev/null -w "%{http_code}" "https://cas.xawl.edu.cn/cas/login"
# 典型的 302 或 200

# 检测表单字段
curl -sk "https://cas.xawl.edu.cn/cas/login?service=https://example.com" | \
  grep -oP 'name="([^"]*)"'
# 典型字段: username, password, lt, _eventId, rememberMe, imageCodeName, errors
```

## 先决条件：确认密码加密方式

**⚠️ 不要假设密码是明文传输！** 很多 CAS 系统在前端用 JSEncrypt (RSA) 或 SM2 对密码加密。

在编写自动化脚本前，先查看登录页的 JS 确认加密方式：

```bash
# 从登录页 HTML 中提取 RSA 相关代码
curl -sk "https://cas.target.edu.cn/cas/login?service=https://someone" | \
  grep -oP '(RSAKey|setPublic|rsa\.encrypt|JSEncrypt|pkcs1pad2|publicKey|encodePassword)'

# 找到 RSA 公钥（n 和 e）
curl -sk "..." | grep -oP 'var n = "\K[^"]+'
curl -sk "..." | grep -oP 'var e = "\K[^"]+'

# 找到 RSA JS 库
curl -sk "..." | grep -oP 'src="[^"]*rsa[^"]*"' | sort -u
```

### 密码加密方式特征

| 特征 | 加密方式 | 输出格式 |
|------|---------|---------|
| `JSEncrypt` | RSA + PKCS#1 v1.5 | **hex**（256 字符）⚠️ |
| `RSAKey` / `jsbn.js` | RSA + PKCS#1 v1.5 | **hex**（256 字符）⚠️ |
| `sm-crypto` / `sm2` | SM2 国密 | hex |
| `encrypt(password.value)` | 自定义算法 | 不定 |

**🚨 JSEncrypt 常见陷阱：** `rsa.encrypt()` 返回 **hex 字符串**（256 字符），不是 base64！很多自动化脚本默认输出 base64 导致登录失败。

## 完整登录流程

### 阶段一：提取 RSA 公钥

从登录页 HTML 中提取 RSA 密钥参数 `n`（模数）和 `e`（指数）：

```bash
# n = 256 位 hex（1024-bit RSA 模数）
# e = "10001"（固定公钥指数 65537）

# 验证公钥是否静态（跨 session 不变）
n1=$(curl -sk "https://cas.xawl.edu.cn/cas/login?service=..." | grep -oP 'var n = "\K[^"]+')
n2=$(curl -sk "https://cas.xawl.edu.cn/cas/login?service=..." | grep -oP 'var n = "\K[^"]+')
[ "$n1" = "$n2" ] && echo "✓ RSA n is static" || echo "✗ RSA n is per-session"
# 大多数部署是静态的，少数会按 session 动态生成
```

### 阶段二：获取登录页 + Session（含 LT）

```python
import urllib.request, re, http.cookiejar

SERVICE = "https://i.xawl.edu.cn/biz-api/j_spring_cas_security_check"
LOGIN_URL = f"https://cas.xawl.edu.cn/cas/login?service={urllib.parse.quote(SERVICE)}"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 获取登录页，自动保存 cookies (JSESSIONID + sessoinMapKey)
req = urllib.request.Request(LOGIN_URL)
resp = opener.open(req)
html = resp.read().decode()

# 提取 lt (Login Ticket) - 每次不同，绑定当前 JSESSIONID
lt = re.search(r'name="lt"\s+value="([^"]*)"', html).group(1)
```

### 阶段三：判断验证码状态

CAS 验证码可能默认隐藏（`display:none`），登录失败后才出现：

```html
<!-- 初始状态：隐藏 -->
<tr id="imageCode" style="display:none;">

<!-- 验证码图片 URL -->
<img src="/cas/codeimage" />

<!-- 错误计数器，初始 0 -->
<input id="errors" name="errors" type="hidden" value="0" />
```

**检测方法：**
```python
# 检查验证码是否显示
# 方法1：检查 errors 字段
errors = re.search(r'name="errors".*?value="(\d+)"', html)
if errors and int(errors.group(1)) >= 1:
    print("⚠️ 需要验证码")
    # 需要手动获取验证码图片 /cas/codeimage 并输入

# 方法2：检查 imageCode 的显示状态
if 'display:none' in html and 'imageCode' not in html.split('display:none')[0]:
    print("✅ 验证码隐藏，可无验证码登录")
```

### 阶段四：RSA 加密密码（关键步骤！）

使用 Python 实现 JSEncrypt 的 RSA PKCS#1 v1.5 加密：

```python
import base64, os

def rsa_encrypt_jsencrypt(password: str, n_hex: str, e_hex: str) -> str:
    """
    模拟 JSEncrypt 的 RSAEncrypt 加密（PKCS#1 v1.5 type 2）
    返回 hex 字符串，与 JSEncrypt 输出完全一致

    参数：
        password: 明文密码字符串
        n_hex: RSA 模数 N（十六进制）
        e_hex: RSA 公钥指数 E（十六进制，通常 "10001"）
    """
    e = int(e_hex, 16)
    n = int(n_hex, 16)
    k = (n.bit_length() + 7) // 8  # 密钥字节长度（1024-bit = 128）

    pw_bytes = password.encode('utf-8')
    pw_len = len(pw_bytes)

    # PKCS#1 v1.5 type 2 padding
    # EM = 0x00 || 0x02 || PS (random non-zero) || 0x00 || M
    ps_len = k - pw_len - 3
    ps = os.urandom(ps_len)
    # 确保 PS 中没有 0x00 字节
    while True:
        zi = ps.find(b'\x00')
        if zi == -1:
            break
        ps = ps[:zi] + os.urandom(1) + ps[zi+1:]

    em = b'\x00\x02' + ps + b'\x00' + pw_bytes
    m = int.from_bytes(em, 'big')
    c = pow(m, e, n)
    hx = hex(c)[2:]
    # JSEncrypt 要求偶数长度 hex
    return '0' + hx if len(hx) & 1 else hx

# 使用示例
n_hex = "5598e3b75d21a2989274e222fa59ab07d829faa29b544e3a920c4dd287aed9302a657280c23220a35ae985ba157400e0502ce8e44570a1513bf7146f372e9c842115fb1b86def80e2ecf9f8e7a586656d12b27529f487e55052e5c31d0836b2e8c01c011bca911d983b1541f20b7466c325b4e30b4a79652470e88135113c9d9"
e_hex = "10001"
encrypted = rsa_encrypt_jsencrypt("0824202X", n_hex, e_hex)
print(f"Encrypted password (hex): {encrypted}")
print(f"Length: {len(encrypted)}")  # 应为 256
```

### 阶段五：提交登录

```python
# ⚠️ 密码必须用 RSA 加密后的 hex 值！
encrypted_pw = rsa_encrypt_jsencrypt("0824202X", n_hex, e_hex)

login_data = {
    "username": "2905220233",
    "password": encrypted_pw,       # RSA 加密后的 hex！
    "lt": lt,                       # 从页面提取
    "_eventId": "submit",           # 固定值
    "rememberMe": "true",
    "_rememberMe": "on",
    "imageCodeName": "",            # 无验证码时留空
    "errors": "0"
}
data = urllib.parse.urlencode(login_data).encode()
req2 = urllib.request.Request(LOGIN_URL, data=data)
resp2 = opener.open(req2)  # 使用同一个 opener（带 cookies）
```

### 阶段四：验证结果

```python
final_url = resp2.geturl()
body = resp2.read().decode()

# 成功：URL 中包含 ticket=ST-xxx
if "ticket=ST-" in final_url:
    ticket = re.search(r'ticket=(ST-[^&\s]+)', final_url).group(1)
    print(f"✅ 登录成功! Ticket: {ticket}")

# 失败：返回登录页（检查错误信息）
elif "login" in final_url:
    # 检查错误信息
    err = re.search(r'<span[^>]*class="error"[^>]*>([^<]+)', body)
    # 检查是否触发验证码
    if "验证码" in body:
        print("⚠️ 需要验证码")
    # 检查账号锁定
    if "锁定" in body:
        print("🔒 账号被锁定")
```

### 阶段五：验证 Ticket

```python
# ticket 需要向 service URL 验证
validate_url = f"{SERVICE}?ticket={ticket}"
resp3 = opener.open(urllib.request.Request(validate_url))
result = resp3.read().decode()
```

## CAS 常见端点

| 端点 | 用途 |
|------|------|
| `/cas/login` | 登录页面 + POST 登录 |
| `/cas/logout` | 登出 |
| `/cas/serviceValidate` | 验证 service ticket (XML) |
| `/cas/validate` | 旧版 ticket 验证 |
| `/cas/codeimage` | 验证码图片 |

## 表单字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `username` | text | 账号（学号/工号） |
| `password` | password | 密码 |
| `lt` | hidden | Login Ticket，每次从页面提取 |
| `_eventId` | hidden | 固定 `submit` |
| `rememberMe` | hidden/checkbox | 记住登录 |
| `imageCodeName` | text | 验证码（初始隐藏） |
| `errors` | hidden | 错误计数器 |

## Service URL 模式差异

不同后端系统使用不同的 CAS 回调路径。实际遇到的两种模式：

| 模式 | 回调路径 | 示例 | 后端类型 |
|------|---------|------|---------|
| Spring Security CAS | `j_spring_cas_security_check` | `biz-api/j_spring_cas_security_check` | Spring Boot + Spring Security CAS |
| 自定义 CAS Filter | `/cas/login` | `fresh.xawl.edu.cn/cas/login` | 自定义 CAS 客户端 |

**发现方法：**

```bash
# 寻找系统的 CAS 回调路径
# 方法1：从授权提示中看
curl -sk "https://cas.xawl.edu.cn/cas/login?service=https://target.com/"
# 检查错误页面的 service URL

# 方法2：枚举常见路径
for path in "/j_spring_cas_security_check" "/cas/login" "/sso/login" "/auth/cas"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")
  echo "$code | $path"
done
# 200 或 302 → 存在

# 方法3：从 JS/base64 编码中提取
# 有时 service URL 隐藏在钉钉免登代码的 base64 编码中
curl -sk "https://target.com/" | grep -oP 'dingService="[^"]*"' | cut -d'"' -f2
# 解码看内容
```

### 案例：fresh.xawl.edu.cn 的 /cas/login 模式

```bash
# 1. CAS 登录配置 service 为 fresh 的 /cas/login
curl -sk -c cookies.txt "https://cas.xawl.edu.cn/cas/login?service=http://fresh.xawl.edu.cn/cas/login" \
  --data "username=xxx&password=RSA_HEX&lt=lt_value&_eventId=submit"
# → 302 + Set-Cookie: CASTGC=... + Location: http://fresh.xawl.edu.cn/cas/login?ticket=ST-xxx

# 2. CAS 验证 ticket
curl -sk "http://fresh.xawl.edu.cn/cas/login?ticket=ST-xxx"
# 预期：重定向或设置 session
# 实际（本案例）：HTTP 301 → HTTPS → HTTP 203
# {"msg":"会话过期,请重新登录!","success":false}
```

**注意：** 拿到 CAS ticket 并不保证目标系统会建立 session。有些系统（如 `fresh.xawl.edu.cn`）有自己的 session 管理机制，即使 CAS 验证通过也不会自动创建 session（返回 203 "会话过期"）。这表示该系统的身份认证与 CAS 不完全整合，或需要额外的登录步骤。

## 链式认证：CAS → Spring OAuth2 授权码

当 CAS 后端同时运行 Spring OAuth2 时（如 `i.xawl.edu.cn/biz-api/`），成功 CAS 登录后可以链式获取 OAuth 授权码：

```
CAS 登录 → POST 表单 (含 RSA 加密密码)
  → 302 重定向 + Set-Cookie: CASTGC=xxx
  → 重定向到 j_spring_cas_security_check?ticket=ST-xxx
  → Spring Security CAS filter 验证 ticket
  → 创建 JSESSIONID（biz-api session）
  → 302 到 /biz-api/

用 JSESSIONID 访问 /biz-api/oauth/authorize：
  GET /biz-api/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=yyy&state=ttt
  → 由于已有认证 session → 302 到 redirect_uri?code=AUTH_CODE
  → 拿到 OAuth 授权码
```

```bash
# 完整 bash 示例
# 1. CAS 登录获取 JSESSIONID
curl -sk -c cookies.txt -b cookies.txt \
  "https://cas.xawl.edu.cn/cas/login?service=https://i.xawl.edu.cn/biz-api/j_spring_cas_security_check" \
  --data "username=xxx&password=RSA_HEX_PW&lt=lt_value&_eventId=submit"

# 2. 用 JSESSIONID 访问 OAuth authorize 拿授权码
# cookies.txt 现在包含 JSESSIONID (biz-api session)
curl -sk -L -b cookies.txt \
  "https://i.xawl.edu.cn/biz-api/oauth/authorize?client_id=client-api-resource&response_type=code&redirect_uri=http://i.xawl.edu.cn/web/guest/index&state=test" \
  | grep -oP 'code=[^&\s]+'
# → code=g18bdC
```

**注意：** 拿到 OAuth 授权码后，还需要 `client_secret` 才能换 access token。client_secret 不可绕过时，可尝试直接用 JSESSIONID 访问 Web 功能（如 API 测试页面）。

## Pitfalls

- **验证码是累计触发的** — 不是每次都出现。初始 `errors=0` 时验证码隐藏。连续失败几次后才会显示。每次获取新登录页重置错误计数。
- **Cookie 一致性** — `lt` 和 `JSESSIONID` 是一一对应的。必须用同一个 opener/cookie jar 完成整个流程。不能先 curl 拿 lt，再 curl 提交——会拿到不同的 JSESSIONID。
- **`lt` 单次有效** — 每个 `lt` 只能用于一次登录尝试。失败了需要重新获取。
- **Ticket 单次验证** — `ST-xxx` ticket 只能验证一次。
- **Service 编码** — `service` 参数必须 URL 编码。
- **验证码 URL 无 session 绑定** — `/cas/codeimage` 不需要 jsessionid，但需要登录页的 cookie 上下文。
- **密码错误与账号锁定** — 连续失败可能导致账号临时锁定。错误信息通常在 `<span class="error\">` 中。
- **RSA 加密输出是 hex 不是 base64** — `jsbn.js` 的 `RSAEncrypt()` 返回 `c.toString(16)`（hex）。不要误用 base64 输出导致认证失败。JSEncrypt 的 `encrypt()` 在 jsbn 原始实现中是 hex，JSEncrypt 包装器才返回 base64。
- **RSA 公钥可能动态生成** — 虽然大多数部署使用静态 RSA 公钥（n 不变），少数系统会为每个 session 动态生成新密钥对。验证方法：在两次独立请求中对比 n 值。
- **CASTGC 有效期** — CAS Ticket Granting Ticket 默认有效期通常为数小时（可配置）。TGT 到期后需要重新登录。使用前检查是否已通过检查 `/cas/login` 页面确认 session 是否仍有效。
