# JS 登录页 RSA 公钥提取与默认口令测试

当 Web 登录页使用 JSEncrypt（前端 RSA 加密）时，公钥通常硬编码在页面源码中。提取后可用 Python 加密密码并尝试默认口令。

## 识别方法

页面源码中搜索以下特征判断是否使用了 JSEncrypt：

```html
<script src="...jsencrypt.min.js"></script>
```

或搜索 JavaScript 中的 `Utility.encryptedString`、`JSEncrypt`、`setPublicKey` 等关键字。

## 公钥提取

找到 `getRSAKey()` 或类似的函数，公钥以 PEM 格式硬编码：

```javascript
var Utility = {
    getRSAKey: function () {
        var key = '-----BEGIN PUBLIC KEY-----\n' +
            'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkXaJGi49qwU2Xuss6kTmDylwK\n' +
            '...\n' +
            '-----END PUBLIC KEY-----\n'
        return key
    },
    encryptedString: function (strValue) {
        var key = this.getRSAKey()
        var encrypt = new JSEncrypt();
        encrypt.setPublicKey(key);
        return encrypt.encrypt(strValue);
    }
}
```

## 密码加密（Python）

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import base64

pubkey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkXaJGi49qwU2Xuss6kTmDylwK
...
-----END PUBLIC KEY-----"""

key = serialization.load_pem_public_key(pubkey.encode())
encrypted = key.encrypt("admin".encode(), asym_padding.PKCS1v15())
encrypted_b64 = base64.b64encode(encrypted).decode()
```

注意：PKCS1 填充每次加密结果不同，每次 POST 前需重新加密。

## 登录请求发送

```bash
curl -sk "http://target/LoginFromPage" \
  -d "p=<RSA_ENCRYPTED_PWD>&u=admin"
```

## 常见登录 API 端点

| 位置 | 注意 |
|------|------|
| `POST /LoginFromPage` | 表单 action 的值 |
| `../../LoginFromPage` | 相对路径，需解析到完整 URL |

## 验证码行为分析

系统通常通过 Ajax 查询判断是否需要验证码：

```javascript
$.get("../../LoginParam?u=" + username, function (response) {
    if (response.isLoginCaptchaEnabled) {
        // 需要验证码
    }
})
```

- 不同用户名可能返回不同的验证码状态
- `admin` 等常用用户名可能因多次失败触发验证码
- 不存在的用户名通常不需要验证码

## 错误信息解读

| 返回 | 含义 |
|------|------|
| `{"Success": false, "Message": "请输入验证码"}` | 需要验证码，换用户名或破解验证码 |
| `{"Success": false, "Message": "block incorrect"}` | 账号已被锁定 |
| `{"Success": false, "Message": "unauthorized"}` | 密码错误 |
| `response == "unauthorized"` | 密码错误（某些系统用字符串而非 JSON） |
| `302 → /PubPlatform/Login` | 登录失败，重定向回登录页（ASP.NET） |

## 相关 skill

- `info-gathering/references/cas-login-automation.md` — CAS 的 RSA 加密登录（与本节互补）
- `info-gathering/references/spa-vue-auth-flow-analysis.md` — Vue SPA 认证流分析
