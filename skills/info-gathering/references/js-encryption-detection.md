# JS 加密方法识别指南

渗透测试中遇到前端加密时，识别其加密方法是逆向的第一步。本文覆盖主流前端加密库的快速识别方法。

## 一、RSA（非对称加密）

### 识别特征

| 库 | 识别关键词 | 存放位置 |
|----|-----------|---------|
| JSEncrypt | `new JSEncrypt()`、`jsencrypt.min.js` | 登录页面直接引用 |
| forge | `forge.min.js`、`forge.pki` | SPA chunk 中 |
| NodeRSA | `NodeRSA` | Node.js 环境 |
| 原生 PEM | `-----BEGIN PUBLIC KEY-----` | 硬编码在 HTML 或 JS 中 |

### 常见使用模式

```javascript
// JSEncrypt 标准用法
var encrypt = new JSEncrypt();
encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----');
var encrypted = encrypt.encrypt(password);
```

### 提取公钥
公钥可能出现在：
- 页面 HTML 中的 `<script>` 标签内
- 独立的 `.js` 文件（如 `rsa.js`, `security.js`）
- Ajax 请求 `/getPublicKey` 返回
- 硬编码在 `window.g` 或 `window._config` 中

## 二、AES（对称加密）

### 识别特征

| 库 | 识别关键词 | 说明 |
|----|-----------|------|
| CryptoJS | `CryptoJS.AES` | 最常用 |
| crypto-js | `crypto-js` | npm 包 |
| WebCrypto | `subtle.encrypt` | 浏览器原生 API |
| aes.js | `aes.js` | 独立实现 |

### 模式识别

| 关键词 | 模式 |
|--------|------|
| `mode: CBC` | AES-CBC（需要 IV） |
| `mode: ECB` | AES-ECB（不需要 IV） |
| `pad: Pkcs7` | PKCS7 填充 |

### 参数提取点
- IV 通常硬编码或从服务端获取
- Key 可能硬编码、从登录接口返回、或由密码派生

## 三、国密 SM 系列

### 识别特征

| 算法 | 库 | 关键词 |
|------|----|--------|
| SM2 | sm-crypto | `sm2` |
| SM3 | sm-crypto | `sm3` |
| SM4 | sm-crypto | `sm4` |
| SM2/3/4 | gm-crypt | `gm-crypt` |

### 常见场景
- 政务系统、银行、央企网站
- 等保三级要求的系统
- 与 RSA 混用（RSA 加密 SM4 密钥）

## 四、MD5 / 哈希

| 库 | 关键词 |
|----|--------|
| md5.js | `md5.js` |
| spark-md5 | `spark-md5` |
| 原生 | `md5(` |

注意：MD5 常用于参数签名而非密码加密。如果只看到 MD5 没有看到解密逻辑，可能是签名而非加密。

## 五、JWT

| 库 | 关键词 |
|----|--------|
| jsonwebtoken | `jsonwebtoken` |
| jwt-decode | `jwt-decode` |
| jwt.io | `jwt.io` |

JWT 的 payload 是 Base64 编码，可直接解码查看。HS256 需要爆破密钥。

## 六、Base64

| 模式 | 特征 |
|------|------|
| `btoa(` | 浏览器原生编码 |
| `atob(` | 浏览器原生解码 |
| `Base64.encode` | js-base64 库 |

Base64 本身不是加密，但常被误用为"加密"手段。看到 Base64 就解码看看。

## 七、XOR 混淆

```
常见模式：
- 循环 ^ 0x 操作
- charCodeAt 逐字节处理
- 自定义混淆函数
```

XOR 混淆常见于：
- 移动端 API 签名
- 自定义协议的数据包加密
- App 反编译后的代码保护

## 八、DES / 3DES

| 库 | 关键词 |
|----|--------|
| CryptoJS.DES | `CryptoJS.DES` |
| CryptoJS.TripleDES | `CryptoJS.TripleDES` |
| des.js | `des.js` |

老旧系统常见，新系统基本用 AES 代替。

## 九、多加密串联

实际系统常使用**多层加密**，常见链：

```
RSA(password)             → 登录密码传输
RSA(AES_KEY) + AES(data)  → 混合加密（最典型）
SM2(SM4_KEY) + SM4(data)  → 国密混合加密
MD5(param1 + param2 + key) → API 请求签名
```

## 测试方法

### 1. 从页面直接检测

```bash
# 从 HTML 中提取所有加密关键词
curl -sk https://target.com | grep -oP 'JSEncrypt|CryptoJS\.AES|sm2|sm4|jsonwebtoken'

# 提取 RSA 公钥
curl -sk https://target.com | grep -oP '-----BEGIN PUBLIC KEY-----[^-]+-----END PUBLIC KEY-----'

# 提取 window.g 配置
curl -sk https://target.com | grep -oP 'window\.g\s*=\s*\{[^}]+\}'

# 提取 __NEXT_DATA__ 运行时配置
curl -sk https://target.com | grep -oP '__NEXT_DATA__[^>]+>\{.*?\}</script>'
```

### 2. 从 JS 文件中检测

```bash
# 从页面引用的所有 JS 中搜索加密库
grep -r "JSEncrypt\|CryptoJS\|sm-crypto\|forge\|jsonwebtoken" /path/to/js/
```

## 实战案例

### 明源云 ERP（明信集团）

登录页使用 JSEncrypt + 硬编码 RSA 公钥：

```
登录页: /PubPlatform/Login/index.aspx
加密: JSEncrypt
公钥: 硬编码在 HTML 中
请求: POST /LoginFromPage { p: RSA(password), u: username }
```

### 明信集团数据中心

```
登录页: /Mdc/Login/Index.html
加密: JSEncrypt
公钥: JavaScript 中 Utility.encryptedString()
请求: POST /LoginFromPage { p: RSA(password), u: username }
account: admin 预填在输入框
```

### 典型案例集

| 系统 | 加密方式 | 特征 |
|------|---------|------|
| 明源ERP | RSA (JSEncrypt) | /PubPlatform/Login |
| 泛微OA | RSA + AES | /weaver/ 路径 |
| 致远OA | RSA | /seeyon/ 路径 |
| 用友NC | 自定义 AES | /yyoa/ 路径 |
| Spring Boot 默认 | BCrypt | /login 接口 |
