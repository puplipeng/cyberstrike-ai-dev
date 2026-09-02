# 明信集团（cdmxjt.com）多阶段信息收集案例

## 目标

明信集团（cdmxjt.com），成都本地房企，1000+员工。从公开信息出发，逐步发现 ERP、数据中心、OA 等系统。

## 执行流程

### 阶段一：基础 DNS + WHOIS

```
dig cdmxjt.com A → 211.149.236.225
dig cdmxjt.com MX → 阿里云企业邮
dig cdmxjt.com NS → 西部数码
whois → 成都明信房地产集团有限公司，2019年注册，2029年到期
cdmxjt.com → gotoip1.com → 211.149.236.225（虚拟主机）
```

### 阶段二：子域名发现

```
www.cdmxjt.com → cdmxjt.gotoip1.com → 211.149.236.225
oa.cdmxjt.com → 61.139.68.43（独立 IP）
erp.cdmxjt.com → 139.159.162.154（华为云）
mail.cdmxjt.com → 阿里云企业邮
```

### 阶段三：SSL 证书组织确认

SSL 证书 Subject 解密后显示"成都明信房地产集团有限公司"，确认目标归属。

### 阶段四：端口与服务探测

**华为云主机 139.159.162.154：**
- 443 → HTTPS 明源 ERP（PubPlatform）
- 9060 → HTTP 明源 ERP
- 50780 → 数据中心（MDC/Login）
- 9000/9010/9070/9090 → 无 HTTP 响应
- 19051 → 健康检查 "Healthy"

**OA 主机 61.139.68.43：**
- 9090 → OA 系统
- 22 → SSH

**主站 211.149.236.225：**
- 80/443 → 官网 ASP.NET 2.0
- 21 → FTP

### 阶段五：ERP 登录页面 JS 分析

数据中心端口 50780 的登录页面中，发现：
- 用户名默认预填 `admin`（value="admin"）
- 密码通过 JSEncrypt（RSA）加密后提交
- RSA 公钥硬编码在页面 JS 中
- 登录 API：POST /LoginFromPage，参数 {p: RSA加密密码, u: 用户名}
- 验证码动态判断：`GET /LoginParam?u=admin` 返回是否开启

获取到的 RSA 公钥：
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkXaJGi49qwU2Xuss6kTmDylwK
...
-----END PUBLIC KEY-----
```

### 阶段六：弱口令测试

RSA 加密 `admin` 密码后发送，结果：
- admin/admin → 需验证码（isLoginCaptchaEnabled=true，账号被风控）
- test/admin → "block incorrect"（账号被锁定）

## 资产拓扑

```
cdmxjt.com（明信房地产集团）
├── 官网 → gotoip1 → 211.149.236.225（ASP.NET 2.0 + FTP 21）
├── OA → 61.139.68.43:9090（+ SSH 22）
├── ERP（明源）→ 139.159.162.154（华为云）
│   ├── 443 HTTPS → PubPlatform
│   ├── 9060 HTTP → PubPlatform
│   ├── 50780 → 数据中心（RSA加密登录，admin默认账号）
│   └── 19051 → 健康检查
├── 邮件 → 阿里云企业邮
└── DNS → 西部数码
```

## 关键技巧

- 首页 HTML 中直接暴露了 OA 链接 `<a href="http://oa.cdmxjt.com:9090">OA</a>`
- 子域名枚举发现 erp.cdmxjt.com 指向华为云独立主机
- SSL 证书 Subject 确认了公司全称
- Quake 扫描 139.159.162.154 发现 33 条服务记录
- 数据中心登录页面 JS 暴露了 RSA 公钥和默认 admin 账号
