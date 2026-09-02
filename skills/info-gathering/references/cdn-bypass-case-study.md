# CDN Bypass Case Study: www.jadejunius.cn

> **目标**: www.jadejunius.cn | **日期**: 2026-06-22 | **目的**: Saber 安全技能记录

## 目标概况

个人技术博客，Typecho 1.2.0 CMS，使用 spux 主题，服务器位于阿里云杭州。

## CDN 绕过过程

### 初始发现

```
$ dig www.jadejunius.cn
www.jadejunius.cn. 600 IN CNAME www.jadejunius.cn.iname.damddos.com.
www.jadejunius.cn.iname.damddos.com. 600 IN A 219.152.188.43
```

→ Damddos CDN（笨DDoS防护），重庆电信节点。

### 直接访问

触发 **Cloudflare Turnstile** 人机验证（"请稍候，正在验证您是否是真人"）。说明两层 CDN：
- Layer 1: Cloudflare（Turnstile 验证）
- Layer 2: Damddos（DDoS 防护）

### 绕过入口

通过子域名枚举发现 `cook.jadejunius.cn`：

```
$ dig cook.jadejunius.cn
cook.jadejunius.cn. 600 IN A 139.196.18.244
```

**直接解析到源站 IP——绕过了所有 CDN！**

### 验证

```bash
curl -sk --resolve www.jadejunius.cn:443:139.196.18.244 https://www.jadejunius.cn/
# → 200 OK，页面内容一致
curl -sk --resolve cook.jadejunius.cn:443:139.196.18.244 https://cook.jadejunius.cn/
# → 同一站点（SSL 证书共享 CN=jadejunius.cn）
```

## 源站指纹

| 项目 | 值 |
|------|-----|
| **真实源站 IP** | **139.196.18.244** |
| CDN/WAF 1 | Cloudflare（Turnstile 人机验证） |
| CDN/WAF 2 | Damddos（iname.damddos.com） |
| 源站机房 | 阿里云（杭州，中国） |
| Web 服务器 | nginx 1.29.8 |
| 后端语言 | PHP 7.3.29 |
| CMS | Typecho 1.2.0（spux 主题） |
| SSL | TrustAsia DV TLS RSA CA 2025 |
| SSL 到期 | **2026-06-22（今天到期！）** |
| Certificate SAN | jadejunius.cn, www.jadejunius.cn |
| OS | Linux (Ubuntu) via OpenSSH 9.6p1 |
| 开放端口 | 22 (SSH/O), 80 (HTTP→301 HTTPS), 443 (HTTPS) |

## 深度探测发现

### 管理员入口

- `/admin/login.php` → 200 OK（登录页可访问）
- Cookie 前缀: `9428019b59ece9f1256da806a4b13403`
- 登录端点: `POST /index.php/action/login?_=<hash>`
- 无 CSRF token、无登录锁定机制
- 密码错误返回 302 → `/`（无延迟）

### XML-RPC 完全暴露

端点: `/index.php/action/xmlrpc`
共 64 个方法，含：

| 方法 | 风险 |
|------|------|
| `pingback.ping` | SSRF / DDoS 放大 |
| `metaWeblog.newPost` | 内容注入（需凭证） |
| `metaWeblog.newMediaObject` | 文件上传 webshell（需凭证） |
| `wp.uploadFile` | 文件上传 webshell（需凭证） |
| `wp.newComment` | 评论注入 |

### 敏感路径

| 路径 | 状态 | 说明 |
|------|------|------|
| `/admin/login.php` | 200 | 管理员登录页 |
| `/install.php` | 302 | 已安装，不可重装 |
| `/install/` | 403 | 目录保护 |
| `/config.inc.php` | 200 (0B) | 正常，PHP 执行无输出 |
| `/LICENSE.txt` | 200 (15KB) | GPL v2，版本信息泄露 |
| `/robots.txt` | 404 | 未配置 |
| `/.git/HEAD` | 404 | 无 Git 泄露 |
| `/.env` | 404 | 无环境变量泄露 |
| `/usr/uploads/` | 403 | 上传目录禁止列表 |
| `/usr/plugins/` | 403 | 插件目录禁止列表 |
| `/var/Typecho/Common.php` | 200 (0B) | 正常 |

### 文章内容

5 篇文章，分类 2 个（网络安全基础、杂谈），首页有翻页（共 2 页）。
文章涉及：Hermes Agent + 飞书集成、Linux 入侵排查、RFC 违规请求等。

### 其他发现

- ICP 备案: 蜀ICP备2026014945号
- 微信公众号二维码（/usr/uploads/）
- TLS 1.2 + 1.3 支持，全部强加密套件（A 级）

## 关键风险评估

### 🔴 高风险

1. **SSL 证书今天到期** — 2026-06-22 23:59:59，明天起浏览器 HTTPS 报错
2. **`cook.jadejunius.cn` 无 CDN 防护** — 直接暴露源站 IP
3. **PHP 7.3.29 EOL** — 2021-12-06 已停止安全支持
4. **Typecho 版本公开** — 已知 CVE（CVE-2022-29321 RCE, CVE-2022-33197 SQLi）

### 🟡 中风险

1. **XML-RPC 完全暴露** — 64 个方法，存在暴力破解面
2. **管理员登录无锁定机制** — 可尝试暴力破解
3. **License 文件泄露** — `/LICENSE.txt` 公开可读

### ✅ 安全实践

- 防火墙策略优秀（仅开 3 端口）
- 目录列表全部禁止（403）
- 安装锁定（install.php 重定向）
- 无 Git/环境变量泄露
- HTTPS 强制跳转
- TLS 加密强（仅 A 级）

## 绕过方法论总结

```
用户请求
    │
    ▼
┌─────────────────────┐
│ Cloudflare Turnstile │  ← 第一步被卡
│ (www.jadejunius.cn)  │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  Damddos CDN         │  ← CNAME 追踪发现
│  219.152.188.43      │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  阿里云源站           │  ← 子域名 cook 绕过
│  139.196.18.244      │
└─────────────────────┘
```

### 使用的技术

1. **DNS 解析** — dig A/CNAME，识别 Damddos CDN
2. **子域名枚举** — 发现 `cook.jadejunius.cn` 直连源站
3. **`--resolve` 验证** — curl 绕过 DNS 确认源站
4. **Host 头绕过** — 通过源站 IP + 正确 Host 访问
5. **全端口扫描** — nmap -p- 确认仅 3 端口
6. **SSL 分析** — openssl s_client 提取证书信息
7. **路径枚举** — 逐一探测 CMS 敏感路径
8. **XML-RPC 调用** — system.listMethods 枚举全部接口
