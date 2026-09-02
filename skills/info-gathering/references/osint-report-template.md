# OSINT 资产侦察报告模板

信息收集完成后按此模板输出报告。十段结构，覆盖完整打点链路。

## 报告模板

```markdown
# OSINT资产侦察报告: {target}

## 一、域名基础信息
• **域名**: example.com
• **注册商**: GoDaddy
• **注册日期**: 2020-01-01
• **到期日期**: 2025-01-01
• **注册邮箱**: admin@example.com
• **DNS服务器**: ns1.example.com, ns2.example.com
• **备案号**: 京ICP备12345678号-1

## 二、DNS解析记录
• **A记录**: 1.2.3.4 (TTL 300)
• **AAAA记录**: 2001:db8::1 (TTL 300)
• **MX记录**: mail.example.com (TTL 3600)
• **NS记录**: ns1.example.com, ns2.example.com
• **TXT记录**: v=spf1 include:_spf.google.com ~all
• **CNAME**: www → target-cdn.example.net

## 三、子域名资产

| 子域名 | IP | 状态 | 标题/服务 | 技术栈 | 风险标记 |
|--------|-----|------|-----------|--------|----------|
| www.example.com | 1.2.3.4 | 200 | Example Inc | Nginx, React | - |
| api.example.com | 1.2.3.5 | 200 | API Gateway | Nginx, Java | API接口 |
| admin.example.com | 1.2.3.6 | 200 | Admin Panel | Apache, PHP | ⚠️ 管理后台 |
| dev.example.com | 1.2.3.7 | 403 | - | Nginx | ⚠️ 测试环境 |
| mail.example.com | 1.2.3.8 | - | SMTP | Postfix | 邮件服务 |

## 四、SSL/TLS证书
• **签发者**: Let's Encrypt Authority X3
• **有效期**: 2024-01-01 ~ 2024-04-01
• **SAN列表**: example.com, www.example.com, api.example.com
• **SHA1指纹**: 12:34:56:78:90:AB:CD:EF...
• **SHA256指纹**: 8D:62:36:52:AD:5A:53:D1...
• **证书关联域名**: [通过指纹反查发现]

## 五、服务器与网络空间

| IP | 端口 | 服务 | Banner | 来源 |
|-----|------|------|--------|------|
| 1.2.3.4 | 80 | HTTP | nginx/1.18.0 | Shodan |
| 1.2.3.4 | 443 | HTTPS | nginx/1.18.0 | Shodan |
| 1.2.3.4 | 22 | SSH | OpenSSH 8.2 | Shodan |

• **归属**: 中国北京/阿里云/AS45102

## 六、Web指纹
• **CMS**: WordPress 6.4
• **Web框架**: React 18.2
• **Web服务器**: Nginx 1.18.0
• **WAF**: Cloudflare
• **CDN**: Cloudflare
• **操作系统**: Linux (Ubuntu，推断)
• **数据库**: MySQL（推断）

## 七、威胁情报
• **VirusTotal**: 0/90 恶意 → 清洁
• **微步**: 无威胁标签 → 清洁
• **360 TI**: 无历史攻击记录 → 清洁

## 八、关联资产
• **同IP旁站**: [列表]
• **同证书域名**: [列表]
• **同注册邮箱域名**: [列表]
• **同ASN其他资产**: [列表]
• **ICP备案关联域名**: [列表]

## 九、风险发现
🔴 **高风险**:
• admin.example.com 暴露管理后台，未限制IP访问
• dev.example.com 测试环境可直接访问
• 证书有效期仅剩30天

🟡 **中风险**:
• SSH服务暴露于公网 (1.2.3.4:22)
• 发现旧版本组件: OpenSSH 8.2 (存在CVE-2020-15778)

🟢 **低风险**:
• Server 头泄露 nginx 版本号

## 十、数据来源与置信度

| 数据源 | 数据类型 | 置信度 | 说明 |
|--------|----------|--------|------|
| crt.sh | 子域名/证书 | 高 | 实时查询证书透明度日志 |
| Shodan | 端口/服务 | 中 | 数据有滞后，以最新结果为准 |
| WHOIS | 注册信息 | 高 | 实时查询，隐私保护可能隐藏注册人 |
| FOFA | 指纹/资产 | 中 | 免费用户数据有限 |
| Quake | 资产/指纹 | 中 | 需积分，数据时效性取决于扫描间隔 |
```

## 使用说明

1. 每个子域名需完整 FQDN（如 `zsrm.zjenergy.com.cn`，不能只写 `zsrm`）
2. 子域名数量 = 去重后的独立域名数，服务记录数 = 含端口的完整记录
3. 每个子域名的每个端口单独一行，不能合并
4. 探活状态基于实际数据（Quake 记录或直接探测）
5. 风险发现分三级：🔴 高 / 🟡 中 / 🟢 低
6. 置信度标注数据来源的可靠性，避免单一来源依赖
7. 飞书消息中禁止管道符表格，改用子弹列表 `•`
