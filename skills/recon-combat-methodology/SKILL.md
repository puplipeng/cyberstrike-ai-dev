---
name: recon-combat-methodology
description: "信息收集实战方法论 —— 迭代决策树，非线性4层。每层评估ROI决定下一步，发现主入口即停。覆盖子域/端口/Web深度/专项服务的精确操作与Kill Switch。与 info-gathering skill（详细命令参考）互补使用。"
version: 1.1.0
author: c1ayoo
platforms: [linux, macos, wsl]
metadata:
  hermes:
    tags: [cybersecurity, recon, methodology, decision-tree, kill-switch, pentest]
    category: cybersecurity
---

# 🔥 Saber 信息收集实战方法论

## 核心理念

> **信息收集不是做完所有步骤，而是在最短路径上找到第一个入口。**

不是线性 6 层，是**迭代决策树**。每层做完问自己三个问题：

1. 当前结果有攻击入口吗？→ **有就停，进 vuln phase**
2. 当前结果提示下一步方向吗？→ **回溯到对应层**
3. 当前层没出东西？→ **继续下一层，不恋战**

## 决策树总图

```
                    ┌─────────────┐
                    │ 目标 (域名/IP) │
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │ ① 暴露面 & 子域 (一把梭)  │ ← crt.sh + Quake 同时跑
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │ 有攻击入口？ │────→ 🏁 进 vuln
                    └──────┬──────┘
                           │ 没有
                    ┌──────▼──────┐
                    │ 有新域名/IP？ │──→ 回溯 ①
                    └──────┬──────┘
                           │ 没有新发现
              ┌────────────▼────────────┐
              │ ② 端口扫描 (两阶段)      │ ← top 1000 + 大Web端口 → 必扫
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │ 有入口/新资产？ │──→ 🏁 或回溯
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │ ③ Web 深度发现          │ ← 目录/JS提取/端点/多端口
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │ 拿到入口？    │──→ 🏁
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │ ④ 专项服务枚举          │ ← SMB/SNMP/FRP/云/phpMyAdmin
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │ 都没有？     │──→ 🔚 收手，汇报无攻击面
                    └─────────────┘
```

## 四层详细操作

### ① 暴露面 & 子域（合二为一）

**目标：** 最快的速度拿到目标的全部公开资产列表。

**并行执行：**
```bash
# crt.sh（被动，免费，3秒出结果）
curl -s "https://crt.sh/?q=%25.target.com&output=json" | python3 -c "
import sys,json; d=json.load(sys.stdin)
for n in sorted({e for i in d for e in i['name_value'].split('\\n') if '*' not in e and e.strip()}):
    print(n)
"

# Quake 多层查询（全面，含指纹和端口信息）
# 第1层：域名查
quake_query__search(query='domain: target.com', size=200)
sleep 3

# 第2层：SSL证书查（发现同证书的其他域名）
quake_query__search(query='cert:"Target" OR cert:"target"', size=200)
sleep 3

# 第3层：标题查
quake_query__search(query='title:"Target" OR title:"target"', size=200)
sleep 3

# 第4层：body查（发现供应商/第三方系统）
quake_query__search(query='body:"Target" AND NOT domain:target.com', size=200)
sleep 3

# 第5层：已知IP关联
quake_query__search(query='ip:"1.2.3.4" OR ip:"5.6.7.8"', size=200)
```

**🪦 Kill Switch：**
- crt.sh 出 0 个域名 + Quake 出 0 条记录 → 只有裸 IP，直接跳 **② 端口扫描**
- 发现任何高价值入口（phpMyAdmin/Druid/actuator）→ **🏁 进 vuln**

**📋 资产分类（Quake 结果归集）：**
- **自有域名资产** — 主域名及子域，正常管理的系统
- **独立域名资产** — 企业注册的其他域名，可能被遗忘
- **供应商系统** — 第三方域名但 body/title 含企业名 → **高危，重点标记**
- **影子资产** — 未出现在任何已知域名下的系统

**↩️ 回溯条件：** 后续层发现新域名/IP（特别是供应商域名）→ 回到 ① 用新发现的域名再扫一轮

---

### ② 端口扫描（两阶段）

### ② 端口扫描（两阶段）

**目标：** 以最小成本发现所有有价值的开放端口。

**⚠️ 非 root 用户限制：** `nmap -sS` 需要 root 权限。用 `nmap -sT -T4 -Pn` 替代。必须加 `-Pn`（跳过主机发现），否则防火墙过滤 ICMP 会导致 nmap 误判主机下线。

**不是扫全端口，是扫最有价值的端口。**

```
第一阶段（必扫，3-5秒）：
  nmap -sT -T4 -Pn --top-ports 100 target  → 快速摸底
  + Quake/Shodan 历史数据              → 交叉验证
  
第二阶段（条件触发）：
  第一阶段出 < 3 个开放端口 → 不扫全端口，直接跳 ③
  第一阶段出 ≥ 3 个开放端口 → 判断价值
    全是 HTTP/HTTPS → 不扫全端口，跳 ③
    有 SMB/MSSQL/Redis/MySQL → 再扫全端口：nmap -sT -T4 -Pn -p- --min-rate=3000
```

**dddd-mod 扫描模式（c1ayoo 二改）：** 本机 dddd-mod（`~/dddd-mod/`）新增三级扫描模式，按需选择避免触发 WAF：
- `--mode light`（默认）：端口+指纹+探活，关 JS 逆向，可无封禁风险摸底
- `--mode normal`：light + 目录爆破 + JS 逆向
- `--mode full`：normal + nuclei PoC + GoPoC 弱口令爆破
- `--dry-run --explain`：只打印执行计划，每步输出原因，不实际扫描

**dddd 全端口陷阱：** `dddd -p 1-65535` 极慢（TCP connect 逐个握手），300s+ 无输出。不用于全端口扫描，仅用于 top 端口 + 指纹识别。

**端口价值分级：**

| 优先级 | 端口 | 价值 |
|--------|------|------|
| ⭐⭐⭐ | 80/443/8080/8443 | Web 入口 |
| ⭐⭐⭐ | 3306/6379/27017 | 数据库弱口令 → 写 shell |
| ⭐⭐ | 445/1433/3389 | 横向移动入口 |
| ⭐⭐ | 9090/3000/5000/9520 | 非标 Web 服务 |
| ⭐ | 7758 | FRP 流量端口标记 |
| 低 | 21/25/53/161 | 专项枚举时才看 |

```bash
# 第一阶段：top 100 快速摸底（非 root 用户）
nmap -sT -T4 -Pn --top-ports 100 target.com

# 额外大Web端口探测
for p in 8080 8443 9090 3000 5000 8000 8888 9000 9520 7758; do
  timeout 3 bash -c "echo > /dev/tcp/target.com/$p" 2>/dev/null && echo "$p OPEN"
done
```

**🪦 Kill Switch：** 80/443/8080/8443 全关 → 不考虑 Web，直接跳 **④ 专项服务**

---

### ③ Web 深度发现

**目标：** 这是最可能出入口的一层。每个开放的 Web 端口独立探测。

```
对每个 Web 端口：
  ├─ a) 技术栈识别（Server头/响应体/Cookie/__NEXT_DATA__）
  ├─ b) 敏感路径探测（actuator/druid/swagger/.git/robots）
  ├─ c) JS 端点提取（JS chunk 中的隐藏 API/子域名/凭据）
  ├─ d) config.js 或 runtimeConfig（硬编码 token/API 地址）
  ├─ e) SPA fallback 识别（对比 size 区分真实 404 和前端路由）
  └─ f) 多端口对比（同 IP 不同端口可能是不同系统）
```

**技术栈→直接决定攻击路径：**

| 识别到 | 直接尝试 |
|--------|---------|
| Spring Boot | `/actuator/env`, `/actuator/heapdump`, Spring4Shell |
| ThinkPHP | RCE payload |
| Laravel | `.env`, `/telescope`, Ignition RCE |
| 芋道 Yudao | `/admin-api/system/user/page` 未授权 |
| Druid | `/druid/datasource.json` |
| Swagger | `/v2/api-docs`, `/swagger-ui.html` |
| Next.js | `__NEXT_DATA__` 提取 runtimeConfig |
| phpMyAdmin | 空密码/默认密码/版本漏洞 |
| 通达/泛微/致远OA | 已知 RCE/文件包含 |
| ASP.NET MVC | 500 触发控制器泄露 |
| Vite 构建 SPA | 检查 `/assets/` autoindex |
| Go 后端 | 测 `%00` null 字节 → 500 = Go |
| **Cloudflare / Damddos** | **CDN 绕过 → 找未保护子域名直连源站（dns对比/crt.sh）** |

**CDN 绕过分支（遇到 Cloudflare/Damddos 时立即执行）：**

当 Web 请求返回 Cloudflare Turnstile 验证页面或 Damddos CDN 时，说明源站就在 CDN 后面。

```bash
# 1. DNS 对比法找未保护子域名
for prefix in cook dev test api admin mail static cdn blog www2 m app; do
  ip=$(dig +short "${prefix}.target.com" 2>/dev/null)
  [ -n "$ip" ] && echo "${prefix}.target.com → $ip"
done

# 2. crt.sh 全量子域名取 IP
curl -s "https://crt.sh/?q=%25.target.com&output=json" | python3 -c "
import sys,json;d=json.load(sys.stdin)
for n in sorted({e for i in d for e in i['name_value'].split('\\n') if '*' not in e and e.strip()}):
    print(n)
" | while read sub; do
  ip=$(dig +short "$sub" 2>/dev/null | head -1)
  [ -n "$ip" ] && ! echo "$ip" | grep -qE '^(104\.|172\.67\.)' && echo "→ $sub ($ip) ← 可能裸奔！"
done

# 3. --resolve 验证
curl -sk --resolve www.target.com:443:IP_EXPOSED https://www.target.com/
# 200 + 正常页面 → 源站确认
# 超时/SSL错 → 假的
```

**🪦 Kill Switch：** 绕过 CDN 后直接拿到真实指纹（nginx/PHP/Typecho 版本）→ 直接进 vuln 阶段。

**JS 端点提取（高价值）：**
```bash
curl -sL "https://target.com/js/chunk-vendors.xxx.js" | \
  grep -oP 'https?://[^"'"'"'") ]+' | sort -u
# → 隐藏子域名（不在 crt.sh/Quake 中）
# → 硬编码 API Key、AccessKey
```

**SPA fallback 检测：**
```bash
# 对比响应体大小
curl -s -o /dev/null -w "%{size_download}" https://target.com/
# 如果 /actuator/health 的 size 跟首页一样 → SPA fallback
# 用 Accept: application/json 区分
curl -s -H "Accept: application/json" -o /dev/null -w "%{http_code}|%{content_type}" https://target.com/actuator/health
```

**🪦 Kill Switch：**
- 发现 actuator 暴露 → 直接拿 heapdump，停 Web 探测
- 发现 phpMyAdmin 空密码 → 试图写 shell，停 Web 探测
- 发现 druid 未授权 → 拿了数据源，停 Web 探测
- 所有路径都是 SPA fallback 200 + 无 API 入口 → 跳 **④ 专项服务**

---

### ④ 专项服务枚举

**目标：** 处理非 HTTP 攻击面。不是每个目标都跑，有对应端口才跑。

| 发现端口 | 专项操作 |
|----------|---------|
| 445 | SMB 空会话 / MS17-010 |
| 161 | SNMP 信息泄露 |
| 3306 | MySQL 弱口令 |
| 6379 | Redis 未授权 / SSH key 写 |
| 27017 | MongoDB 未授权 |
| 7758 | FRP 流量端口 → Dashboard 爆破 |
| 3389 | RDP 弱口令 / BlueKeep |
| 22 | SSH 弱口令 / 密钥泄露 |

**🪦 Kill Switch：** 所有专项枚举无结果 → 收手，汇报「当前信息收集未发现可靠攻击面」

---

## C2 / 远控服务器判定（四层决策树）

信息收集遇到可疑 IP 时，按以下顺序判定是否为 C2/钓鱼服务器：

### 第一层：基础画像
1. **IP 归属地** — 荷兰/俄罗斯/瑞士/保加利亚等东欧或抗投诉地区 → ⚠️
2. **ISP** — SWISSNET / AMATEN / QUANTYX / M247 等 bulletproof 厂商 → ⚠️
3. **SSL 证书** — 自签名且 Org=`Internet Widgits Pty Ltd`（OpenSSL 默认值）→ ⚠️ 无真实域名
4. **DNS PTR** — 无反向解析 → ⚠️ 临时服务器特征
5. **crt.sh** — 0 个域名 → ⚠️ 未出现在证书透明度日志中
6. **ip77.net 风险评分** — ≥ 80 → ⚠️

### 第二层：端口与服务
1. **仅 443 开放**（+ SSH 22）→ 非典型 Web 服务器（正常业务会开更多端口）
2. **默认 nginx 欢迎页** → 可能尚未部署/已下线，或伪装成普通服务器
3. **高端口（65533 等）** → 管理隧道入口
4. **`/sh` 等脚本路径存在** → ✅ 确认是恶意服务器

### 第三层：脚本内容分析
- 下载脚本但不执行：`curl -sk https://IP/sh` 查看源码
- 检查特征：`.redtail`、`clean`、架构检测（`uname -mp`）、下载二进制

### 第四层：关联分析
- 同 /24 段是否有类似服务器
- Quake 搜索关联域名
- AbuseIPDB / VirusTotal 历史记录

### IOC 输出格式
```
C2/IP:  IP:PORT
下载路径: /sh /x86_64 /i686 /aarch64 /arm7 /clean
家族:    RedTail 等
ISP:     SWISSNET 等
```

CyberStrikeAI 的完整方法论包含 8 层 + 时序控制 + 退出自检链表（在 2026-06 会话中由用户提供）。与本 skill 的差异：

| 维度 | CyberStrikeAI | Saber 实战版 |
|------|--------------|------------|
| 流程 | 8层深度（外部暴露面→子域→端口→Web→技术栈→专项→暗面→云） | 4层迭代，每层 ROI 决策 |
| 终止条件 | 退出自检清单（无新发现→收手） | 发现主入口就停 |
| 端口扫描 | rustscan 极速全端口 + nmap -sV | 两阶段，top1000+大Web先扫 |
| Web路径 | ffuf + dirsearch 多词库 | 手动 curl + dddd |
| 隐参发现 | arjun + x8 | 无自动化，chunk grep |
| 历史URL | gau + waybackurls(Windows 兼容包装器) + katana | 无 |
| 专项服务 | SMB/SNMP/SMTP/LDAP 完整枚举 | 有基础，但不自动 |
| 多源验证 | subfinder + amass + Quake cert: 三源交叉 | crt.sh + Quake 双源 |
| 时序控制 | T=0 → T=300s 固定执行节奏 | 无固定节奏，按需回溯 |
| JS提取 | 提到但没展开 | ✅ 独立子流程（chunk/__NEXT_DATA__/config） |
| SPA fallback | ❌ 没有 | ✅ 识别和绕过 |
| 多端口探测 | ❌ 没有 | ✅ 同一 IP 不同端口独立评估 |
| **YAKIT被动检测** | ❌ 没有 | ✅ 112条正则规则（导入后） |
| 中国企业指纹 | ❌ 没有 | ✅ Tengine/APISIX/CE_C/tencent-cos |
| ASP.NET MVC | ❌ 没有 | ✅ 500 错误控制器泄露 |

**工具缺口（将来可用时补齐）：**
```
rustscan     → 极速全端口扫描
ffuf         → Web路径/参数模糊测试
arjun / x8   → HTTP 隐参自动发现
katana       → JS 爬取/端点提取
gau/waybackurls(Windows 兼容包装器) → 历史URL自动收集
amass        → 子域主动枚举（暴力模式）
```

**已通过 dddd-mod 填补的部分缺口：**
- ✅ JS 逆向提取（config.js / __NEXT_DATA__ / RSA 公钥）→ `--jsrecon`
- ✅ 22 种国产系统指纹（明源/致远/泛微/用友/金蝶/帆软/Nacos 等）→ `--cnasset`
- ✅ 8 种 WAF 识别 + 绕过建议 → 自动检测（light 模式关 JS 以防触发）
- ✅ Quake 搜索引擎集成（自动 domain: 查询）→ `--quake --qk "KEY"`
- ✅ Dry-run 计划预览（每步输出原因）→ `--dry-run --explain`

**中国企业指纹（dddd-mod 内置 22 种）：** 已内置扫描模式。详见 info-gathering skill 的 dddd-mod 增强命令章节。

## 被动检测（YAKIT 流量嗅探补充）

在 Web 深度发现阶段，对每个 HTTP 请求/响应做被动嗅探，自动标记异常。参考 `info-gathering` skill 的 `references/passive-detection-patterns.md`。

```bash
# 渗透中快速使用的被动检测命令
# 平时测试时把这几条插到流程里，每步多看两眼响应体

# 1. 搜 GitHub Token
grep -oP '(ghp|ghu)_[a-zA-Z0-9]{36}'

# 2. 搜云密钥（Aliyun AKID）
grep -oP '(?i)(AKID[a-zA-Z0-9]{15,40}|LTAI[a-z0-9]{12,20})'

# 3. 搜数据库连接串
grep -oP '(?i)(mongodb(\+srv)?://|postgresql://|redis://)'

# 4. 搜 Webhook
grep -oP '(open\.feishu\.cn|oapi\.dingtalk\.com/robot|qyapi\.weixin\.qq\.com/cgi-bin/webhook)'

# 5. 搜异常栈（Stacktrace）
grep -oP '(Exception|Traceback|Stack trace|at\s+[\w\.]+\([\w\.]+:\d+\))'

# 6. 搜 Fastjson
grep -oP '@type|com\.alibaba\.fastjson'

# 7. 搜 CORS 通配符+凭据（必须在 header 中同时匹配）
curl -skI "https://api.target.com" -H "Origin: https://evil.com" 2>&1 | \
  grep -q 'access-control-allow-origin:\s*\*' && \
  grep -q 'access-control-allow-credentials:\s*true'

# 8. 搜 Swagger/GraphQL
grep -oP '(swagger-ui\.html|/graphql|/graphiql|/api-docs|openapi\.json)'
```

## Pitfalls（被动检测专用）

- **Index 84 (Base64)** — `[A-Za-z0-9+/]{40,}={0,2}` 会大量误报（正常 Base64 传输），只在响应体超过 200KB 时才值得怀疑
- **Index 71 (CORS)** — `Access-Control-Allow-Origin: *` 单独出现不是漏洞，必须和 `Credentials: true` 同时出现才标红

## 📋 信息收集报告大纲（飞书知识库写作模板）

信息收集归档到飞书知识库时，严格按以下大纲撰写。必须包含 JS 分析章节和 Quake API 使用体现。

```
# 🎯 目标域名/IP — 信息收集报告

## 1. 概述
目标、测试时间、方法概要、核心结论。

## 2. 暴露面 & 资产发现（第一层）

### 2.1 多源子域收集（并行）
• crt.sh（被动）— N 个，SSL 证书透明度
• 360 Quake API（含指纹+端口）— N 条服务记录，厂商/组件/版本/开放端口
• JS 文件提取（静态分析）— N 个，隐藏子域、内网域名、API 端点

### 2.2 DNS 解析 & IP 分布
• 去重后 IP 列表
• IP 归属云厂商（阿里云/腾讯云/AWS）

## 3. 真实 IP 绕过（如有 CDN）
> 🔴 CDN 绕过
> cook.target.com → 源站 x.x.x.x（未过 CDN）
> crt.sh 全量子域对比 + Quake 指纹交叉验证

## 4. 端口扫描（第二层）

### 4.1 第一阶段 — Top 1000 + 大Web端口
### 4.2 第二阶段 — 全端口（条件触发）

## 5. Web 深度发现（第三层）

### 5.1 技术栈识别
### 5.2 敏感路径探测
### 5.3 JS 端点提取与分析
### 5.4 多端口对比

## 6. JS 分析过程

### 6.1 目标 JS 文件收集
• 从首页 HTML 提取所有 `<script src="...">` 标签
• 从已知 JS 文件递归提取更多 JS 引用

### 6.2 端点与路径提取
• API 路径（`/api/`、`/v1/`、`/graphql` 等）
• 隐藏子域（`*.target.com`、`*.internal.com`）
• 敏感关键字（`password`、`token`、`secret`、`admin`、`debug`）

### 6.3 结果整理与验证
• 去重后列表
• 对可疑路径做 HTTP 请求验证（状态码、响应内容）
• 标记可访问端点（200/403/401 等）

### 6.4 分析结论
• 发现的敏感信息（API Key、内网域名、未授权接口）
• 后续利用建议

## 7. 攻击面汇总
• 🔴 高风险（可直接利用的入口）
• 🟡 中风险（需进一步验证）
• 🟢 低风险（信息泄露但无直接危害）

## 8. 附件 & 命令速查
• 所有使用命令（完整参数）
• 工具版本说明
• 原始输出文件（可选）
```

### 大纲易读性要求

每个步骤必须写明：**做了什么、用什么工具、发现了什么**。

- ❌ 避免只写"提取了 JS 端点"这种概括性描述
- ✅ 给出具体数量、路径示例、状态码
- ✅ 若发现敏感信息，用引用块或高亮标记

### Quake API 使用体现

- 在 2.1 节中显式列出 Quake 作为并行数据源
- 在 3 节（CDN 绕过）中说明 Quake 指纹如何辅助验证源站
- 在命令速查中附上 Quake API 调用示例（脱敏后的 query 语句）

### 自检清单

- [ ] JS 分析章节是否包含"收集→提取→验证→结论"四个子步骤？
- [ ] 每个步骤是否有工具名、命令示例、结果数量？
- [ ] Quake 是否出现在暴露面发现和 CDN 绕过两个位置？
- [ ] 分析过程是否能让非原作者看懂？


## 与 info-gathering skill 的关系

`info-gathering` skill（已有）是**详细命令参考库**——包含所有工具的精确参数、指纹匹配规则、案例研究。

本 skill 是**决策框架**——告诉你什么时候用什么工具、什么时候停、什么时候回溯。

> **实战流程：** 加载本 skill 确定策略 → 需要具体命令时参考 info-gathering skill 的对应章节。

## 🎯 蜜罐检测（信息收集关键步骤）

信息收集时发现「太好」的目标时，先做蜜罐检测再深入。以下方法论帮你区分真实系统和蜜罐。

### 检测清单（逐项核查）

收到一个返回 200 的开放端口时，不要直接深入，先跑完以下清单：

```
[ ] ES build_date 与真实版本对比
[ ] ES build_hash 是否为占位符（abc123 / deadbeef）
[ ] Favicon 是否真实（file 命令确认类型）
[ ] 端口分布是否合理（CPE 模式 vs 蜜罐模式）
[ ] 多端口响应是否高度统一（相同 403/Retry-After）
[ ] Quake/FOFA 服务指纹与 HTTP 响应是否一致
[ ] JS 包体量与功能是否匹配（太大可能扒的别人前端）
```

### 实锤指标

| 指标 | 特点 | 判定 |
|------|------|------|
| **ES build_date 与版本不匹配** | ES 8.11.0 发布 2023 年，但声称 2026-03-15 | ❌ 伪造 |
| **ES build_hash = abc123** | 真 ES 从不用这种占位符值 | ❌ 伪造 |
| **Favicon 是文本文件** | JPG/PNG 返回 ASCII 文本（如 "404 page not found"） | ❌ 伪造 |
| **多端口返回完全相同的 403 + Retry-After: 120** | 非标准 WAF 行为，统一屏蔽模式 | ⚠️ 可疑 |
| **端口堆叠模式诡异** | 22 + 8080 + 8081/2/3 + 7001 + 9200 — 非典型部署 | ⚠️ 可疑 |
| **1MB+ JS 包 + Vue 组件完整** | 蜜罐很少投入这么大，但可能是扒了真实产品前端 | 反方证据 |

### 典型蜜罐端口模式

| 模式 | 常见端口 | 真实场景 |
|------|---------|---------|
| CPE 路由器 | 22/23/21 + 161/500/1701 + 7547 + 80/8080 | 真实家庭宽带 |
| Hikvision 摄像头 | 8000 + 554 + 80 | 真实 IoT |
| 蜜罐端口沙拉 | 22 + 8080 + 8081/2/3 + 7001 + 9200 | 人工堆叠诱饵 |
| 蜜罐 ES | 9200 + kibana 5601 + 少量 Web | 假日志数据 |

```bash
# ES 蜜罐检测
curl -sk "http://TARGET:9200/" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ver = d.get('version', {})
    build_date = ver.get('build_date', '')
    build_hash = ver.get('build_hash', '')
    cluster = d.get('cluster_name', '')
    print(f'Cluster: {cluster}')
    print(f'Build hash: {build_hash}')
    print(f'Claimed date: {build_date}')
    # 检测占位符
    if build_hash in ('abc123', 'deadbeef', '0000000', 'changeme'):
        print('❌ FAKE: build_hash is placeholder')
    # 检测版本与日期不符（如 ES 8.x was released 2023-2024 but claimed 2026）
    import re
    m = re.match(r'(\d{4})', build_date or '')
    if m and int(m.group(1)) > 2025:
        print(f'❌ FAKE: build_date year {m.group(1)} exceeds product life')
except:
    print('Not ES or not JSON')
"

# Favicon 真实性检测
file /tmp/favicon.jpg
# ASCII text → ❌ 伪造
# JPEG image data → ✅ 真实

# 多端口响应一致性检测
for port in 8081 8082 8083 9200; do
  curl -skI "http://TARGET:$port/" 2>/dev/null | head -5
done
# 全部返回完全相同的 403 + Retry-After → ⚠️ 可疑
```

### 蜜罐 vs 真实系统对照表

| 特征 | 蜜罐 | 真实系统 |
|------|------|---------|
| ES build_hash | `abc123` / `deadbeef` | 真实 git SHA |
| ES build_date | 与版本号不符 | 匹配真实发布日志 |
| Favicon | 文本文件 | 真实图片文件 |
| 端口列取 | CPE 端口 + 敏感服务（ES）+ Web | 与业务匹配的模式 |
| 多端口响应 | 完全相同的 403/限流 | 不同服务各有行为 |
| JS 包体 | 扒来的，大但不匹配服务名 | 与产品功能对应 |
| CSRF Token 规律 | 每次返回相同格式 | 符合框架特征 |

### CPE 路由器识别（反例：不是蜜罐）

中国宽带用户的 CPE 路由器端口模式是**正常的**，不是蜜罐：

| 端口 | 服务 |
|------|------|
| 22/2222 | SSH |
| 23 | Telnet |
| 21 | FTP |
| 161 | SNMP |
| 500 | IPSec/IKE |
| 1701 | L2TP |
| 7547 | **TR-069 ACS** |
| 8000 | Hikvision 摄像头（端口映射） |

**判断原则：** 如果端口分布符合 CPE 路由器模式 + Quake 确认 ISP 是电信/联通/移动 → 大概率真实设备。

### 参考

- `references/honeypot-detection.md` — 实战案例（两个 IP 的对比分析：目标云服务器IP 蜜罐 vs 115.198.202.226 真实 CPE）
- `references/linux-postexploit-find.md` — Linux 后渗透：find 自动寻找可写目录（RedTail 木马实战技巧）

## WAF 感知扫描策略

部分目标（尤其是教育/政府网站）存在 WAF 或速率限制，在多次扫描后触发阻断：

| 现象 | 处理方式 |
|------|---------|
| 首次扫描 80/443 正常开放，后续显示 closed/filtered | 已触发 WAF，切换到被动源（Quake / 历史数据）确认真实端口 |
| 所有子域名返回 502 | 代理线路问题或目标限流，换代理节点或直接访问 |
| DNS 可解析但端口全关 | 可能是 WAF 已封禁来源 IP，换 IP 或等待封禁周期结束 |

**WAF 触发后的替代方案：**
- 停止主动探测，优先使用测绘平台（Quake / Fofa / Hunter）获取资产指纹
- 测绘平台有历史数据缓存，即使 WAF 封禁了主动扫描也有效
- 通过 SSL 证书透明度（crt.sh）获取子域，不产生 HTTP 流量

## .edu.cn 目标特殊处理

中国 .edu.cn 域名由 CERNET 管理，信息收集时需注意：

**DNS 特征：**
- 大量教育单位使用 DNS 泛解析（`*.edu.cn` → 同一 IP）
- DNS 服务器通常位于教育网（CERNET），而非商业机房
- 主站 IP 可能为电信线路，DNS 服务器为教育网线路，形成两线部署
- SPF 记录常见，但 DMARC / DKIM 往往缺失

**ICP 备案限制：**
- `.edu.cn` 由 CERNET 管理，不在公开 ICP 备案 API 范围内
- 无法通过 beianx.cn / ip138 等常规备案渠道查询
- Who is 归属于 CNNIC "Out of this registry" 或 CERNET whois 超时

**三线部署架构（常见模式）：**
```
电信 IP （125.71.233.x） → 主站 + SSLVPN + 应用系统
CERNET IP（202.115.254.x）→ DNS 服务
移动 IP（183.223.221.x）→ 旧域名 / 备份线路
```
- 多线路意味着资产分散在不同 IP 段，需要分别探测
- 旧域名/历史域名（曾用校名）往往仍在运行，存在历史配置漏洞风险
- 移动线路的安全防护通常弱于主站线路

**常见子域名模式（.edu.cn 高校特有）：**
- `jw` / `jwc` — 教务系统
- `lunwen` — 论文/毕业设计平台
- `xg` — 学工系统
- `zs` — 招生系统
- `ehall` — 一站式服务门户
- `radius.auth` — 融合身份认证/SSLVPN

完整实战流程和案例经验参考 `references/edu-cn-recon-workflow.md`。

## 被动收集模式（Passive-Only，用户指定"不能打POC"时使用）

当用户明确要求**不能打POC**（如授权范围受限、仅做资产测绘、客户要求被动）时，走此模式。

### 与正常模式的区别

| 维度 | 正常模式 | 被动模式 |
|------|---------|---------|
| 端口扫描 | dddd/nmap 主动连接 | Quake/Shodan 历史数据 |
| 漏洞验证 | afrog nuclei PoC 验证 | **跳过，不执行任何 exploit** |
| 目录爆破 | feroxbuster/ffuf 路径枚举 | **跳过，避免 WAF 告警** |
| JS 提取 | 下载执行，解析 chunk | **跳过 JS 解析** |
| URL 探活 | curl 直连 HTTP 探活 | dig DNS + 页面标题 curl（仅 GET 首页） |

### 被动模式操作清单

```
Step 1 — crt.sh 子域名收集（纯被动，不触目标）
  curl -s "https://crt.sh/?q=%25.target.com&output=json"

Step 2 — DNS 记录（不触目标）
  dig A/MX/NS/TXT/SOA +short target.com

Step 3 — Quake API 查询（第三方数据，不触目标）
  curl -X POST "https://quake.360.net/api/v3/search/quake_service"

Step 4 — 主站轻触（仅 GET 首页，不做路径探测）
  curl -skI "https://www.target.com/" → Server 头 + 状态码
  curl -skL "https://www.target.com/" → 提取 title + ICP 备案号

Step 5 — 子域名轻触（仅 DNS 解析，不 HTTP 探活）
  dig +short sub.target.com → 看有没有 A 记录即可

Step 6 — 关联资产（纯第三方数据）
  ICP 备案号反查（beian API / Quake icp: 查询）
  证书指纹反查（crt.sh fingerprint= 查询）

Step 7 — 输出十段报告模板
  套用 info-gathering skill 的 references/osint-report-template.md
```

### 被动模式 Kill Switch

• crt.sh 返回 0 条 + DNS 无 A 记录 + Quake 无数据 → 「该域名无公开资产记录，无法开展被动收集」
• 目标使用 CDN（TencentEdgeOne/Cloudflare）且 crt.sh 无数据 → 仅输出"域名受 CDN 保护，需授权后开展主动扫描"
• 主站返回 JS Challenge（501/567 等非标准状态码）→ **立即停止，不做绕过尝试**，报告"目标 CDN 反爬已触发，被动收集到此为止"

### 被动模式报告格式差异

与正常模式共享十段模板，但以下内容标记为 "被动模式，未做主动验证"：
• 端口/服务信息后标注「来源：Quake 历史数据，可能滞后」
• 子域名不标注存活状态（不做 HTTP 探活就不确认存活）
• 风险发现中仅标注"可查证"的条目（不要写"测试环境存在漏洞"这种无主动验证的推测）

## 大规模企业目标策略（100+ 资产）

当目标为企业集团且提供子域名清单（如 50+ 域名）时，不用逐个深挖——**主站轻触，子域重拳**。

### 优先级分层

```
主站 (www)         → 轻触：Server头 + 标题 + ICP备案号。不做JS提取/目录爆破
边缘资产           → 中触：探活 + 指纹
子公司域/非标端口   → 重拳：完整指纹 + 端口扫描 + 敏感路径
```

### 主站轻触原则

**用户明确要求：主站防护严格，不需要深入到 JS 探测。**

主站通常有 WAF/IPS/CDN 多层保护，花费大量时间做敏感路径探测和 JS 提取大概率被阻断（如 `.git/` → `000` 连接重置），性价比极低。主站只取：
- `curl -skI` → Server 头、状态码
- `grep '<title>'` → 页面标题
- `grep '备案号'` → ICP 备案号（用于反查子公司域名）
- `openssl s_client` → SSL 证书 SAN（发现隐藏子域）

### 子域才是薄弱点

招投标平台、招聘系统、邮件系统等子域通常：
- 防护弱于主站（无 WAF 或规则宽松）
- 暴露更多版本信息（如 nginx/1.21.3、eYouMail v8.23.0）
- 对外公开敏感数据（供应商名单、招聘内部系统名称）

### delegate_task 止损规则

大规模目标委托 delegate_task 时注意：
- 单批 ≤ 3 个 agent，每个 ≤ 600s 超时
- 超时中断不重试——已收集的数据通常足够
- 子域名枚举和多端口扫描分两批跑，避免单批超时
- ENScan/ICP 反查作为补充，但不要阻塞主流程

### 输出要求

子域名必须完整 FQDN（如 `zsrm.zjenergy.com.cn`，不能只写 `zsrm`）。用户明确要求「子域名要完整」。

## 常见 Pitfalls

0. **分析结果展示必须完整呈现过程** — 用户明确要求「过程详细点」。每次展示分析结果时，格式为：`命令` → `输出` → `解读` → `决策`。不能直接跳到结论。反例：只写「已确认 981 台 Ollama 外露」；正例：「搜索 port:11434 AND body:model AND body:Ollama → 981 条 → 验证其中 3 台 → 都是阿里云 ECS 模板部署的小模型 → 结论：公网 Ollama 没有可利用的大模型」
1. **SPA fallback 掩盖真实端点** — Vue/React SPA 配置 `try_files $uri /index.html` 时 `/actuator` 返回 200（实际是首页），用 size 对比或 Accept 头区分
2. **子域枚举不要只依赖一种来源** — crt.sh + Quake + JS 提取，三层互补
3. **同一 IP 不同端口可能完全无关** — 安防系统 :9520 和 :9526 可能是不同的应用，各自独立探测
4. **技术栈识别要精确** — Spring Boot 的 404 返回 JSON 格式 error，SPA 返回 HTML；Go 后端用 `%00` 500 判断
5. **不要无脑扫全端口** — 80/443 都没开的目标，全端口大概率也是白费时间，除非有 SMB/数据库端口
6. **Vite CVEs 只影响开发服务器** — 生产构建由 nginx 托管，`/@vite/client` 404 则 Vite CVE 不可用
7. **主站轻触原则** — 当主站有 WAF（.git/.env 等敏感路径返回 000）时，不要深入做 JS 提取和目录爆破，性价比极低。主站只取指纹+ICP，重点放子域和子公司。见「大规模企业目标策略」章节。
