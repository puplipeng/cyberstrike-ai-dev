# Chinese Persona OSINT — 个人信息公网暴露面搜索

## 适用场景

对特定中国籍/中文姓名个人进行公网暴露面搜索（自查或授权评估）。与 `info-gathering` 主技能的目标型信息收集（IP/域名/服务）不同，本方法聚焦**人**。

## 搜索维度（并行展开）

### 维度 0：会话历史检索（Unique to this agent）

在进行任何外部搜索前，先查历史对话记录。用户过去可能已经在对话中透露过个人信息、个人网站、GitHub 等。

```python
# 使用 session_search 工具
session_search(query="何俊杰 天融信 渗透 个人")
session_search(query="c1ayoo github 简历")
```

### 维度 1：GitHub 账号深度分析

```bash
# 1. 用户资料（检查 name/company/location/email/bio/blog 是否泄露真实身份）
curl -sL "https://api.github.com/users/<username>"

# 2. 仓库列表 — 区分 fork 和 own repo
curl -sL "https://api.github.com/users/<username>/repos?per_page=100&sort=updated"

# 3. Commit 历史 — 检查 author name/email 是否为真名
# 先查 own repos（非 fork）
curl -sL "https://api.github.com/users/<username>/repos?per_page=100&type=owner"
# 对于非 fork 仓库，获取 commits
curl -sL "https://api.github.com/repos/<username>/<repo>/commits?per_page=10"

# 4. 搜索 commits 中的 author/committer 信息
curl -sL -H "Accept: application/vnd.github.cloak-preview+json" \
  "https://api.github.com/search/commits?q=author:<username>&per_page=100"

# 5. Issues / PRs 历史
curl -sL "https://api.github.com/search/issues?q=author:<username>+type:issue&per_page=10"

# 6. Starred repos — 可能关联其他身份
curl -sL "https://api.github.com/users/<username>/starred?per_page=50"
```

**关键判断：**
- 使用 `noreply.github.com` 邮箱 → 有隐私意识
- 37 个仓库全是 fork → 纯工具收集者，零原创内容，OSINT 价值低
- 有 blog/homepage 链接 → 可能关联个人网站
- 创建时间早 + 持续活动 → 更可能泄露信息

### 维度 2：ICP 备案查询（最强关联手段）

中国个人网站必须 ICP 备案，备案信息关联**真实姓名 + 域名**。

```bash
# 方法1：通过已知名词查询ICP
curl -sL "https://icp.chinaz.com/<domain>" \
  -H "User-Agent: Mozilla/5.0"

# 方法2：通过 ICP 备案号反查（从网站首页提取）
curl -skL --connect-timeout 10 "https://<domain>" | grep -iP 'icp|备案|beian'

# 方法3：Quake 搜索关联资产
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: <TOKEN>" \
  -d '{"query": "icp: \"蜀ICP备20XXXXXX\"", "start": 0, "size": 200}'
```

**注意：** ICP 备案全国库是半公开的，任何第三方查询站的 API 都可能返回主办单位名称。这是中文 OSINT 中**最独特的资产**——西方 OSINT 无法直接通过备案关联真实姓名与域名。

### 维度 3：域名 / WHOIS

```bash
# 当前 WHOIS（通常隐私保护，但注册日期/注册商可见）
whois <domain>
dig <domain> ANY +short

# DNS 服务商（DNSPod/阿里云等）
dig <domain> NS +short

# 历史 WHOIS（可能有未保护的历史记录）
# 尝试：whois.domaintools.com, who.is, securitytrails
```

### 维度 4：搜索引擎搜索

需要**使用具体的关键词组合**，避免被通用词典页淹没：

```bash
# Bing（比百度对非中国IP更友好）
# 关键词组合：
#   - "李四" 渗透测试
#   - "李四" 安全
#   - "李四" GitHub
#   - "李四" 公司名（原厂/驻场单位）
#   - "李四" 网名/ID

# DuckDuckGo Lite（无需 JS）
curl -sL "https://lite.duckduckgo.com/lite/?q=%E6%9D%8E%E5%9B%9B+%E5%AE%89%E5%85%A8+%E6%B8%97%E9%80%8F" \
  -H "User-Agent: Mozilla/5.0"
```

**常见问题：** "何" / "张" 等常见姓氏的搜索会被字典/百科页淹没。必须加限定词（渗透、安全、GitHub、公司名职业等）。

### 维度 5：安全社区搜索

```bash
# 使用 site: 限定
site:zhihu.com "李四" 安全
site:xz.aliyun.com "李四"
site:anquanke.com "李四"
site:bbs.kanxue.com "李四"
site:freebuf.com "李四"
site:cnblogs.com "李四"
site:segmentfault.com "李四"
```

**返回值判断：** 如果所有社区返回 0 条 → 该人没有通过此身份发表过公开内容，或使用网名而非真名活动。

### 维度 6：其他代码 / 技术平台

```bash
# GitLab
curl -sL "https://gitlab.com/api/v4/users?username=<id>"

# Gitee（码云）— 通过 web search，无公开 API

# StackOverflow / V2EX / 掘金 / 思否
site:stackoverflow.com <id>
site:v2ex.com <id> / site:v2ex.com <网名>
site:juejin.cn <id>
site:segmentfault.com <id>

# Keybase / 其他身份验证平台
```

### 维度 7：泄露数据 / 暗网查询

```bash
# 有邮箱时的 HIBP
# curl -sL "https://haveibeenpwned.com/api/v3/breachedaccount/<email>"

# DeHashed / IntelX / Snusbase — 通常需要 API key 或付费

# 搜索模式
<id> leaked
<id> breach
<id> exposure
<email> pwned
```

### 维度 8：漏洞赏金平台

```bash
# HackerOne / Bugcrowd / Openbug bounty / 补天 / 漏洞盒子
site:hackerone.com <id>
site:bugcrowd.com <id>
site:openbugbounty.org <id>
<id> hackerone
<id> bug bounty
<id> researcher
```

## 信息汇总表格式

```markdown
| 维度 | 结果 |
|------|------|
| 真实姓名暴露 | ICP备案、个人网站、GitHub profile |
| 工作单位暴露 | 未/已发现 |
| 私人联系方式 | 邮箱/手机 未/已暴露 |
| 安全社区账号 | 未/已发现（知乎/先知/看雪等） |
| 其他平台关联 | GitLab/Gitee/HackerOne 等 |
| 泄露事件 | 未/已发现（含泄露源） |
```

## 实战案例：何俊杰（c1ayooo）

| 搜索项 | 结果 |
|--------|------|
| ICP备案 蜀ICP备2026014945 | ✅ 关联真实姓名 何俊杰 + 域名 jadejunius.cn |
| 域名 jadejunius.cn | ✅ 运行中 Typecho 1.2.0 博客，阿里云杭州 139.196.18.244 |
| GitHub c1ayooo | ✅ 37 个安全工具 fork，零原创 commit，noreply 邮箱 |
| 搜索引擎 "何俊杰 安全/渗透/天融信" | ❌ 无相关结果 |
| 安全社区（知乎/先知/安全客/看雪） | ❌ 未找到同名账号 |
| 其他代码平台（GitLab/Gitee） | ❌ 未找到关联 |
| 漏洞赏金平台 | ❌ 未注册 |
| 泄露数据库 | ❌ 未发现 |

**结论：** 主要暴露面为 ICP备案实名关联域名。隐私保护相对较好（WHOIS隐私、GitHub noreply、无社区发文）。
