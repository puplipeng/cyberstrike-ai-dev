# 匿名漏洞披露事件调查方法论

当某个 GitHub 仓库或匿名漏洞披露因删除/私有化而无法直接访问时，通过多源三角验证重建其内容。

## 调查流程

### 第一步：GitHub API 搜索

```bash
# 搜索用户（可能已删除）
curl -s "https://api.github.com/users/EXPLOIT_USERNAME"

# 搜索仓库
curl -s "https://api.github.com/search/repositories?q=EXPLOIT_KEYWORD&sort=updated"

# 搜索关键词
curl -s "https://api.github.com/search/repositories?q=exploitarium"
```

### 第二步：多源三角验证

同时查询三个互补来源：

| 来源 | 数据 | 获取方式 |
|------|------|---------|
| **结构化漏洞语料库** | 漏洞 ID、CWE、根因、利用原语 | GitHub 搜索 `vuln-corpus`、`exploit-db` 等 |
| **检测规则仓库** | 文件名、检测逻辑、漏洞目标 | GitHub 搜索 `detections`、`rules`、`KQL` 等子仓库 |
| **威胁情报报告** | 综合评估、严重性、技术分析 | detections.ai、systemtwosecurity.com 等平台 |

```bash
# 1. 搜索结构化语料库
# 关键词: vuln-corpus, exploit-dataset, cve-db
curl -s "https://api.github.com/search/repositories?q=vuln-corpus+DESCRIPTION_KEYWORD"

# 2. 搜索检测规则仓库
# 关键词: exploitarium detection rules KQL
curl -s "https://api.github.com/search/repositories?q=EXPLOIT_KEYWORD+detection"

# 3. 搜索情报报告
# detections.ai 格式: https://systemtwosecurity.com/share/inspiration/XXXX
# 直接访问或通过 Wayback Machine
```

### 第三步：信息交叉比对

```bash
# 比对三个来源的共同漏洞列表
# 语料库 → corpus.json 中的 entries
# 检测规则 → 目录名对应漏洞目标
# 情报报告 → 综合严重性评估

# 关注点：
# - 三方都提到的漏洞 → 高置信度
# - 仅有检测规则但无语料库条目 → 未确认或低严重性
# - 仅情报报告有评估 → 社区验证状态
```

### 第四步：CVE 追踪

从三个来源提取所有 CVE 编号，确认哪些已有正式分配：

```bash
curl -s "https://api.github.com/search/repositories?q=CVE-2026+KEYWORD"
```

### 输出格式

按严重性分级（🔴 严重 / 🟡 高 / 🟢 中）列出每个漏洞，包含：

- 漏洞 ID 和 CVE（如有）
- 产品与版本
- 根因（CWE + 简短描述）
- 利用原语
- PoC 可用性
- 实战价值评估
