# CyberStrikeAI Dev（二开版）

基于官方 CyberStrikeAI v1.7.17 的二次开发版本。核心变更：**PostgreSQL 原生化**（移除 SQLite 方言翻译层）、**pgvector 向量检索**、**知识库扩充**（HackTricks 中文版 + H1-PoC 指引）。

> ⚠️ 安全说明：`config.yaml`（含数据库 DSN / AI API Key）已被 `.gitignore` 排除，**不会**随仓库提交。请勿在任何提交中混入密钥、密码、token。

---

## 环境要求

| 组件 | 版本 | 说明 |
|---|---|---|
| Go | 1.25+ | 构建（国内环境建议 `GOPROXY=https://goproxy.cn,direct`） |
| PostgreSQL | 16+ | 主数据库（业务表 + 知识库向量表） |
| pgvector 扩展 | 0.7+ | 向量检索（`CREATE EXTENSION vector`） |
| Ollama | 任意 | 本地向量模型服务（bge-m3 1024 维） |
| poppler-utils | 任意 | PDF 文本提取（pdftotext——官方 eino_fs read_file 依赖） |
| 安全工具 | 可选 | subfinder/nuclei/ffuf 等（tools/ 目录定义，按需安装） |

## 快速开始

### 1. 数据库准备

```bash
# 创建用户和库（以 postgres 超级用户执行）
CREATE USER cyberstrike WITH PASSWORD '<你的密码>';
CREATE DATABASE cyberstrike OWNER cyberstrike;
CREATE EXTENSION IF NOT EXISTS vector;
GRANT ALL ON SCHEMA public TO cyberstrike;
```

### 2. 配置

复制示例配置并填写：

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml：
#   database.dsn     —— PostgreSQL 连接串（密码含 @ 需 URL 编码 %40）
#   knowledge.embedding.base_url —— Ollama 地址（默认 http://127.0.0.1:11434/v1）
#   ai.channels      —— 对话模型通道（OpenAI 兼容）
```

### 3. 构建

```bash
export GOPROXY=https://goproxy.cn,direct
go build -o cyberstrike-ai cmd/server/main.go
```

### 4. 启动

```bash
./cyberstrike-ai
# 默认 https://127.0.0.1:8080/（自签证书）
# 首次启动自动建表 + 知识库索引（knowledge_base/ 目录自动扫描嵌入）
```

### 5. 验证

```bash
# 登录
curl -k -X POST https://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<你的密码>"}'
# 知识库检索
curl -k -X POST https://127.0.0.1:8080/api/knowledge/search \
  -H 'Content-Type: application/json' -H "Authorization: Bearer <token>" \
  -d '{"query":"SQL注入","topK":3}'
```

---

## 更改说明

### 1. PostgreSQL 原生化（核心）

- **移除 SQLite 方言翻译层**：删除 pgwrap 方言翻译器，改为原生驱动直通。
- **351 处 SQL 原生转换**：`?` 占位符 → `$N`；动态拼接改为 `fmt.Sprintf("...$%d")` 动态序号。
- **SQLite 专属函数兼容**：
  - `rowid` → `ctid`（23 处排序/查询）
  - `pragma_table_info` / `sqlite_master` → `information_schema.columns`
  - `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`
  - `strftime` → `to_char` / `EXTRACT(EPOCH FROM ...)`
  - `julianday` → `EXTRACT(EPOCH FROM ...)`
  - `MAX(0, x)` 标量 → `GREATEST(0, x)`
  - `sql.NullTime` 编码支持（postgresArgValue 增加 NullTime 分支）
- **建表 DDL 原生化**：`DATETIME` → `TEXT`、`AUTOINCREMENT` → `BIGSERIAL`、FK 顺序修正。
- **参数序号修复**：LIMIT/OFFSET 动态化；ON CONFLICT 歧义表限定（`tool_stats.last_call_time` 等）。

### 2. pgvector 向量检索

- `knowledge_embeddings.embedding` 由 TEXT（JSON 数组）改为原生 `vector(1024)`。
- 相似度计算从 Go 代码余弦改为 **SQL 层**：`ORDER BY embedding <=> $1::vector`。
- 增加 **HNSW 索引**（`idx_knowledge_embeddings_hnsw`）。
- 向量模型：本地 Ollama **bge-m3**（1024 维）——与对话模型（DeepSeek 等）分离配置。
- reranker 未配置时**降级为纯向量检索**（不阻断启动）。

### 3. 知识库扩充

- **HackTricks 中文版**导入：Web 攻击 7 主题（注入/IDOR/SSRF 走私/XSS/JWT/WAF）+ 服务渗透 9 协议（数据库/SMB/云/工控等）。
- **H1-PoC 指引**导入（9 篇：方法论/文件解析 RCE/SSRF 走私/CVE 反查等）。
- 分类动态反映（`list_knowledge_risk_types` 返回全部分类，非硬编码）。

### 4. 安全与工具

- 文件读取使用**官方 eino_fs 工具组**（read_file/glob/grep/write/edit/execute——默认启用，PDF 由 pdftotext 提取）。
- 补充信息收集 skills（recon-combat-methodology / info-gathering）。
- exec 工具保留官方默认（使用需谨慎，平台审计兜底）。

### 5. 项目关联

- 批量任务（batch_task_create）在 `project_id` 为空时**继承当前对话的项目**——项目内触发的自动分析产物留在同一项目。
- 项目关联**尊重用户选择**：不自动分配默认项目（未选即无项目）。

### 6. 前端

- 统一弹窗交互风格。
- 移除仪表盘"最近更新时间"与标题栏版本号徽章。
- 登录框默认显示（访问即校验身份，不再先渲染页面再弹登录框）。

### 7. 运维

- admin 密码重置脚本：`scripts/reset_admin_password.py`（直接 UPDATE PostgreSQL）。
- 更新监控：每日检查官方仓库 Releases/commits（`~/.hermes/scripts/check_csai.py`，零 LLM 消耗）。

---

## 回滚

- 全量替换前备份提交：`6967c24`（可 revert/checkout 回到方言翻译层方案）。

## 目录结构（简）

```
├── cmd/server/          # 主程序
├── internal/
│   ├── database/        # 数据层（原生 PostgreSQL + pgvector）
│   ├── knowledge/       # 知识库（索引/检索/工具）
│   ├── mcp/             # MCP 工具框架
│   ├── multiagent/      # 多代理编排（eino）
│   └── security/        # 工具执行器/RBAC
├── tools/               # 工具 YAML 定义
├── skills/              # 平台 skills（含信息收集）
├── knowledge_base/      # 知识库源文件（按分类目录）
├── web/                 # 前端（传统 JS 单页）
└── scripts/             # 运维脚本
```
