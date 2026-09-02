# CyberStrikeAI 二开版 变更记录

> 基于官方 v1.7.17 的二次开发版本。本文件记录全部核心变更，作为持续二开与回滚参考。

## 一、PostgreSQL 原生化（核心架构变更）

### 1.1 移除 SQLite 方言翻译层
- 删除 pgwrap 方言翻译器（dialect.go），改为原生驱动直通。
- 351 处 SQL 完成原生转换：`?` 占位符 → `$N`（每语句独立编号）。
- 动态拼接 SQL 全部改为 `fmt.Sprintf("...$%d", len(args)+N)` 动态序号。

### 1.2 SQLite 专属函数兼容修复
- `rowid` → `ctid`（23 处——消息/过程详情/批量任务排序）。
- `pragma_table_info` / `sqlite_master` → `information_schema.columns`。
- `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`（rbac 种子等 11 处）。
- `strftime` → `to_char` / `EXTRACT(EPOCH FROM ...)`（10 处）。
- `julianday` → `EXTRACT(EPOCH FROM ...)`（3 处）。
- `MAX(0, x)` 标量 → `GREATEST(0, x)`。
- `datetime('now')` → `now()::text`。
- `sql.NullTime` 编码支持（postgresArgValue 增加 NullTime 分支）。
- LIMIT 参数类型强制 `::bigint`（notification 通知加载）。

### 1.3 建表 DDL 原生化
- `DATETIME` → `TEXT`（97 处列定义）。
- `AUTOINCREMENT` → `BIGSERIAL`。
- `model_token_usage` 外键顺序修正（PG 严格 FK）。

### 1.4 参数序号修复
- LIMIT/OFFSET 序号动态化（conversation/batch_task/project/vulnerability 等 10+ 处）。
- `last_call_time` / `total_calls` ON CONFLICT 歧义表限定。

## 二、pgvector 向量检索改造

- knowledge_embeddings.embedding 由 TEXT（JSON 数组）改为原生 `vector(1024)`。
- 相似度计算从 Go 代码余弦改为 SQL 层 `ORDER BY embedding <=> $1::vector`。
- 增加 HNSW 索引（`idx_knowledge_embeddings_hnsw`）。
- 向量模型：本地 Ollama bge-m3（1024 维），与对话模型（deepseek）分离配置。
- reranker 未配置时降级为纯向量检索（不阻断启动）。
- 知识库表随主库初始化（knowledge_dsn 空时复用主库）。

## 三、知识库扩充（24 分类 / 180 项 / 4200+ 向量块）

- HackTricks 中文版导入：Web 攻击 7 主题（注入/IDOR/SSRF/走私/XSS/JWT/WAF）+ 服务渗透 9 协议（数据库/SMB/云/工控等）。
- H1-PoC 指引导入（9 篇：方法论/文件解析 RCE/XSS 越权/SSRF 走私/信息泄露/CVE 反查）。
- 风险类型列表（list_knowledge_risk_types）动态反映全部分类。

## 四、安全与工具

- 移除自定义 read_file 工具（避免与官方 eino_fs 文件工具同名冲突），纯用官方文件工具组。
- 补充信息收集 skills（recon-combat-methodology / info-gathering）至平台 skills 目录。
- exec 工具保持官方默认（enabled，使用需谨慎——安全边界由平台审计兜底）。

## 五、项目关联修复

- 批量任务（batch_task_create）在 project_id 为空时自动继承当前对话的项目——项目对话中触发的自动分析产物留在同一项目。
- 项目关联完全尊重用户选择：不自动分配默认项目（未选即无项目）。

## 六、前端

- 统一弹窗交互风格。
- 移除仪表盘"最近更新时间"显示与标题栏版本号徽章。

## 七、部署与运维

- 本地 PG16（5433）双库：cyberstrike（业务 + 知识库）、postgres 系统库。
- 公网映射：SSH 反向隧道（云服务器 → 本地 8080，autossh 保活——按需配置）。
- 每日 9:00 GitHub 更新监控（check_csai.py——零 LLM 消耗）。
- admin 密码重置脚本：scripts/reset_admin_password.py（直接 UPDATE PG）。

## 回滚

- 全量替换前备份提交：`6967c24`（git revert 或 checkout 可回滚到翻译层方案）。
