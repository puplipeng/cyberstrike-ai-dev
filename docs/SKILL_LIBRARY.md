# 技能与 PoC 资料库

这个模块使用 PostgreSQL + pgvector 保存文本快照、元数据、关联和向量；原文件仍是内容的权威来源。原来的技能加载及聊天模型配置不变。资料库不执行文件，也不会把语义相似视为漏洞验证成功。

## 本地配置

先安装与 PostgreSQL 主版本一致的 pgvector，在目标数据库执行 `CREATE EXTENSION IF NOT EXISTS vector`。启动独立的本地 Ollama 实例，下载 BGE-M3，确认 `/api/embed` 返回 1024 维向量。配置中的修订值使用 `/api/tags` 返回的模型 digest。

```yaml
skill_library:
  enabled: true
  embedding_url: "http://127.0.0.1:11435"
  model: "bge-m3"
  model_revision: "填写本机已校验模型的实际 digest"
  pocs_dir: "library_pocs"
```

Embedding 地址只接受字面量 loopback IP 的 HTTP origin，不使用代理、聊天 API Key 或外部模型服务，不跟随重定向。生产配置应固定模型 digest；更换模型后更新 digest、重启并重建索引。不要把不同模型的向量混用。

本机部署位于 `D:\Projects\CyberStrikeAI`。模型、数据库、Ollama 配置和临时目录均位于其 `work` 下。使用 `outputs/start-local.ps1` 启动应用、PostgreSQL 和 Embedding 服务；`outputs/stop-local.ps1` 停止三者。新增 PoC 文本源码放入 `work/cyberstrike-ai-dev/library_pocs`，不需要额外的 API Key。

## 使用

刷新页面后进入 **技能 → 技能与 PoC 库**，或打开 `/#skill-library`。

- 搜索：技能与 PoC 分开筛选；支持审核状态、精确 CVE 和产品元数据筛选。空查询按文件分页。非空查询合并最多 60 条关键词候选和 60 条向量候选，展示分页候选数，不冒充全库命中总数。
- 详情：查看原文快照和 SHA-256，维护人工 CVE、产品、适用版本、前置条件、许可证、来源和备注。自动识别的 CVE 单独显示，仍需核验。
- 关联：一个技能可以关联多份资源，同一资源也可以关联多个技能；目录归属自动建立，人工关联必须显式选择并保存。解除关联不会删除文件。
- 索引：启动时和每 5 分钟扫描一次；可以手动增量扫描或全量重建。元数据编辑后需要重算的文件进入队列。原文件变化会重置人工审核状态；来源缺失的快照和关联保留，但不参与检索。
- 审核：`reviewed` 仅表示人工审阅，不表示对任何目标验证成功。被停用的记录默认排除，可用审核筛选单独查看。

`skills/*/SKILL.md` 识别为技能，技能包中的其他文件只作为该技能的附件；新增 `pocs_dir` 文件仍以“待审核”导入。通用方法论、经验手册和索引指南统一放入 `knowledge.base_path`，由知识管理索引，不再通过 `references_dir` 重复进入技能审核队列。旧的 `references_dir` 配置仅为兼容保留，运行时会忽略。

## 一致性与边界

文本按 1600 字符分块，重叠 160 字符，保留整文件快照。向量只用于检索证据，不作为执行输入。关键词使用 PostgreSQL 全文检索和字面匹配，向量使用余弦距离，最后用 RRF 合并排名；精确 CVE 额外提升。向量服务不可用时页面明确提示退回关键词检索。

文件扫描完整成功后才提交来源状态。每份文件的新向量全部生成后在事务中替换旧向量；索引哈希与模型标识检查会排除过时向量。单例 advisory lock 防止多个应用实例同时建库。元数据修改检查修订号和当前原文件哈希，防止旧详情覆盖新内容。

共享目录的读取要求全局 `skills:read`，索引、元数据和关联修改还要求全局 `skills:write`。变更记录写入 `skill_library_audit`。不会导入项目私有漏洞记录。PoC 与文档在前端按纯文本转义展示。

只读取配置的目录中允许扩展名的 UTF-8 文本；每文件最多 1 MiB，总计最多 10000 文件，限制目录深度，跳过软链接、隐藏项、二进制及明显的私钥/API Key 内容。这只是有限的敏感内容检查，不代替人工检查。首次导入失败应查看索引状态和 D 盘日志。

当前实现不包含文件上传、自动抓取 PoC、PoC 自动执行、历史版本回放，也没有自动把检索结果注入 Agent 执行链。

## 验证和维护

新增测试覆盖目录边界、分块、Embedding 协议和模型修订、真实 pgvector 存取、增量索引、故障恢复、权限与乐观并发、关联审计及前端文本转义。数据库测试使用独立临时数据库，不对生产资料执行 PoC。

重要表为 `skill_library_documents`、`skill_library_chunks`、`skill_library_text_chunks`、`skill_library_document_cves`、`skill_library_schema`、`skill_library_links`、`skill_library_job` 和 `skill_library_audit`。备份 PostgreSQL 时一起保留，并单独备份原始目录。禁用 `skill_library.enabled` 可停用模块，不删除源文件或已建库的数据。

### 检索与重试修复（2026-08-28）

关键词全文索引独立于向量，按 1600 字符、重叠 160 字符建立分块 GIN 索引，避免合法大文件触发 PostgreSQL 单个 tsvector 的大小上限。全文查询在片段内匹配，字面子串查询仍检查完整原文；向量失败不影响关键词检索。

正文中的所有唯一 CVE 和人工 CVE 都保存到完整关系表，精确筛选不再受 50 个限制。详情仅展示前 50 个自动识别项，并显示识别总数；自动识别不代表适用性已确认。

文件级失败不会中断后续健康文件。失败记录按 1、5、15、60 分钟退避，到期后在下一次扫描重试；未尝试文件优先。连续三次服务不可用才提前停止本轮。手动增量扫描可立即重试，源文件修改或模型更换也会解除旧退避。

启动时在事务中迁移旧库，补建关键词分块和完整 CVE 关系，删除原整文件全文索引。迁移不修改原文件、人工标注、审核状态、关联或已有向量，不需要全量重算。重复启动不会重复补建索引。

实现依据：[pgvector](https://github.com/pgvector/pgvector)、[BGE-M3 模型说明](https://huggingface.co/BAAI/bge-m3)、[Ollama Windows 文档](https://docs.ollama.com/windows)。
