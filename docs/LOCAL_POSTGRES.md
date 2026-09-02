# 本地 PostgreSQL 与回归测试

本分支使用 PostgreSQL，不再支持传入 SQLite 文件路径。Go 版本以 `go.mod` 为准。

## 配置

复制 `config.example.yaml` 并设置 `database.dsn`。不需要知识库时设置 `knowledge.enabled: false`；此时普通 PostgreSQL 即可运行。知识库需要另行安装 pgvector，当前向量列为 1024 维。可以通过 `database.knowledge_dsn` 指向独立知识库数据库。

AI 密钥在运行配置的 `ai.channels.<通道ID>.api_key` 中设置，或登录后在「系统设置 → 基本设置 → AI 通道配置」填写服务商、Base URL、API Key、模型并保存。不要将密钥提交到 Git。

`server.trusted_proxies` 默认空，应用忽略外来转发头。反向代理部署仅填写真实代理的 IP/CIDR，并确保代理覆盖客户端传来的转发头；修改该项需要重启。不要填写所有地址范围。

前端依赖已随仓库提供；如需恢复，执行 `python scripts/fetch-vendor.py`。脚本根据 `web/vendor-lock.json` 校验文件，不执行 npm 安装脚本。

## 运行测试

配置 `CYBERSTRIKE_TEST_POSTGRES_DSN`，使用指向测试 PostgreSQL 实例的 `postgres://` URL。测试账号需要 `CREATEDB` 权限。每次 fixture 调用创建随机命名数据库，并在结束时删除该数据库；不对连接串指定库的业务表写入数据。

```powershell
$env:CYBERSTRIKE_TEST_POSTGRES_DSN = 'postgres://test_user:YOUR_TEST_PASSWORD@127.0.0.1:5432/postgres?sslmode=disable'
go test -p 2 -count=1 -timeout 5m ./...
go vet ./...
node --test web/static/js/*.test.cjs
```

不设置变量时，数据库集成测试会明确标记为跳过，不能把这种结果当作完整回归通过。Windows 运行可移植测试；Unix shell/job-control 集成需要 Linux，已加入 GitHub Actions 的 PostgreSQL 测试任务。增加 CI 配置不代表 CI 已运行或通过。
