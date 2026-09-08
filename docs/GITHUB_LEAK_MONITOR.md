# GitHub 凭据泄露监控

平台通过 GitHub Code Search 按具名 AND 规则发现疑似凭据暴露。例如规则同时配置 `clientid` 与 `vendor.example` 后，实际查询为 `"clientid" AND "vendor.example" in:file`。每条启用规则生成一条独立查询并按配置顺序串行执行。命中只进入待研判列表，系统不会尝试登录、调用或验证发现的凭据。

## 配置

可在“系统设置 → 资产管理 → GitHub 凭据泄露监控”中配置，也可编辑 `config.yaml`：

```yaml
github_leak_monitor:
  enabled: false
  token: ""
  fingerprint_key: "hex:<64个十六进制字符>"
  rules:
    - enabled: true
      name: example-corp-clientid
      keywords: ["vendor.example", "clientid"]
    - enabled: true
      name: example-corp-accesskey
      keywords: ["vendor.example", "ACCESSKEY"]
  lookback_days: 365
  interval_seconds: 7200
  request_timeout_seconds: 45
  per_page: 30
```

旧版 `keywords` 字段仍兼容，并在 `rules` 为空时映射成 `legacy` 规则；只要 `rules` 非空，就以具名规则为准。`enabled` 只控制自动调度，已配置的监控在暂停自动调度时仍可手动运行。

`token` 可改用环境变量 `GITHUB_TOKEN` 注入。建议创建专用、只读且权限最小的 Token。`fingerprint_key` 可改用 `GITHUB_LEAK_FINGERPRINT_KEY` 注入，应使用稳定的独立随机密钥；`hex:<64hex>` 会解码为 32 字节 HMAC key。未配置时仅为兼容旧版才从 Token 派生，轮换 Token 前应迁移到等价的 `hex:` key。管理页面只返回两项密钥是否已配置，不会回显密钥。

所有配置词会被转义并引用为字面量，用户输入不会被当作 `repo:`、`OR` 等 GitHub 查询语法执行。`lookback_days` 控制发现的时间回溯窗口，默认 365 天，允许 1–3650 天。它不会向 GitHub Code Search 查询拼接日期语法：每轮 Code Search 命中且本地 detector 发现疑似凭据后，平台会查询默认分支中该路径最近一次提交的时间；只有该时间不早于本轮开始时间减去 `lookback_days`，且没有异常超前于本机时间的发现才会入库。列表、统计与详情接口也只展示当前回溯窗口内的数据，历史行会留在数据库中供审计，不会被删除。

路径提交时间查询每轮最多 200 次，并在所有启用规则之间预留公平额度；前面规则没有用完的额度会分给后面的规则。某条规则本轮未检查完时会把游标与搜索快照 ETag 一起保存：快照未变时从未覆盖的位置继续，快照变化时从头校验，避免沿用失效的数组位置。文件刚被删除或重命名造成的单项 404、409、422 或空提交记录只跳过该项；鉴权、限流、服务端和网络错误会停止本轮并保留重试状态。

调度周期默认 7200 秒（2 小时）。Code Search 请求按 `interval_seconds` 串行限速，默认相邻请求至少间隔 60 秒；路径提交元数据请求使用独立队列，完成时间之间至少间隔 1 秒。`request_timeout_seconds` 是每个 HTTP 请求的超时，默认 45 秒。Code Search 的可重试响应会遵循 `Retry-After`，只有确认限流时才使用 `X-RateLimit-Reset`；元数据请求不自动重试，错误按上一段规则结束本项或本轮。

## 入库边界

平台仅保存：规则名称及规范查询、仓库、文件路径、blob SHA、凭据类型、可信度、严重度、HMAC 指纹、固定的 `<redacted:类型>` 标记、GitHub 定位链接和发现时间。搜索片段及其上下文不会进入候选对象；数据库、API、日志和页面均不保存或返回完整候选凭据及 GitHub 原始响应。

本地 detector 对明确的赋值语法做字段白名单分类，当前包括：

- `api_key`、`apiKey`、`apikey`、`x-api-key`，以及 OpenAI、Anthropic、DeepSeek、DashScope、ARK、Moonshot、智谱等 LLM API Key 环境变量；
- 云厂商 `access_key_id`、`secret_access_key`、`access_key_secret`，以及千帆 `QIANFAN_AK/SK`；
- OAuth `client_secret`、webhook/signing secret、access/auth/bearer/refresh token 和 `Authorization: Bearer ...`；
- 现有 GitHub Token、AWS Access Key ID、Google API Key、Slack、Stripe、SendGrid、npm、Twilio 与私钥块格式。

赋值值必须满足对应的最小长度、字符类别和熵要求。空值、`example`、`sample`、`dummy`、`changeme`、`your-*`、`API_KEY_HERE`、测试/脱敏占位符、重复字符与典型顺序样例会被排除。环境变量、模板表达式、配置对象、YAML alias、Vault/Secret Manager、容器密钥文件等引用也不会作为明文泄露入库。普通 `password`/`token` 单词不会命中；裸 `token=` 和密码字段使用更严格阈值。OAuth client ID 属于公开标识符，只能作为检索锚点，即使与 client secret 同时出现也只保存 secret finding。

GitHub Code Search 的结果只是候选情报：它只覆盖默认分支，对大文件、历史提交、其他分支、Gist、Issue 和 PR 内容并不完整；`incomplete_results` 会被记录为部分结果，不能据此认定没有泄露。
