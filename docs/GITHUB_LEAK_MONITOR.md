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
  interval_seconds: 7200
  request_timeout_seconds: 45
  per_page: 30
```

旧版 `keywords` 字段仍兼容，并在 `rules` 为空时映射成 `legacy` 规则；只要 `rules` 非空，就以具名规则为准。`enabled` 只控制自动调度，已配置的监控在暂停自动调度时仍可手动运行。

`token` 可改用环境变量 `GITHUB_TOKEN` 注入。建议创建专用、只读且权限最小的 Token。`fingerprint_key` 可改用 `GITHUB_LEAK_FINGERPRINT_KEY` 注入，应使用稳定的独立随机密钥；`hex:<64hex>` 会解码为 32 字节 HMAC key。未配置时仅为兼容旧版才从 Token 派生，轮换 Token 前应迁移到等价的 `hex:` key。管理页面只返回两项密钥是否已配置，不会回显密钥。

所有配置词会被转义并引用为字面量，用户输入不会被当作 `repo:`、`OR` 等 GitHub 查询语法执行。调度周期默认 7200 秒（2 小时），相邻请求内部固定至少 60 秒。`request_timeout_seconds` 是独立的 HTTP 超时，默认 45 秒。所有可重试响应都会遵循 `Retry-After`；只有确认限流时才使用 `X-RateLimit-Reset`。

## 入库边界

平台仅保存：规则名称及规范查询、仓库、文件路径、blob SHA、凭据类型、可信度、严重度、HMAC 指纹、固定的 `<redacted:类型>` 标记、GitHub 定位链接和发现时间。搜索片段及其上下文不会进入候选对象；数据库、API、日志和页面均不保存或返回完整候选凭据及 GitHub 原始响应。

本地 detector 对明确的赋值语法做字段白名单分类，当前包括：

- `api_key`、`apiKey`、`apikey`、`x-api-key`，以及 OpenAI、Anthropic、DeepSeek、DashScope、ARK、Moonshot、智谱等 LLM API Key 环境变量；
- 云厂商 `access_key_id`、`secret_access_key`、`access_key_secret`，以及千帆 `QIANFAN_AK/SK`；
- OAuth `client_secret`、webhook/signing secret、access/auth/bearer/refresh token 和 `Authorization: Bearer ...`；
- 现有 GitHub Token、AWS Access Key ID、Google API Key、Slack、Stripe、SendGrid、npm、Twilio 与私钥块格式。

赋值值必须满足对应的最小长度、字符类别和熵要求。`example`、`sample`、`dummy`、`changeme`、`your-*`、测试占位符、重复字符、环境变量/Vault 引用、URL 及元数据字段会被排除。普通 `password`/`token` 单词不会命中；裸 `token=` 和密码字段使用更严格阈值。OAuth client ID 属于公开标识符，只能作为检索锚点，即使与 client secret 同时出现也只保存 secret finding。

GitHub Code Search 的结果只是候选情报：它只覆盖默认分支，对大文件、历史提交、其他分支、Gist、Issue 和 PR 内容并不完整；`incomplete_results` 会被记录为部分结果，不能据此认定没有泄露。
