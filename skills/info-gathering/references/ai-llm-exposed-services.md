# 公网暴露 AI/LLM 服务搜索

## Ollama 实例

Ollama 默认端口 11434。搜索暴露在公网的实例并验证是否有鉴权。

### Quake 搜索

```bash
# 发现端口 11434 上所有服务
python3 ~/.hermes/tools/quake_query.py --search 'port:11434 AND body:"model" AND body:"Ollama"' --size 50 --format md

# 限制国内
python3 ~/.hermes/tools/quake_query.py --search 'body:"model" AND body:"Ollama" AND port:11434 AND country:CN' --size 50 --format md

# 搜特定大模型（70B+）
python3 ~/.hermes/tools/quake_query.py --search 'body:"70b" AND port:11434' --size 10 --format md
python3 ~/.hermes/tools/quake_query.py --search 'body:"72b" AND port:11434' --size 10 --format md
```

### 验证是否为真实 Ollama

```bash
# 1. 检查根路径
curl -sk "http://IP:11434/"

# 2. 列出模型
curl -sk "http://IP:11434/api/tags"

# 3. 调用生成（测试无鉴权）
curl -sk "http://IP:11434/api/generate" \
  -d '{"model":"deepseek-r1:latest","prompt":"hi","stream":false}'
```

### 区分真实实例与反向代理

| 特征 | 真实 Ollama | 反向代理（如 Straico） |
|------|------------|----------------------|
| 模型大小 | 各不相同（2~80GB） | 全部统一固定值（如 7024MB） |
| 模型名称 | 标准 Ollama 格式 | 厂家品牌前缀（OpenAI:/Anthropic:/Meta:） |
| 生成 | 返回推理结果 | Internal Server Error |
| /api/version | 返回版本号 | 返回版本号或 0.9.0 |
| /api/ps | 返回加载中的模型 | 返回空 |

### 规模统计数据

| 搜索条件 | 结果数 |
|---------|--------|
| port:11434（全部） | ~335,000 条 |
| 确认为 Ollama（body 匹配 model+Ollama） | ~981 台 |
| 国内 Ollama | ~50+ 台 |
| 搭载 70B+ 模型 | ~7 台（海外） |
| 大模型实例是否可用 | ❌ 全被封 |

### 注意事项

- 国内 Ollama 实例多为统一模板部署（5 个固定模型：deepseek-r1/llama3/mistral/qwen，均约 2~5GB）
- 大模型（70B+）实例均在海外，无法从国内连通
- 可通过代理尝试连接海外实例
- 判断是否走代理：`export https_proxy=http://127.0.0.1:7897`

## Gradio / HF Spaces

Gradio 常见端口为非标端口，Quake 不直接支持 service:gradio。推荐 body 匹配：

```bash
python3 ~/.hermes/tools/quake_query.py --search 'body:"gradio" AND body:"model"' --size 50 --format md
```
国内约 44,000+ 条。但大多数 Gradio 的 `/api/predict` 和 `/api/chat` 返回 404，不开放推理接口。

## OpenAI API 兼容端点

```bash
python3 ~/.hermes/tools/quake_query.py --search 'body:"openai" AND body:"v1" AND body:"chat" AND body:"completions"' --size 50 --format md
```
全球约 90,000 条，国内约 16,000 条。大部分是反向代理，需要 API key 才能调用。
