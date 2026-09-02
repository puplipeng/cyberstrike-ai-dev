# afrog 空间搜索引擎配置详情

## 已验证的事实 (afrog v3.5.3)

**源码位置:** `zan8in/afrog` GitHub 仓库, `pkg/cyberspace/cyberspace.go`

### 支持情况

| 引擎 | CLI 参数 | 实际支持 | 配置键 |
|------|----------|----------|--------|
| ZoomEye | `-cs zoomeye` | ✅ 已实现 | `cyberspace.zoom_eyes` |
| FOFA | `-cs fofa` | ❌ 未实现 | 无 |
| 360 Quake | `-cs quake` | ❌ 未实现 | 无 |
| Shodan | `-cs shodan` | ❌ 未实现 | 无 |

### 源码证据

```go
// pkg/cyberspace/cyberspace.go
func (c *Cyberspace) GetApiKey(engine string) string {
    switch engine {
    case "zoomeye":
        if len(c.Config.Cyberspace.ZoomEyes) > 0 {
            return c.Config.Cyberspace.ZoomEyes[0]
        }
        return ""
    }
    return ""  // 其他引擎全部走这里
}
```

### 唯一有效的配置格式

```yaml
# ~/.config/afrog/afrog-config.yaml
cyberspace:
  zoom_eyes:
    - "your_zoomeye_api_key"
```

### 无效的配置格式 (会被忽略)

```yaml
# 以下格式均无效！afrog 不会报错但也不会使用这些配置
quake:
  api_key: "xxx"        # ❌ afrog 不支持 Quake
fofa:
  email: "xxx"
  api_key: "xxx"        # ❌ afrog 不支持 FOFA
zoomeye:
  api_key: "xxx"        # ❌ 错误键名，必须用 zoom_eyes 数组
shodan:
  api_key: "xxx"        # ❌ afrog 不支持 Shodan
```

**注意：** 这些无效配置不会被 afrog 报错，只是静默忽略。如果写了 `quake.api_key` 并用 `-cs quake`，会看到 "engine quake api key is empty" 错误——这不是配置问题，而是 afrog 根本没实现 Quake。

## Quake API 替代方案

**⚠️ Quake API 域名已迁移：`quake.360.cn` → `quake.360.net`（旧域名返回 308 重定向）**

### 子域名收集（quake_service 端点）

```bash
# 最常用：按域名查询，返回完整服务信息
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: YOUR_API_KEY" \
  -d '{"query": "domain: target.com", "start": 0, "size": 200}'

# 返回结构：
# data[].service.http.host  → 域名
# data[].service.http.title → 页面标题
# data[].service.http.server → Server头
# data[].ip                 → IP地址
# data[].port               → 端口
# data[].service.name       → 服务名 (http, http/ssl)
```

### IP 反查

```bash
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: YOUR_API_KEY" \
  -d '{"query": "ip: 1.2.3.4", "start": 0, "size": 100}'
```

### 注意事项

- 认证头：`X-QuakeToken`（不是 `Authorization`）
- `quake_service` 端点不支持 `service.port` 等细粒度 include 字段，会报 "筛选字段传参错误"
- 旧端点 `quake.360.cn` 返回 308，必须用 `quake.360.net`
- Quake 结果可以喂给 dddd/afrog 进一步扫描
