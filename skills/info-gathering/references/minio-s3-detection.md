# MinIO / S3 兼容存储后端检测

## 检测方法

### 1. S3 兼容 API 指纹（响应头）

向非标 HTTPS 端口发起 GET 请求，检查响应头：

```bash
curl -skI "https://target.com:8443/" 2>&1
```

| Header | 含义 | 示例 |
|--------|------|------|
| `X-Amz-Id-2` | S3 请求跟踪 ID | `dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8` |
| `X-Amz-Request-Id` | S3 请求 ID | `18B9D642440B7848` |
| `X-Amz-Bucket-Region` | Bucket 区域 | `us-east-1` |
| `x-amz-*` 其他 | 任何 x-amz- 前缀头 | 如 `x-amz-delete-marker` |

**确认标准：** 响应含任意 `x-amz-` 前缀头 → S3 兼容 API。

### 2. MinIO 版本指纹

通过访问 Admin API 端点获取版本信息：

```bash
# v2（返回 426 Upgrade Required，告知正确版本）
curl -sk "https://target.com:8443/minio/admin/v2/info"
# 响应：{"Code":"AccessDenied","Message":"Access Denied."}
# 如果带 Upgrade: websocket 头：
curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" \
  "https://target.com:8443/minio/admin/v2/info"
# 响应：{"Code":"XMinioAdminVersionMismatch",
#   "Message":"Server expects client requests with 'admin' API version 'v3'",
#   ...}
```

| 指纹 | 含义 |
|------|------|
| `XMinioAdminVersionMismatch` | ✅ MinIO 确认 |
| `mode-server-xl-single` | 单机单盘模式 |
| Admin API v3 | MinIO RELEASE.2024+ |
| 426 Upgrade Required | MinIO Admin API 未认证 |

### 3. Bucket 枚举

S3 兼容 API 通过 403 vs 404 区分 Bucket 是否存在：

```bash
for bucket in luckyyyyy service www assets static files uploads backups data; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 \
    "https://target.com:8443/${bucket}/")
  echo "$bucket: $code"
done
```

| 状态码 | 含义 |
|--------|------|
| **403** | Bucket 存在（Access Denied，需要认证） |
| **404** | Bucket 不存在（NoSuchBucket） |

**注意：** 如果所有路径（含随机名）都返回 403，说明 S3 后端配置了全局 Deny All，无法枚举。

### 4. MinIO Console 端口

| 默认端口 | 服务 | 说明 |
|:---:|:---|:---|
| 9000 | S3 API | 标准 S3 端点 |
| 9001 | Console UI | Web 管理界面（可能映射到非标端口）|
| 8443 | 常见反代端口 | nginx 反代 S3 API |

Console UI 判断：
```bash
curl -sk "http://target:9001/"                # MinIO Console
curl -sk "http://target:9001/login"           # 登录页
curl -sk "http://target:9001/api/buckets"     # API
```

### 5. Cloudflare 源站暴露场景

```
luckyyyyy.online ─┬─ Cloudflare CDN (104.21.x.x)
                  └─ 源站: 154.26.181.125
                        ├── :443 → service.luckyyyyy.online（nginx 静态站）
                        └── :8443 → MinIO S3 API（X-Amz 指纹确认）
```

检测要点：
- **service 子域名直接解析到源站 IP** → CDN 保护被旁路
- **非标端口 :8443** → Cloudflare 仅代理 80/443，非标端口可直接访问
- **SSL 证书状态**：源站使用 CloudFlare Origin CA 自签证书（不由公共 CA 信任），
  而公共域名的 CF 代理使用 Let's Encrypt

### 6. 完整探测流程

```bash
# 步骤 1: 确认 S3 兼容 API
curl -skI "https://target:8443/" | grep -i 'x-amz'

# 步骤 2: 确认 MinIO
curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" \
  "https://target:8443/minio/admin/v2/info" | grep -o 'mode-server-[^"]*'

# 步骤 3: Bucket 枚举
for bucket in $(cat buckets.txt); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target:8443/${bucket}/")
  [ "$code" = "403" ] && echo "Bucket exists (locked): $bucket"
  [ "$code" = "404" ] && echo "No such bucket: $bucket"
done

# 步骤 4: 尝试匿名读写
curl -sk -X PUT "https://target:8443/test-bucket/test.txt" -d "test" \
  -o /dev/null -w "%{http_code}"
# 403 = 写拒绝, 200 = 可匿名写

# 步骤 5: 尝试匿名列举
curl -sk "https://target:8443/luckyyyyy/?list-type=2" \
  -o /dev/null -w "%{http_code}"
# 403 = 列举拒绝, 200 = 可列举
```

## Pitfalls

1. **403 不一定是 Bucket 存在** — 某些 S3 后端对所有路径返回 403（全局 Deny），
   此时需通过响应体中的 `<BucketName>xxx</BucketName>` 标签确认
2. **MinIO 小版本差异** — Admin API 端点路径（v1/v2/v3）随版本变化，
   优先尝试 v3（当前最新）
3. **Cloudflare 代理 S3** — 如果通过 CF 访问 :8443，CF 可能添加额外安全头，
   直连源站 IP 获得原始 S3 响应
4. **WSL 中 iptables 无效** — WSL 的 iptables 是软实现，不拦截实际流量。
   如需阻断出站连接，需在 Windows 防火墙侧操作
