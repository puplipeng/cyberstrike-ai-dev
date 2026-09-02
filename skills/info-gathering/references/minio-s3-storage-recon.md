# MinIO / S3 存储后端信息收集

S3 兼容对象存储（MinIO / AWS S3 / Cloudflare R2）的探测与指纹识别方法论。

## 快速识别

### 响应头指纹

S3 兼容 API 的特性响应头：

```
X-Amz-Id-2:     dd9025bab4ad464b...   ← S3 请求追踪 ID（所有 S3 兼容服务通用）
X-Amz-Request-Id: 18B9D642440B7848    ← S3 请求 ID
X-Amz-Bucket-Region: us-east-1        ← Bucket 区域（可能暴露内部区域名）
```

```bash
curl -skI "https://target:8443/" | grep -i "x-amz-"
```

### MinIO vs AWS S3 vs Cloudflare R2

| 特征 | MinIO | AWS S3 | Cloudflare R2 |
|:---|:---:|:---:|:---:|
| Server 头 | nginx 或自定义 | AmazonS3 | cloudflare |
| /minio/admin/ 响应 | 426 / 403 / "XMinioAdminVersionMismatch" | 404 | 404 |
| /minio/health/live | 200 OK | 404 | 404 |
| 错误消息 | `mode-server-xl-single` | `NoSuchBucket` | 标准 S3 XML |
| Admin API | `/minio/admin/v3/` | 不存在 | 不存在 |
| Console UI | :9001 或自定义端口 | AWS Console | R2 Dashboard |

```bash
# MinIO 特有端点探测
curl -sk "https://target:8443/minio/health/live"
# MinIO → 200 OK ； AWS/R2 → 404

# Admin API 版本探测
curl -sk "https://target:8443/minio/admin/v2/info"
# MinIO 返回 426 → "XMinioAdminVersionMismatch"
# 消息含 mode-server-xl-single = 单机单盘
```

## MinIO 部署模式

Admin API 错误消息中提取：

```json
{"Code":"XMinioAdminVersionMismatch",
 "Message":"This 'admin' API is not supported by server in 'mode-server-xl-single'" }
```

| 模式 | 含义 |
|:---|:---|
| `mode-server-xl-single` | 单机单盘（EC 模式，1 节点） |
| `mode-server-pool` | 多节点池 |
| `mode-server-xl` | 多节点 EC 模式 |

```bash
curl -sk "https://target:8443/minio/admin/v3/cluster"
# "mode-server-xl-single" → 单机 ； "mode-server-pool" → 多节点
```

## 端口探测

MinIO 双端口架构：

| 端口 | 用途 | 默认 | 备注 |
|:---:|:---|:---:|:---|
| S3 API | 对象存储 API | 9000 / 8443 | 通常经 CDN 暴露 |
| Console UI | Web 管理界面 | 9001 / 自定义 | **通常防火墙拦截** |

```bash
for port in 9001 60032 9090 10000; do
  timeout 3 bash -c "echo -n '' > /dev/tcp/target_ip/$port" 2>/dev/null \
    && echo "✅ :$port OPEN" || echo "❌ :$port closed"
done
```

## Bucket 枚举

### 存在性判断

```bash
for bucket in name1 name2; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target:8443/${bucket}/")
  echo "${bucket}: ${code}"
done
```

| 状态码 | 含义 |
|:---:|:---|
| 200 | Bucket 公开可读 |
| 403 | Bucket 存在（无匿名权限） |
| 404 | Bucket 不存在（仅 AWS S3 可靠） |
| 403（全部路径） | 全局 Deny 策略，无法区分 |

⚠️ 配置了全局 Deny 的 MinIO 实例对所有路径返回 403，包括不存在的 Bucket。

### 列出内容

```bash
curl -sk "https://target:8443/bucket/?list-type=2"
curl -sk "https://target:8443/bucket/?location"
curl -sk "https://target:8443/bucket/?max-keys=1"
```

## 匿名访问测试

| 操作 | 端点 | 预期结果 |
|:---|:---|---:|
| 根端点 | `GET /` | 403 |
| 读对象 | `GET /bucket/obj` | 403 / 200 |
| 写对象 | `PUT /bucket/test` | 403 |
| CORS 预检 | `OPTIONS /` | 200 |
| Admin API | `GET /minio/admin/v3/info` | 403 |
| WebRPC | `POST /webrpc` | 400 BadRequest |

### 绕过 CDN 直连源站

```bash
curl -sk "https://target:8443/"           # 走 CDN
curl -sk "https://origin-ip:8443/"        # 直连源站
```

### 虚拟托管风格

```bash
curl -sk "https://origin-ip:8443/" -H "Host: bucket.domain.com"
```

## Console UI 探测

### 默认凭据

```bash
for creds in "minioadmin:minioadmin" "admin:password"; do
  user=$(echo $creds | cut -d: -f1)
  pass=$(echo $creds | cut -d: -f2)
  auth=$(echo -n "$user:$pass" | base64)
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Basic ${auth}" \
    "https://target:8443/minio/admin/v3/info")
  echo "${user}:${pass} -> ${code}"
done
# 400 → MinIO 不支持 Basic Auth（需 AWS SigV4）
# 200 → Console 有独立 Cookie 认证
```

## 防火墙拦截判断

| 响应时间 | 含义 |
|:---:|:---|
| 0.1-0.3s | **iptables DROP** — 端口存在但被拦截 |
| 3-10s | **网络超时** — 端口不存在或被中间设备丢弃 |
| 立即连接 | **端口开放** |

```bash
curl -sk --connect-timeout 5 -o /dev/null -w "耗时: %{time_total}s\n" "http://target:port/"
```

## 常见 Bucket 名

```bash
{domain}  {domain}-{tld}  www  assets  static  files
uploads   backups   data  media  images  public  private  docs  service  api
```

## 突破路径（全 403 时）

```
1. SSRF → http://127.0.0.1:60032/ 或 http://localhost:9001/
2. Web 源码泄露 → .env / config.js 中的 MINIO_ACCESS_KEY
3. SSH 进服务器 → 本地访问 Console
4. frp/SSH 隧道 → ssh -L 60032:127.0.0.1:60032 user@target
```
