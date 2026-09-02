# 字节跳动 / 腾讯云 CDN 指纹识别

## 字节跳动 CDN（Lego Server）

| 特征 | 值 |
|------|-----|
| Server 头 | `Lego Server` |
| 响应头 | `X-Tt-Supplier-Id`, `X-Tt-Trace-Host`, `X-Tt-Trace-Tag` |
| 典型 CNAME | `*.dailygn.com.cdn.dnsv1.com` |
| 常见子域名 | `lf11-atom-cn.dailygn.com`（lf = live? front?） |
| ICP 主体 | 北京朝夕光年信息技术有限公司（字节跳动游戏子公司） |
| 状态码 | 418 拦截不匹配 Host 头的直连请求 |
| 跳转模式 | 302 → 对应区域的 CDN 域名 |

**字节跳动/抖音系 CDN 的 X-Tt- 头特征：**

```
X-Tt-Supplier-Id: 0_27         # 供应商/区域 ID
X-Tt-Trace-Host: 01ba2c21ef... # 追踪标识
X-Tt-Trace-Tag: id=11;cdn-cache=hit;type=static
```

### 识别方法

```bash
# 1. Server 头
curl -skI "https://target.com" | grep -i "^server:"
# Server: Lego Server → 字节跳动 CDN

# 2. X-Tt- 特征头
curl -skI "https://target.com" | grep -i "^x-tt-"

# 3. CNAME 链
dig target.com CNAME +short | grep -i "dailygn.com\|dnsv1.com"

# 4. ICP 备案号查主体
# 京ICP备13010862号-8 → 北京朝夕光年信息技术有限公司
```

## 腾讯云 CDN（TencentEdgeOne / Lego Server 混用）

**注意：** 腾讯云 CDN 和字节跳动 CDN 都可能返回 `Server: Lego Server`。区分方法：

| 区分维度 | 字节跳动 | 腾讯云 |
|---------|---------|--------|
| Server 头 | `Lego Server` | `Lego Server` 或 `TencentEdgeOne` |
| 特征头 | `X-Tt-*` | `X-NWS-LOG-UUID` 或 `EO-LOG-UUID` |
| 缓存头 | `X-Cdn-Cache: Hit from oc` | `X-Cache-Lookup: Return Directly` |
| 证书 CN | `*.dailygn.com` 等 | `*.cdn.myqcloud.com`（腾讯云 CDN） |
| 所属公司 | 字节跳动/朝夕光年 | 腾讯云 |

### 腾讯云 CDN 特征

```bash
# 腾讯云 CDN（旧版）
curl -skI "https://target.com" | grep -i "^server:"
# Server: Lego Server  (与字节跳动相同)
# 区别在:
# X-NWS-LOG-UUID: 13044025482409359089
# X-Cache-Lookup: Return Directly

# 腾讯云 EdgeOne（新版）
# Server: TencentEdgeOne
# EO-LOG-UUID: xxx
```

## 快速判断脚本

```bash
# 判断 CDN 厂商
cdn_identify() {
  local url=$1
  echo "=== CDN 指纹识别: $url ==="
  echo "--- Server 头 ---"
  curl -skI "$url" 2>/dev/null | grep -iE "^server:|^x-tt-|^x-nws-|^eo-log-|^x-cdn-cache"
  
  echo "--- 证书 CN ---"
  domain=$(echo "$url" | sed 's|https://||;s|/.*||')
  echo | openssl s_client -connect "${domain}:443" -servername "$domain" 2>/dev/null | \
    openssl x509 -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*[^\s,]+'
}

cdn_identify "https://target.com"
```

## 哪些厂商用 Lego Server

目前已知：
- **腾讯云 CDN**（旧版节点）：Server: Lego Server，带 X-NWS-LOG-UUID
- **字节跳动/抖音系 CDN**（朝夕光年/dailygn.com）：Server: Lego Server，带 X-Tt-* 头
