# 证书指纹反查关联资产

通过 SSL/TLS 证书的 SHA256/SHA1 指纹反查使用同一证书的所有域名。这是发现**未备案、未公开域名**的有效手段——同一个企业可能给所有子域名签发同一张通配证书，通过一张证书就能找到全部资产。

## 原理

```
已知域名 example.com
    ↓
提取证书 SHA256 指纹
    ↓
crt.sh / Censys / Shodan 反查该指纹
    ↓
返回所有使用同一证书的域名
    ↓
可能发现：test.example.com / jira.example.com / admin-dev.example.com
         （这些域名不在公开 DNS 记录中）
```

## 提取证书指纹

```bash
# 标准方法
openssl s_client -servername target.com -connect target.com:443 < /dev/null 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256

# 输出示例:
# SHA256 Fingerprint=8D:62:36:52:AD:5A:53:D1:FC:EA:5D:0A:35:CF:2F:60:5C:8C:74:42:2A:C6:AB:11:05:70:FD:A9:85:8A:0B:E0

# SHA1 指纹（部分数据源需要）
openssl s_client -servername target.com -connect target.com:443 < /dev/null 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha1

# 提取完整证书信息（含 SAN 列表）
openssl s_client -servername target.com -connect target.com:443 < /dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

## crt.sh 反查指纹

crt.sh 支持按证书指纹搜索域名。这是最快的免费方法。

```bash
# SHA256 指纹（去掉冒号）
curl -s "https://crt.sh/?fingerprint=8D623652AD5A53D1FCEA5D0A35CF2F605C8C74422AC6AB110570FDA9858A0BE0&output=json" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
names=set()
for e in d:
    for n in e.get('name_value','').split(chr(10)):
        if n.strip() and '*' not in n:
            names.add(n.strip())
for n in sorted(names):
    print(n)
"

# SHA1 指纹
curl -s "https://crt.sh/?fingerprint=12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78&output=json"
```

## Censys 反查指纹

Censys 的证书搜索接口，需要 API Key（免费 250 queries/月）。

```bash
curl -s -X POST "https://search.censys.io/api/v2/certificates/search" \
  -H "Accept: application/json" \
  -u "API_ID:API_SECRET" \
  -d '{"q":"fingerprint_sha256:8D623652AD5A53D1FCEA5D0A35CF2F605C8C74422AC6AB110570FDA9858A0BE0"}'
```

## Shodan 反查指纹

Shodan 支持按证书指纹搜索主机。

```bash
curl -s "https://api.shodan.io/shodan/host/search?key=KEY&query=ssl.cert.fingerprint:8D623652AD5A53D1FCEA5D0A35CF2F605C8C74422AC6AB110570FDA9858A0BE0"
```

## 证书关联分析

反查结果中可能出现以下情况：

| 情况 | 含义 | 价值 |
|------|------|------|
| 同一主域不同子域 | `www.example.com` + `api.example.com` + `admin.example.com` | 扩大攻击面 |
| 不同主域同一证书 | `example.com` + `example.cn` + `example.net` | 发现关联品牌 |
| 通配证书 `*.example.com` | 一张证书覆盖所有子域 | 全量子域名泄露 |
| 跨主体共用证书 | 多个不相关域名共用一张证书 | 可能是同一托管商或 CDN |
| Let's Encrypt 短期证书 | 90天有效期，频繁更换 | 历史证书可能泄露已下线域名 |

## 历史证书追踪

同一域名在不同时间的证书不同，历史证书的快照可以：
- 发现已下线但之前暴露的子域名
- 追踪基础设施变更（从自签→Let's Encrypt→商业CA）
- 发现之前使用但后来移除的 SAN 域名

```bash
# crt.sh 历史记录
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "
import sys,json
from datetime import datetime
d=json.load(sys.stdin)
# 按时间排序，每组取唯一证书
seen = set()
for e in sorted(d, key=lambda x: x.get('not_after','')):
    fp = e.get('fingerprint','')
    if fp not in seen:
        seen.add(fp)
        print(f'{e.get(\"not_after\",\"\")[:10]} | {fp[:20]}... | {e.get(\"issuer_name\",\"\")[:40]}')
"
```

## 证书链分析

完整的证书链（叶子证书 → 中间CA → 根CA）可用于：
- 确认证书颁发机构（不同CA的审核标准不同）
- 发现同一中间CA签发的其他客户证书（仅Censys支持）
- 判断证书类型（DV/OV/EV）

```bash
openssl s_client -servername target.com -connect target.com:443 -showcerts < /dev/null 2>/dev/null
```

## 注意

- Let's Encrypt 的短有效期证书（90天）意味着历史指纹反查可能返回已失效的域名
- CDN 后的证书可能是 CDN 提供商签发的泛域名证书（如 Cloudflare 的 `*.cloudflare.com`）
- 反查结果需要人工验证域名归属，避免误将 CDN 共享证书的域名归为目标
- 部分 CDN 提供证书加密，不会暴露后端真实证书
