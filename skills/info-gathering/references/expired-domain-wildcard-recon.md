# Expired Domain Wildcard Recon

## 场景

域名过期但泛解析（wildcard DNS）未关闭。主域名指向停放页（172.65.211.209 Gname），但子域名通过泛解析指向不同后端（nginx 源站、Cloudflare CDN）。

## 价值

- 过期域名仍在托管 20+ 活跃的企业站点
- 部分 Cloudflare 子域名返回 521（Web server is down），存在子域名接管风险
- 泛解析使攻击面远大于域名本身

## 识别方法

```bash
# 1. DNS 基础
dig +short example.com A
# → 172.65.211.209 (Gname 停放页，域名已过期)

# 2. Quake 泛域名搜索 — 直接搜域名看子域名
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "Content-Type: application/json" \
  -H "X-QuakeToken: ${KEY}" \
  -d '{"query": "domain: example.com", "start": 0, "size": 200}'
# 返回 62 条记录：m.example.com（AGE动漫站）、tjtcjxdypyxgsktg.example.com（企业站）等

# 3. 区分停放页和真实网站
# 停放页：只有 NS 记录，A 记录指向注册商 IP
# 真实子域名：nignx/Tengine/Cloudflare，有业务内容
```

## 案例：szqinlv.com

- 注册商：Gname.com Pte. Ltd.
- 创建时间：2023-06-19
- 过期状态：NS 为 expire1.gname-dns.com
- 源站：154.206.135.22（Windows Server 2012 R2 + nginx）
- CDN：Cloudflare 多端口代理（80/443/8080/8443/8880/2052/2053/2083/2086/2087/2095/2096）
- 企业站点：20+ 个随机子域名（nginx/1.14.0 Ubuntu, Krypt Technologies）
  - `tjtcjxdypyxgsktg.szqinlv.com` — 天津同诚净洗涤用品有限公司
  - `hnqyhyslyxgsqpf.szqinlv.com` — 河南倩阳辉源饲料有限公司
  - `cdcfsmyxzrgsaj5.szqinlv.com` — 成都诚菲商贸有限责任公司
  - `bjggjykjyxgs6en.szqinlv.com` — 北京古格教育科技有限公司
- 动漫站：`m.szqinlv.com` — AGE动漫（Tengine, 503）

## PoC 场景

1. **子域名接管**：Cloudflare 子域名返回 521 → 可能未绑定后端 → 尝试在 Cloudflare 注册
2. **源站固定**：源站 IP 不变（154.206.135.22），域名过期但源站仍可直连
3. **供应链攻击**：20+ 企业站点在一台 nginx 1.14.0 Ubuntu 上，一个漏洞影响多家
