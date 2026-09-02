# 过期域名 + 泛解析 Wildcard 子域名发现模式

**目标:** szqinlv.com
**场景:** 域名已过期（Gname 停放页），但泛解析 wildcard DNS 未关闭，发现 20+ 活跃中国企业子站点

## 流程

### 1. DNS 基础探测
```
dig +short szqinlv.com A → 172.65.211.209（Gname 停放 IP）
```
域名已过期，解析到注册商默认停放页。

### 2. Quake 空间测绘
```
query: "domain: szqinlv.com"
```
返回 62 条服务记录，发现：
- 主站 `szqinlv.com:80` → nginx, "无法访问此网站", 同源 154.206.135.22
- 子域名 `m.szqinlv.com:80` → **AGE动漫**（Tengine 503）
- 20+ 随机子域名 → 中国企业官网（nginx 1.14.0 Ubuntu, Krypt Technologies）
- Cloudflare 泛解析 → 随机子域名通过 CF 代理（部分 521 Web server is down）

### 3. 发现的企业站点（示例）
- `tjtcjxdypyxgsktg.szqinlv.com` — 天津同诚净洗涤用品有限公司
- `hnqyhyslyxgsqpf.szqinlv.com` — 河南倩阳辉源饲料有限公司
- `cdcfsmyxzrgsaj5.szqinlv.com` — 成都诚菲商贸有限责任公司
- `bjggjykjyxgs6en.szqinlv.com` — 北京古格教育科技有限公司
- `csblsjkjyxgskg0.szqinlv.com` — 长沙标磊数据科技有限公司

## 关键技术点

1. **域名过期 ≠ 服务下线** — 子域名的泛解析可能仍指向活跃的后端服务器
2. **Wildcard DNS 暴露攻击面** — 同一域名下的随机子域名指向不同服务器（nginx、Tengine、Cloudflare），扩大攻击面
3. **Subdomain Takeover 风险** — Cloudflare 子域名返回 521（Web server is down）表示 CF 配置了回源但源站已不可达，可尝试注册接管
4. **Quake 的 domain 搜索查的是历史+当前数据** — 即使域名当前 DNS 不解析，Quake 仍保留历史服务记录

## 关联
- 同组织: OWGELS INTERNATIONAL CO., LIMITED
- 同 IP: 154.206.135.22（见 woniumovie-recon-case.md）
