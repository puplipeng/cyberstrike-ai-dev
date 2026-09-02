# 蜗牛学苑 woniumovie.com 信息收集案例

## 目标
`woniumovie.com` — 蜗牛学苑关联域名（同 ICP：蜀ICP备15014130号-2）

## 特殊场景
目标域名 DNS 无 A 记录（仅 NS 记录），无法通过正常域名解析访问。通过 Quake 历史数据发现真实资产。

## 执行流程

### 1. ICP 关联
通过已有 ICP 备案号反查，确认 woniumovie.com 与 woniuxy.com 同属成都沃尼创想科技有限公司。

### 2. Quake 空间测绘
```http
POST /api/v3/search/quake_service HTTP/1.1
Host: quake.360.net
Content-Type: application/json
X-QuakeToken: ${QUAKE_KEY}

{"query": "domain: woniumovie.com", "start": 0, "size": 200}
```

### 3. 发现
- **源站 IP**: 154.206.135.22（Windows Server 2012 R2）
- **开放端口**: 5985 WinRM, 5986 WinRM HTTPS, 47001, 1025-1028 MSRPC
- **组织**: OWGELS INTERNATIONAL CO., LIMITED
- **同 IP 站点**: china-puyi.com（苹果CMS影视站）, szqinlv.com
- **Cloudflare CDN IPs**: 172.67.203.157, 104.21.69.36, 104.21.17.12

### 4. 关键结论
域名无 A 记录不等于资产不存在。通过 Quake 历史数据 + IP 直连仍可发现并定位真实源站。
