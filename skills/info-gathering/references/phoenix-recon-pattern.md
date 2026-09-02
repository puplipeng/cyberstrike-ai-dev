# Phoenix Recon：域名无 DNS 解析时的历史资产发现

## 场景

域名注册但无 A 记录（DNS 不解析），无法通过正常方式访问。常见原因：
- 域名到期未续费
- DNS 记录被删除
- 仅作为跳转/备案域名存在
- 服务器迁移后未更新 DNS

## 方法

### 1. 360 Quake 历史数据检索

即使域名不解析，Quake 仍保留历史扫描记录：

```http
POST /api/v3/search/quake_service HTTP/1.1
Host: quake.360.net
Content-Type: application/json
X-QuakeToken: ${QUAKE_KEY}

{"query": "domain: woniumovie.com", "start": 0, "size": 200}
```

返回内容包含：历史 IP、开放端口、服务指纹、组件识别、注册人信息。

### 2. 源站 IP 反查

从 Quake 返回的源站 IP 反查更多资产：

```http
POST /api/v3/search/quake_service HTTP/1.1
Host: quake.360.net
Content-Type: application/json
X-QuakeToken: ${QUAKE_KEY}

{"query": "ip: 154.206.135.22", "start": 0, "size": 500}
```

可发现同 IP 的其他域名、所有开放端口、组件版本。

### 3. 实战案例：woniumovie.com

woniumovie.com DNS 无 A 记录，但 Quake 仍返回历史数据：
- **源站 IP**: 154.206.135.22 (Windows Server 2012 R2)
- **Cloudflare IPs**: 172.67.203.157, 104.21.69.36, 104.21.17.12
- **源站开放端口**: WinRM 5985/5986, MSRPC 1025-1028, nginx 80/443/888/8888
- **同 IP 其他站点**: china-puyi.com（影视站，苹果CMS）、szqinlv.com
- **组织**: OWGELS INTERNATIONAL CO., LIMITED

### 4. 局限

- Quake 扫描周期导致数据可能滞后（数天到数周）
- 域名彻底注销后数据最终会消失
- 需主动探测确认当前状态
