# dddd 二开：指纹 + JS 逆向 + 缓存优化

## FingerprintHub 指纹集成

从 `0x727/FingerprintHub` (⭐1,410) 的 `web_fingerprint_v4.json` (3183 条指纹) 中提取国产系统相关指纹，内置为 `cnassets.BuiltinFingerprints`。

### 内置的 22 个国产系统指纹

| 类别 | 系统 | 探测路径 | 关键特征 |
|------|------|---------|---------|
| OA | 致远OA | /seeyon /seeyon/login | body: seeyon, 致远 |
| OA | 泛微OA | /weaver /wui | body: weaver, 泛微 |
| OA | 通达OA | /ispirit /ispirit/login.php | body: ispirit, 通达OA |
| OA | 蓝凌OA | /landray | body: landray, 蓝凌 |
| OA | 万户OA | /defaultroot | body: defaultroot, 万户 |
| OA | 华途OA | /huatuo | body: huatuo, 华途 |
| ERP | 用友ERP | /yyoa /yonyou /ufida /U8 | body: yyoa, yonyou, ufida, 用友 |
| ERP | 金蝶ERP | /kingdee /kdlogin | body: kingdee, 金蝶 |
| ERP | 明源云ERP | /PubPlatform/Login /Mdc/Login/Index.html | body: PubPlatform, 用户登录-明源, 数据服务中心 |
| 报表 | 帆软FineReport | /ReportServer /webroot/decision | body: ReportServer, FineReport |
| 报表 | 帆软FineBI | /webroot/decision/login | body: FineBI |
| 配置中心 | Nacos | /nacos | body: nacos, Nacos Server |
| 配置中心 | Druid | /druid/index.html | body: Druid StatIndex |
| 配置中心 | Swagger | /swagger-ui.html /v2/api-docs | body: swagger-ui, apiVersion |
| 框架 | Spring Actuator | /actuator /actuator/health | body: _links, UP, status |
| 安全 | JumpServer | /jumpserver /api/health | body: jumpserver |
| 安全 | 齐治堡垒机 | /qizhi | body: 齐治, Shterm |
| DevOps | Jenkins | /jenkins /login | body: Jenkins |
| DevOps | GitLab | /users/sign_in | body: GitLab |
| DevOps | Confluence | /login.action | body: Confluence |
| DevOps | Jira | /secure/Dashboard.jspa | body: Jira |
| 框架 | Apache Shiro | /login | header: Set-Cookie → rememberMe |

### 非标端口（17 个）

```
9090, 9060, 50780, 19051, 9010, 9070, 9000, 7213,
8089, 8443, 8008, 8888, 10002, 5555, 11211, 27017, 6379
```

### 国产系统路径（22 条）

覆盖 Vue SPA 配置(/config.js, /webConfig.js)、明源系列(/PubPlatform/Login, /Mdc/Login/Index.html)、国产 OA 系统、云原生中间件(Nacos, Druid, Swagger)、DevTools(.git, .env, phpinfo)。

## JS 逆向分析模块

`common/jsrecon/jsrecon.go` — 不依赖外部 CLI，只对已缓存的 HTTP 响应体做正则匹配。

| 功能 | 匹配内容 |
|------|---------|
| config.js 提取 | window.g = {baseUrl, token, appid, agentid} |
| Next.js 配置 | __NEXT_DATA__ runtimeConfig (API/内部域名/CDN/AppID) |
| RSA 公钥 | -----BEGIN PUBLIC KEY----- 硬编码公钥 |
| 隐藏 URL | JS chunk 中 https?:// 开头的非公开域名 |

## 缓存优化：零额外 HTTP 请求的指纹匹配

指纹匹配优化前：对每个存活 URL 重新发 nethttp.Get()获取响应体。

优化后：从 httpx 探测阶段已缓存的 hybrid map 中读取 body 和 header，零额外请求。

```go
// body 匹配
if bodyBytes, ok := structs.GlobalHttpBodyHMap.Get(pathEntity.Hash); ok {
    body := string(bodyBytes)
    // 匹配关键字...
}

// header 匹配
if headerBytes, ok := structs.GlobalHttpHeaderHMap.Get(pathEntity.HeaderHashString); ok {
    // 匹配 Set-Cookie 等 header 特征
}
```

## CLI 参数

```bash
--jsrecon  启用 JS 逆向分析
--cnasset  启用国产系统资产增强（非标端口 + 国产路径 + 22 个指纹）
--quake-key Quake API Key（默认读取 ~/.hermes/scripts/.quake_key）
```
