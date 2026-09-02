# 华住酒店集团 (Huazhu) 非常规资产侦察案例

## 概述

华住宿酒店集团（H World / 华住会），旗下汉庭、全季、桔子水晶、美居等 30+ 品牌，是中国最大酒店集团之一（全球第4）。本次侦察聚焦**非常规资产**（非 SSO/主站，已被大量测试），挖掘 B 端业务系统、CDN、非标准域名等薄弱环节。

## 侦察路线

1. Certificate Transparency（crt.sh）→ 发现 20+ 子域名
2. Next.js `__NEXT_DATA__` → 提取内部 API 域名和配置
3. JS chunk 源码分析 → 发现隐藏子域名和 API Key
4. Server 头指纹 → 识别 Tengine/APISIX/腾讯 COS
5. 公共 API 端点测试 → 发现 CORS 漏洞

## 关键发现

### 资产清单

| 域名 | 类型 | 技术栈 |
|------|------|--------|
| hworld.com | 主站 | Next.js + Tengine + APISIX |
| m.hworld.com | 移动端 | Next.js（额外 wxAppId） |
| ows-nofficial.huazhuidc.com | 后端 API | **非标准域名**（huazhuidc.com） |
| hweb-personalcenter.hworld.com | 个人中心 API | 会员数据接口 |
| signin.hworld.com | SSO 登录 | Next.js + TGW + WAF |
| franchise-huazhu.com | 加盟商 | Vue 2 SPA |
| franchise-out.huazhu.com | **外部 API** | **CORS 通配符** |
| franchise-cmsapi.huazhu.com | **CMS API** | Spring Boot + 观测云 APM |
| hb2btravel.huazhu.com | 商旅 B 端 | Umi.js 3.5.34 |
| b2b.huazhu.com | 采购平台 | APISIX |
| campaign.huazhu.com | 活动页面 | **腾讯 COS** |
| ows-cdn.huazhu.com | 主 CDN | CDN 静态资源 |
| cdn.huazhu.com | B 端 CDN | **腾讯 COS** |
| res-pub.huazhu.com | 资源 CDN | 腾讯 COS |
| duhu.huazhu.com | 内部系统 | 403（Tengine） |
| career.hworld.com | 社会招聘 | 北森 iTalent SaaS |
| campus.hworld.com | 校园招聘 | 北森 iTalent |
| exp-e.huazhu.com | 费用报销 | Server: CE_E |
| exp-e01.huazhu.com | 费用报销2 | 400 Bad Request |

### 内网资产（公网可达但仅返回 Connection established）

| 域名 | 系统 | 攻击面 |
|------|------|--------|
| jira.huazhu.com | JIRA 项目管理 | 用户枚举、漏洞公开 |
| sslvpn.huazhu.com | SSL VPN | VPN 接入点泄露 |
| adfs.huazhu.com | ADFS | 联合认证配置泄露 |
| sunlogin.huazhu.com | 向日葵远程控制 | CNVD-2022-10270 RCE（历史） |
| wafwl.huazhu.com | WAF 白名单管理 | 白名单规则绕过 |
| aiot.huazhu.com | IoT 平台 | 设备管理接口 |
| hmeeting.huazhu.com | 视频会议 | 502 后端离线 |
| *.int.hworld.com | 开发/测试环境 | api/admin/dev/test/uat 等 |

### 信息泄露

1. **高德地图 API Key**：`6ebf98a4368fca69ac36c5769cda5052`
   - 来源：franchise 系统 JS chunk 中硬编码
   - 用途：高德地图 POI 搜索、逆地理编码
   - 风险：可查配额、调用统计、绑定的 Web 服务

2. **微信 AppId**：`wx3d59bdf075b94c9b`
   - 来源：移动端 __NEXT_DATA__ runtimeConfig
   - 用途：华住会微信小程序 OAuth

3. **观测云 (Guance) APM 追踪 ID**
   - 来源：franchise-cmsapi 响应头 `guance_trace_id`
   - 用途：APM 链路追踪，可反查内网服务拓扑

4. **后端实例 ID**：`X-Instance-Id: jD6dLRMWktjJuxDlXqH_4A==`
   - 来源：franchise-cmsapi 响应头
   - 用途：服务器实例指纹

5. **WAF UUID**：`X-WAF-UUID: 38bc39c97bedbecb7acb8865597df116-...`
   - 来源：signin.hworld.com 响应头
   - 用途：可能是签名/会话标识

### CORS 严重配置缺陷

**franchise-out.huazhu.com：**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: *
```
通配符 Origin + Credentials: true + 允许所有 Header → 严重 CORS 漏洞

**franchise-cmsapi.huazhu.com 允许的认证 Header：**
```
Access-Control-Allow-Headers: Content-Type, token, authorization, Cookie,
  x-requested-with, Client-Platform, sid, sk, code, redirect_url,
  User-Token, Authorization
```
→ 暴露了自定义认证字段：`sid, sk, code, User-Token`

### API 认证测试结果

```json
// franchise-out.huazhu.com 所有路径返回统一错误
GET /api/anything → {"code":603,"message":"对不起，你没有登录！"}
POST /api/login {} → {"code":603,"message":"对不起，你没有登录！"}

// franchise-cmsapi.huazhu.com actuator 存在但被拦截
GET /actuator → 501 Not Implemented
GET /swagger-resources → 501 Not Implemented
```

## 技术要点总结

1. **crt.sh + huazhu.com 发现内网资产**：向日葵/JIRA/ADFS/SSLVPN 等域名暴露
2. **huazhuidc.com 非标域名**：主站 JS 中引用，非标准 TLD 不受搜索引擎索引
3. **B 端系统安全最薄弱**：franchise/商旅/B2B 系统的安全配置明显弱于主站
4. **腾讯 COS 对象存储多处使用**：campaign/cdn/res-pub 子域名均指向 COS
5. **APISIX 作为统一网关**：hworld/franchise 等系统均使用 APISIX 代理
6. **Guance 观测云 APM**：用于全链路追踪，可泄露内部调用拓扑
