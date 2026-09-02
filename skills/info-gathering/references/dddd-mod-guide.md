# dddd-mod 二开指南

## 概述

基于 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) (⭐1.9k) 二开，增强国产企业资产发现能力。全部代码在 `~/dddd-mod/`。

## 新增模块

| 模块 | 路径 | 功能 |
|------|------|------|
| Quake 搜索 | `pkg/quake/quake.go` | 自写 Quake API 模块，带回 title/server/org |
| JS 逆向 | `common/jsrecon/jsrecon.go` | config.js/__NEXT_DATA__/RSA公钥/加密方法(9类27指纹) |
| 国产资产 | `common/cnassets/` | 17非标端口 + 22国产路径 + 22系统指纹 + 国产数据库 |
| WAF 检测 | `pkg/waf/bypass.go` | 8类WAF指纹识别 + 绕过建议 |
| 扫描模式 | `internal/scan/options.go` | light/normal/full 三级控制 + dry-run + explain |

## dddd 架构必需遵循的规范

### PluginList 注册制（gopocs）

```go
// gopocs/base.go
var PluginList = map[string]interface{}{
    "SSH-Crack":  SshScan,
    "Redis-Crack": RedisScan,
    // 新增协议：加一行注册
}
```

函数签名固定：`func(info *structs.HostInfo)`

### 全局配置（structs/type.go）

所有配置集中在 `structs.GlobalConfig`，通过 `common.Flag()` 解析 CLI 参数：

```go
// 加新参数只需两步：
// 1. structs/type.go 加字段
// 2. common/flag.go 注册 flagSet.BoolVar/IntVar/StringVar
```

### 协程控制（gopocs/scanner.go）

`AddScan()` 统一管理 chan + WaitGroup，固定 `GoPocThreads` 并发数。

## 国产资产增强要点

### 非标端口（17个）

```
9090 OA/明源ERP    9060 明源PubPlatform  50780 数据中心
19051 健康检查      9010/9070 内部RPC     9000/7213 阿里云
8089/8443/8008/8888 备用Web              5555/11211/27017/6379
```

### 国产系统指纹（22个）

OA: 致远/泛微/通达/蓝凌/万户/华途
ERP: 用友/金蝶/明源云
报表: 帆软FineReport/FineBI
配置: Nacos/Druid/Swagger/Spring Actuator
DevOps: Jenkins/GitLab/Confluence/Jira
安全: JumpServer/齐治堡垒机
框架: Apache Shiro (rememberMe)

### 国产数据库/中间件

达梦(5236)、人大金仓(54321)、南大通用(19080)、东方通TongWeb、中创InforSuite、宝兰德BES

## JS 逆向分析能力

| 检测项 | 正则 | 提取内容 |
|--------|------|---------|
| config.js | `window\.g\s*=\s*\{[^}]+\}` | baseUrl/token/appid |
| __NEXT_DATA__ | `<script id=\"__NEXT_DATA__\"` | runtimeConfig 全部字段 |
| RSA公钥 | `-----BEGIN PUBLIC KEY-----` | PEM 公钥 |
| 加密方法 | 27个指纹正则 | RSA/AES/SM2/3/4/MD5/JWT/Base64/XOR/DES |
| 隐藏URL | `https?://[^\"]+` | 过滤CDN/统计后的API端点 |

## WAF 检测

8类WAF指纹 + 置信度评分 + 绕过建议：

```
Cloudflare → 找未走CDN的子域名
阿里云WAF → Chunked编码/Content-Type变换/HPP
安全狗 → 注释混淆/大小写混合/内联注释/Ghost Bits
ModSecurity → 分块传输/编码混淆
长亭SafeLine/腾讯云/百度云/深信服 → 各有专攻
```

## CLI 用法

```bash
# light 模式（默认）：端口+指纹+探活，不触发WAF
./dddd -t target.com --mode light --cnasset

# normal 模式：+ 目录爆破 + JS逆向
./dddd -t target.com --mode normal --cnasset --jsrecon

# full 模式：全量 nuclei + GoPoC
./dddd -t target.com --mode full

# dry-run：只打印执行计划
./dddd -t target.com --mode full --dry-run --explain

# 跳过WAF检测
./dddd -t target.com --skip-waf
```

## 工作流集成点

```
main.go workflow() 的插入顺序：
1. mode.ParseMode → 模式控制
2. WAF检测 (pkg/waf.Detect)
3. searchEngine → Quake搜索 (替换旧 uncover.QuakeSearch)
4. 端口扫描 → cnasset 非标端口补充
5. httpx 探活
6. JS 逆向分析 (common/jsrecon)
7. 目录爆破 → cnasset 国产路径补充
8. 指纹识别 → cnasset 22系统指纹匹配（从缓存读body，零额外请求）
9. nuclei + GoPoC
10. 报告输出
```
