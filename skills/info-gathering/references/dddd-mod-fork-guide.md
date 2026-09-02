# dddd 二开指南：国产企业资产增强

dddd (SleepingBag945/dddd) 是一个 Go 编写的批量信息收集与漏洞扫描工具。本仓库 `~/dddd-mod/` 是其二开分支，新增国产企业资产发现能力。

## 架构总览

```
main() → common.Flag() → workflow()
  ├── searchEngine()          ─── Quake 搜索（新版 common/quake 模块）
  ├── GetSubDomain()
  ├── cdn.CheckCDNs()
  ├── 端口扫描                 ─── 补充国产非标端口
  ├── 服务识别 (gonmap)
  ├── httpx HTTPx              ─── 插入 JS 逆向分析
  ├── HostBindCheck
  ├── 目录爆破                 ─── 补充国产系统路径
  ├── ddfinger + cnasset 指纹   ─── 22 个国产系统指纹
  ├── CallNuclei()
  ├── GoPocsDispatcher()
  └── report
```

## 新增模块

| 模块 | 目录 | 功能 |
|------|------|------|
| Quake 搜索 | `common/quake/quake.go` | API 封装，支持 Search/SearchByDomain/SearchByOrg/SearchByICP |
| JS 逆向 | `common/jsrecon/jsrecon.go` | config.js/__NEXT_DATA__/RSA 密钥/隐藏 URL 提取 |
| 国产资产 | `common/cnassets/assets.go` | 17 个非标端口 + 22 条国产路径 + 指纹 |
| 国产指纹 | `common/cnassets/fingerprints.go` | 22 个国产系统指纹规则（OA/ERP/中间件/DevOps） |

## 新增 CLI 参数

```bash
--jsrecon        启用 JS 逆向分析
--cnasset        启用国产资产增强（端口+路径+指纹）
--quake-key      指定 Quake API Key
```

## 指纹来源

- `0x727/FingerprintHub` (⭐1,410) — 3183 条 Web 指纹，提取 202 条国产相关
- `TideSec/TideFinger` (⭐2,075) — 指纹识别工具

## 国产系统指纹覆盖

| 类别 | 系统 |
|------|------|
| OA | 致远、泛微、通达、蓝凌、万户、华途 |
| ERP | 用友、金蝶、明源云 |
| 报表 | 帆软 FineReport/FineBI |
| 配置中心 | Nacos、Druid、Swagger、Spring Boot Actuator |
| 安全 | JumpServer、齐治堡垒机 |
| DevOps | Jenkins、GitLab、Confluence、Jira |
| 框架 | Apache Shiro |

## 编译

```bash
cd ~/dddd-mod && go build -o dddd .
```

## 使用

```bash
# 全套流程
./dddd -t target.com --quake --qk "KEY" --jsrecon --cnasset

# 单独的国产系统探测
./dddd -t 47.96.122.15 --cnasset

# Quake 搜集团资产
./dddd -t "org:浙能" --quake --qk "KEY"
```
