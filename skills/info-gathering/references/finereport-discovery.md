# FineReport/ReportServer 发现指南

> 关联 skill: `info-gathering` (指纹识别)
> 系统：帆软报表（FineReport），中国高校和政府常见 BI/报表系统

## 核心特征

```bash
# 检测方式
curl -s "http://target.com/ReportServer"
# 响应 HTML 特征：
# - <meta name="author" content="FineReport" />
# - <meta name="Copyright" content="FineReport" />
# - <link href="...ReportServer?op=resource&resource=/com/fr/web/core/css/..."/>
```

## 常用路径

| 路径 | 用途 | 需认证 |
|------|------|--------|
| `/ReportServer` | 部署成功页（确认安装） | ❌ 公开 |
| `/ReportServer?op=fs` | 决策系统（FineDecision）- BI 前端 | ✅ 需登录 |
| `/ReportServer?op=resource` | 静态资源（CSS/JS 文件） | ❌ 公开 |
| `/ReportServer?op=fr_console` | 控制台（管理员） | ✅ 需管理员 |
| `/ReportServer?op=designer` | 设计器 | ❌（返回 Unresolvable） |
| `/ReportServer?op=login` | 登录 | ❌（返回 Unresolvable） |

## 子路径模式

FineReport 通常部署在以下路径下（在不同系统中路径不同）：

```bash
# 常见前缀
/datawarn/ReportServer        # 数据分析平台
/ReportServer                 # 单独部署
/WebReport/ReportServer       # 老版本 WebReport
```

## 帆软历史漏洞

| CVE/漏洞 | 影响版本 | 说明 |
|---------|---------|------|
| 任意文件读取 | ≤ 10.0 | `?op=resource&resource=../../WEB-INF/web.xml` |
| SQL 注入 | 多版本 | `ReportServer?op=fs_load&cmd=...` |
| 未授权 RCE | ≤ 11.0 | 通过 `op=fr_console&cmd=...` |
| 权限绕过 | 部分版本 | 决策系统未授权访问 |

## 注意

- FineReport 的 `op=resource` 路径可以用于确认版本号（`deploySuccess.css` 内容）
- ReportServer 容易被 WAF 限速，建议降低请求频率
- 部分部署会重定向到 HTTPS，需要跟随
