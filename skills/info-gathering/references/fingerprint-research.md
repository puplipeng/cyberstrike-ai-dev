# Web 指纹识别研究笔记

## 参考项目

| 项目 | Stars | 核心思路 |
|------|-------|---------|
| [TideSec/TideFinger](https://github.com/TideSec/TideFinger) | 2074 | SQLite 指纹库，header/body/title 三维度匹配，支持 `&&`（与）和 `||`（或）组合 |
| [EASY233/Finger](https://github.com/EASY233/Finger) | 1721 | 红队资产存活探测 + 指纹识别，结合 cdn 检测 |
| [urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) | 6620 | Ruby 生态，插件化架构，最全指纹库之一 |
| [b1ackc4t/14Finger](https://github.com/b1ackc4t/14Finger) | 399 | Vue3+Django 平台，集成 rad 爬虫，10000+ 指纹 |
| [wappalyzer/wappalyzer](https://github.com/wappalyzer/wappalyzer) | — | 浏览器插件，JSON 指纹库，TideFinger 的 technologies.json 来源 |

## TideFinger 指纹匹配逻辑 (核心参考)

TideFinger 用 SQLite 存储指纹规则，每条规则格式：

```
title="关键词"     — 匹配 <title> 标签
header="关键词"    — 匹配响应头
body="关键词"      — 匹配响应体
```

组合逻辑：
- `规则1||规则2||规则3` — 任一匹配即命中
- `规则1&&规则2&&规则3` — 全部匹配才命中
- `规则1||(规则2&&规则3)` — 嵌套组合

我们 `web_fingerprint.py` 的 `match_rules` 数组沿用了 OR 逻辑（任一规则匹配即命中），`probes` 则是独立的路径探测。

## 指纹检测维度

| 维度 | 检测内容 | 典型示例 |
|------|---------|---------|
| **Header** | `Server`, `X-Powered-By`, `Set-Cookie` | `Server: Apache-Coyote` → Tomcat |
| **Body** | HTML 内容、错误页面、特定关键词 | `Whitelabel Error Page` → Spring Boot |
| **Cookie** | 会话 Cookie 名称 | `JSESSIONID` → Java, `laravel_session` → Laravel |
| **路径探测** | 访问特定路径看返回内容 | `/actuator` → Spring Boot Actuator |

## 路径探测的关键陷阱

1. **404 页面会匹配宽泛 pattern**：如 `/nacos/` 返回 404 但 body 含 "Nacos"（某个通用错误页），导致误报
   - **解决方案**：只对 HTTP 2xx 响应做 body/header 匹配，4xx/5xx 跳过
2. **通用框架的响应包含大量应用名**：百度等大站的错误页可能包含 "thinkphp"、"用友" 等字符串（被引用/提及）
   - **解决方案**：pattern 要足够具体，如 `致远软件` 而非 `致远`
3. **`A8`、`NC` 等短字符串极容易误匹配**
   - **解决方案**：加上下文限定，如 `A8\+.*?协同` 而非 `A8\+?`

## 中国常见 OA/ERP/中间件指纹速查

| 目标 | 特征字符串 | 敏感路径 |
|------|-----------|---------|
| 通达 OA | `通达`, `tongda`, `MYOA` | `/login/`, `/ispirit/` |
| 泛微 OA | `泛微`, `weaver`, `e-cology` | `/eoffice/`, `/e-cology/` |
| 致远 OA | `致远软件`, `Seeyon.*?OA` | `/seeyon/` |
| 用友 | `用友网络`, `yonyou` | — |
| 金蝶 | `金蝶`, `kingdee` | — |
| 宝塔面板 | `宝塔面板`, `BT-Panel` | `/login` |
| 齐治堡垒机 | `shterm`, `齐治`, `堡垒机` | `/api/virtual/role` |
| JumpServer | `JumpServer`, `jumpserver` | — |

## 指纹规则验证流程（实测经验）

新增或修改指纹规则后，必须用**已知干净站点**验证误报率：

```bash
# 用百度等大型站点测试 — 这些站点不应该匹配任何指纹
python3 scripts/web_fingerprint.py https://www.baidu.com -v --timeout 5

# 期望结果：0 个匹配
# 如果出现匹配，说明 pattern 太宽泛，需要收紧
```

**调试迭代流程：**

1. 运行测试 → 发现误报（如百度匹配到 "致远 OA"）
2. 用 `curl -s https://www.baidu.com | grep -oi "pattern"` 确认是哪个字符串命中
3. 收紧 pattern：加上下文限定词（如 `致远` → `致远软件`，`A8` → `A8\+.*?协同`）
4. 对路径探测类规则，确认已加 `status_code >= 400` 跳过逻辑
5. 重新测试直到干净站点零匹配

**常见误报模式：**

| 误报原因 | 示例 | 修复方法 |
|----------|------|---------|
| 短字符串匹配 | `A8` 匹配到页面中的 `A8` 标签 | 加上下文：`A8\+.*?协同` |
| 通用词匹配 | `致远` 匹配到任何含 "致远" 的页面 | 用专有名词：`致远软件` |
| 404页面内容 | 探测路径返回404但body含关键词 | 过滤 status >= 400 的响应 |
| 通用错误页 | 大站错误页包含各种框架名 | 组合多个条件（AND逻辑） |

## 扩展指纹库的建议

后续新增指纹时，建议从以下来源补充：
- `TideSec/TideFinger/python3/cms_finger.db` — SQLite 格式，500+ 国内 CMS 指纹
- `wappalyzer/wappalyzer` 的 `technologies.json` — 覆盖主流国际技术栈
- `14Finger` 内置的 10000+ 指纹（需通过 Django 管理界面导出）
