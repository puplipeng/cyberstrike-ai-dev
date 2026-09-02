# Vue SPA 认证流分析（实战方法论）

## 概述

分析 Vue.js/React SPA 的认证流，找出 API 端点、token 获取方式、路由守卫和认证绕过漏洞。适用场景：单主机多端口部署（如安防/门禁/人脸识别系统），每个端口独立 SPA + 独立后端。

## 分析流程

### 阶段 1：静态文件侦察

```bash
# 1. 读取 config.js（根目录常见位置）
curl -sk https://target:port/config.js
# 典型内容：
# window.g = {
#   baseUrl: window.location.origin + "/api/",
#   apiKey: "xxx",          # 可能硬编码
#   secret: "yyy"           # 可能硬编码
# }

# 2. 从 index.html 发现 JS 文件
curl -sk https://target:port/ | grep -oP 'src="[^"]*\.js"' | head -20
# 主要关注: app.js（主应用）, chunk-vendors.js（第三方库）

# 3. 下载 app.js
curl -sk https://target:port/static/js/app.xxx.js -o app.js
```

### 阶段 2：认证流逆向

#### 2.1 查找 HTTP 库配置（axios 实例）

搜索 `baseURL` + `create` + `interceptors`：

```bash
grep -oP '.{0,100}(baseURL|create|interceptors|withCredentials).{0,100}' app.js
```

```javascript
// 关键配置：baseURL + withCredentials
var Z = window.g.baseUrl + "visitor",  // API 基础路径
ee = W.a.create({
  baseURL: Z,                          // → https://target/bio_platform/visitor
  timeout: 30000,
  withCredentials: true                 // 发送 Cookies
});
```

**`withCredentials: true` 意味着 API 请求带 Cookies（如 CAS 的 JSESSIONID）。** 测试时务必使用 cookie jar 维持会话。

#### 2.2 查找 request/response interceptors

```bash
# request interceptor → 添加 token/Content-Type 等 headers
grep -oP '.{0,200}interceptors.request.{0,200}' app.js
```

```javascript
// Interceptor 1: 添加 Content-Type
ee.interceptors.request.use(function(e) {
  return e.headers["Content-Type"] = "application/json", e
});

// Interceptor 2: 从 sessionStorage 读取 token 添加为 header
ee.interceptors.request.use(function(e) {
  var n = sessionStorage.getItem("collect_token");
  return e.headers["token"] = n, e
});
```

**关键发现：token 存储在 `sessionStorage`，key 名可能是 `collect_token`、`token`、`access_token` 等。**

```bash
# response interceptor → 统一错误处理
grep -oP '.{0,200}interceptors.response.{0,200}' app.js
```

```javascript
ee.interceptors.response.use(function(e) {
  var n = e.data;
  return 200 !== n.code && 0 !== n.code && ... && n.code
    ? Promise.reject(new Error(...))
    : n  // 返回完整 response body，不是 n.data
});
```

注意：interceptor 返回的是整个 `e.data`（即 `{code:200, data:"xxx", msg:"ok"}`），**不是 `.data` 字段**。组件中拿到的是完整 JSON 对象，然后提取 `r.code` 判断。

#### 2.3 查找辅助函数

```bash
grep -oP 'axiosUrl|axiosParams|axiosData|axiosArrData' app.js
```

```javascript
ee.axiosUrl = function(e) { return e };  // URL 原样返回（相对于 baseURL）
ee.axiosParams = function(params, addTimestamp=true) {
  // 自动添加时间戳参数 t=(new Date).getTime()
  return addTimestamp ? { t: Date.now(), ...params } : params
};
ee.axiosData = function(data, addTimestamp=true, format="json") {
  // 自动添加时间戳，JSON.stringify
};
```

### 阶段 3：Vue Router 路由表与守卫

#### 3.1 提取路由表

```bash
grep -oP 'path:"[^"]+",name:"[^"]+",component' app.js | head -30
# 或
grep -oP 'path:"/[^"]*"' app.js
```

输出示例：
```
path:"/",name:"index"              →  requireAuth:false  (首页/登录页)
path:"/visitor/cas",name:"..."     →  requireAuth:false  (CAS回调)
path:"/Visitor",name:"..."         →  requireAuth:false  (公开页)
path:"/home",name:"Home"           →  requireAuth:true   (需认证)
path:"/identity",name:"Identity"   →  requireAuth:true   (身份选择)
path:"/student",name:"Student"     →  requireAuth:true   (学生页面)
```

#### 3.2 分析路由守卫（beforeEach）

```bash
grep -oP '.{0,200}beforeEach.{0,200}' app.js
```

```javascript
K.beforeEach(function(e, n, t) {
  e.meta.requireAuth, t()  // 读取 requireAuth 但不检查！
});
```

**常见陷阱：** Vue Router 的 `beforeEach` 可能声明式读取 `requireAuth` 但不做实际跳转。此时 `requireAuth:true` 只是标记，不阻止页面渲染——认证完全依赖后端 API 校验。

#### 3.3 Vuex Store 状态检查

```bash
grep -oP 'new [\w.]+Store[\s\S]{0,500}' app.js
```

```javascript
var store = new Vuex.Store({
  state: {
    staffId: window.localStorage.getItem("staffId")  // 从 localStorage 读取
  }
});
```

**发现 localStorage 中的 `staffId` 但未找到 `setItem("staffId")` → staffId 可能在服务端渲染时设置，或由特定登录流程写入。**

### 阶段 4：Chunk 组件分析

#### 4.1 找出懒加载 Chunk

```bash
# 从 app.js 提取 chunk 映射
grep -oP 'chunk-[a-f0-9]+' app.js | sort -u
```

每个 chunk 对应一个 Vue 组件。关键分析目标：
- **`requireAuth:false` 的组件** — 可能包含免认证 API 调用
- **根路径组件（`"/"` → chunk-xxx）** — 通常包含 getStaticToken 等初始化调用
- **含 login/auth 关键词的 chunk** — 认证逻辑

#### 4.2 组件反混淆 - 查找 API 调用

Chunk 中的典型认证调用模式：

```javascript
// 查找 axiosUrl 包裹的 URL 路径
grep -oP 'axiosUrl\("[^"]*"' chunk-xxx.js
// 或直接搜索 http 调用
grep -oP '{url:\s*"[^"]*"' chunk-xxx.js
```

#### 4.3 示例：从根组件发现认证机制

根组件（`/visitor/cas` 或 `index`）常包含初始化逻辑：

```javascript
// chunk-xxx.js 中的 init 函数
methods: { init: function() {
  var request = {
    url: window.g.baseUrl + "bio_auth/authen/getStaticToken",
    method: "post",
    data: {
      apiKey: "4dabbc214dc088a5b1ddabc131b07375",
      secret: "fefb6073d3daecab10fa741206f88ed7"
    }
  };
  // 发送请求
  var response = await this.$http(request);
  if (200 == response.code) {
    sessionStorage.setItem("collect_token", response.data);
  }
}}
```

**认证流程：** `getStaticToken` → 系统级 JWT → 存 `collect_token` → 后续 API 在 header 中自动携带。

### 阶段 5：API 路径探测

#### 5.1 从所有 chunk 提取 URL 模式

```bash
# 搜索 URL 路径
for f in chunk-*.js; do
  grep -oP '"[a-z_]+/[a-z_]+/[a-z_/]+"' "$f" | grep -viE '(static|chunk|css|img|font|routerlink)' | sort -u
done
```

#### 5.2 系统化的端点测试

```python
# 全面测试框架
base = "https://target/bio_platform/visitor"
endpoints = [
    # 找到的 API
    "/visitor_mobile/visitor/info/{id}",
    "/visitor_mobile/visitor/list",
    "/visitor_mobile/img/pic?visitorId={id}",
    "/pass/door/innerinfo",
    "/phone/student/applyDoorList",
    # 可能的认证端点
    "/bio_auth/authen/getStaticToken",
    "/bio_auth/authen/refresh",
    "/bio_auth/authen/login",
]
# 测试系统 token —— 区分 "invalid token" vs "token失效"
# "invalid token" = token 格式错误或缺失
# "token失效" = token 格式正确但权限不够
```

### 阶段 6：认证 bypass 测试

#### 6.1 Token 传递方式枚举

```python
# 系统 token 可能通过以下方式传递
methods = [
    ("header", "token"),
    ("header", "Authorization", "Bearer {token}"),
    ("cookie", "token={token}"),
    ("query", "?token={token}"),
]
```

#### 6.2 错误信息分析

| 返回信息 | 含义 |
|----------|------|
| `"invalid token"` | token header 缺失或格式错误 |
| `"token失效，请重新登录"` | token 格式正确但权限不足/已过期 |
| `HTTP 405 Not Allowed` | 端点存在但方法不对 |
| `HTTP 404` (纯文本 nginx) | 端点不存在 |
| Vue SPA HTML (4419+ bytes) | SPA fallback — 非真实 API |

## 典型发现模式

### 模式 1：双 token 系统

系统级 token（getStaticToken）用于识别应用身份，用户级 token（CAS 回调后获取）用于识别用户身份。API 按 token 类型分级授权：

| token 类型 | 可访问范围 |
|-----------|-----------|
| 系统级 JWT (iss:rongbang) | 基础只读 API，data 为空 |
| 用户级 token（含 staffId） | 全功能 API |

### 模式 2：CAS + 自建认证混合

部分端口使用 CAS SSO，部分使用自建 token 系统。同一主机不同端口可能：
- 共享 CAS 认证（同一 session cookie）
- 各自独立认证（不同的 token 体系）
- CAS 只作为用户身份绑定，业务授权在各自后端

### 模式 3：Vue Router 路由标记未强制执行

`requireAuth:true` 在 `beforeEach` 守卫中被读取但不检查——认证完全依赖后端 API 的 HTTP 401 响应。前端不阻止页面渲染，仅 API 调用失败时显示错误。

## 工具链

```bash
# Chrome DevTools Protocol 远程调试（可选）
# 1. 启动 headless chrome
google-chrome --headless --remote-debugging-port=9222
# 2. 访问页面后获取 token
curl -s http://localhost:9222/json/activate | python3 -c "
import sys,json
d=json.load(sys.stdin)
# 通过 CDP 执行 JS 获取 sessionStorage
"

# 或直接用 curl + cookie jar 模拟
COOKIES=/tmp/cookies.txt
curl -sk -c $COOKIES -b $COOKIES https://target.com/
```
