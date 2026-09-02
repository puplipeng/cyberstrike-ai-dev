# ASP.NET MVC 信息收集技术

## 控制器发现：通过 500 错误泄露

ASP.NET MVC 应用使用路由模式 `{controller}/{action}/{id}`。当存在多个同名控制器（不同命名空间）且路由未指定命名空间时，访问 `/ControllerName/ControllerName` 会触发 **500 Internal Server Error**，错误信息会列出所有匹配的控制器。

### 触发方法

```bash
# 访问 /ControllerName/ControllerName
# 返回 500 + "Multiple types were found that match the controller named 'X'"
curl -sk "https://target.com/User/User"
```

### 典型错误响应

```
Multiple types were found that match the controller named 'User'.
This can happen if the route that services this request
('{controller}/{action}/{id}') does not specify namespaces to search
for a controller that matches the request.
The request for 'User' has found the following matching controllers:
Unionsoft.Web.Areas.Sys.Controllers.UserController
Unionsoft.Platform.Web.Areas.Sys.Controllers.UserController
```

**泄露的信息：**
- 框架名称（如 `Unionsoft`、`Unionsoft.Web.Areas.Sys`）
- 命名空间结构（`Areas.Sys.Controllers.UserController`）
- 控制器完整类名
- 路由模式（`{controller}/{action}/{id}`）
- 确认是 ASP.NET MVC（非 WebForms/API）

### 控制器字典

常见 ASP.NET MVC 控制器名用于探测：

```bash
for ctrl in Home Login Account User UserInfo Admin AdminController \
            System Sys Config Setting Profile Report Form Workflow Flow \
            Data File Upload Download Message Notice News Article \
            Role Permission Menu Module Org Organize Department \
            Dictionary Code Category Log Error Test Debug Help \
            About Contact; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/${ctrl}/${ctrl}")
  [ "$code" = "500" ] && echo "⚠️  500 ${ctrl}/${ctrl} — 控制器存在"
done
```

### 动作方法（Action）发现

控制器存在后，尝试常见的动作方法名：

```bash
# 数据接口
for action in GetList GetData GetPage List Index Page Search Query; do
  curl -sk -o /dev/null -w "%{http_code}" "https://target.com/User/${action}"
done

# CRUD
for action in Create Update Delete Save Add Edit Remove; do
  curl -sk -o /dev/null -w "%{http_code}" "https://target.com/User/${action}"
done
```

返回 500 但非 404 的端点 → 动作方法存在（可能因缺少参数或认证失败）。

### 端点状态码解读

| 状态码 | 含义 | 示例场景 |
|--------|------|----------|
| 200 + 登录页 | URL 匹配路由但需要认证后重定向 | `{controller}/{action}` 匹配成功 |
| 200 + JSON | 免认证数据接口 | `/Flow/Index` 返回 `{"code":500,"info":"View not found"}` |
| 500（路由冲突） | 控制器存在！命名空间冲突 | `/User/User` — 多个 UserController |
| 500（参数缺失） | 动作方法存在，但参数校验失败 | `/User/GetList?page=1` — 需要 model 绑定 |
| 404 | 控制器/动作不存在 | `/Nonexistent/Nonexistent` |
| 403 | 目录浏览禁止 | `/Content/`、`/Scripts/` |
| GET 404, POST 200 | 仅 POST 的端点 | `/Login/CheckLogin` |

### Unionsoft 框架特定端点

Unionsoft（三盟敏捷开发框架 V2018）常用端点模式：

```bash
# 已确认存在的控制器
/User/User           → 500 (多个 UserController)
/Workflow/Workflow   → 500 (Workflow 控制器)
/Flow/Index          → 200 JSON ({"code":500,"view not found", 暴露框架版本)

# 已确认存在的数据接口
/User/GetList        → 500 (需要参数)
/User/GetData        → 500 (需要 keyValue 参数)
/User/GetUserInfo    → 500

# 登录端点
/Login/CheckLogin    → POST 400 (CSRF token + username + password)
/Login/VerifyCode    → 验证码图片

# 其他
/Home/Index          → 登录后首页
/Error/ErrorBrowser  → 浏览器兼容性提示页
```

### ASP.NET 特性速查

| 特性 | 检测方法 |
|------|----------|
| CSRF Token | `__RequestVerificationToken` hidden input，绑定到 session |
| ViewState | `__VIEWSTATE` hidden input（WebForms 特征） |
| IIS 版本 | 404.8 错误页显示 IIS 版本号 |
| 路由模式 | 500 错误消息泄露 `{controller}/{action}/{id}` |
| MVC Area | 500 错误显示 `Areas.Sys.Controllers`（区域化路由） |
| 密码算法 | 前端 JS 中的 hash 函数（如 MD5 双传明文+哈希） |
| 验证码策略 | `errornum` hidden input — 失败 N 次后显示 |

### 登录端点分析要点

```bash
# 1. 获取 CSRF Token
TOKEN=$(curl -sk "https://target.com/" | grep -oP '__RequestVerificationToken.*?value="\K[^"]+')

# 2. 分析请求参数
# 前端 JS 中查找 login() 函数
curl -sk "https://target.com/" | grep -oP 'url:[^,]+|data:\{[^}]+\}'
# 典型参数: username, password (MD5), verifycode, p (明文)

# 3. 判断账户是否存在（用户枚举）
# "密码和账户名不匹配!" → 账户存在
# "账户不存在!" → 账户不存在（或 SQL 注入被拦截）
curl -sk -X POST -d "username=target_user&password=hash&p=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "__RequestVerificationToken: $TOKEN" \
  "https://target.com/Login/CheckLogin"

# 4. 确认参数化查询（无 SQL 注入）
# SQL 注入 payload 返回 "账户不存在!" → 输入被参数化，非拼接
# 无时间延迟 → 非时间盲注
```

### Pitfalls

1. **所有路径返回 200（登录页）** — ASP.NET MVC 默认路由会捕获所有合法路径并返回登录页。用响应体大小区分：登录页 3-5KB，未授权 JSON 接口 < 1KB
2. **GET 404 ≠ 端点不存在** — 某些端点仅接受 POST。先用 POST 确认
3. **500 错误可能被 IIS 自定义错误页覆盖** — 生产环境 `customErrors mode="On"` 会显示通用错误页而非详细错误
4. **Google 搜索不支持中文 URL** — 中文关键词需 URL 编码或用英文替代搜索
5. **nginx 反代掩盖后端** — 前端 nginx 可能隐藏了后端 IIS/ASP.NET 版本头。`/web.config` → IIS 7.5 404.8 错误可暴露 IIS 版本
