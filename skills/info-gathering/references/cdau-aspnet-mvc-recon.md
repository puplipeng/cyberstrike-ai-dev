# 成都艺术职业大学 — 信息收集案例

> ASP.NET MVC 站点 + 腾讯企业邮 + 咏沃建站

**目标：** 成都艺术职业大学
**主域：** `cdau.edu.cn`
**旧域：** `cdartpro.cn`
**主 IP：** `125.71.233.152`

## 发现流程

### 1. 域名发现

Bing 搜索 `成都艺术职业大学 官网` 找到主域 `cdau.edu.cn`（学校的缩写是 **C**heng**d**u **A**rt **U**niversity）。

**注意：不要想当然猜域名缩写。** 此学校简称是 `cdau`（Art+University）而非 `cdart` 或 `cdyszy`。多个历史域名（`cdyszyjsxy.edu.cn`、`cdyszy.edu.cn`、`cdartpro.edu.cn`）都 502 不可达，仅 `cdau.edu.cn` 和 `cdartpro.cn` 有实际内容。

### 2. 测绘平台受阻

crt.sh 因网络环境返回 502 Bad Gateway（直接和走代理都失败），无法通过证书透明度日志查子域名。需用 Bing/Baidu 搜索补充。

Quake 查询因代理/网络环境未成功返回（代理出口 TCP 超时），需在直连或不同代理出口下重试。

### 3. ASP.NET MVC 指纹

- **Server:** nginx（前端代理）
- **框架:** ASP.NET MVC 5.2（`X-AspNetMvc-Version: 5.2` 响应头）
- **会话:** `ASP.NET_SessionId`（HttpOnly）+ 自定义 `server_session_39707597`
- **jQuery 3.7.1**

### 4. Catch-All 路由陷阱

此站点采用了 ASP.NET MVC Areas 架构，所有未匹配路径都返回 **200 OK + 空响应体**。不能通过 HTTP 状态码判断路径是否存在，必须对比响应体内容或大小：

```
/admin → 200 (空)
/.env  → 200 (空)
/swagger → 200 (空)
/web.config → 200 (空)
```

**正确方法：** 只关注已知工作路由模式 `/Article/View?id=N`、`/Article/List?id=N`、`/Article/Indexes?id=N`，从首页 HTML 提取实际使用的路径。

### 5. IDOR 风险

`/Article/View?id=N` 接受连续数字 ID（1~22532+ 均返回 200），可批量遍历文章内容。ASP.NET MVC 的 Route Attribute 未做严格的 ID 范围限制。

### 6. 其他暴露面

| 项目 | 详情 |
|------|------|
| 文件存储 | `/Files/upload/Webs/Media/Data/PC1/` 直链可访问 |
| 建站开发商 | 咏沃技术（`yongwo.com.cn`） |
| 邮件 | 腾讯企业邮 |
| 旧站 | `old.cdartpro.cn` 已下线（502） |
| 第三方集成 | 中国教育在线 school_id=48009 |

## 关键教训

1. **中国高校站缩写无规律** — 不要按常识猜，直接 Bing/Baidu 搜
2. **ASP.NET MVC Areas 架构** — 有 Areas 的站点通常 `/Article` 路由为主内容入口，需要从首页 HTML 提取控制器名
3. **Catch-all 路由掩盖状态码** — 必须读响应体内容，不能只看 HTTP 状态码
4. **crt.sh 不可用时** — Bing `site:domain 官网` + DNS A 记录查询 + ICP 备案查询（在页脚）作为被动收集的替代方案
5. **文件路径结构暴露** — `/Areas/Home/Views/Home/PC/1/` 这种路径结构直接暴露了 MVC 的 Area 名称和视图层次
