# WeChat 公众号文章内容提取

## 问题

微信公众号文章使用 JS 动态渲染（Vite-built SPA），静态 HTML 不包含正文。直接 curl 访问被微信反爬系统拦截（"环境异常" + 验证码），browser 工具 60s 超时也无法完成渲染。

## 解决步骤

### 1. 绕过反爬

```bash
# ❌ 默认 UA 被拦截
curl -sL "https://mp.weixin.qq.com/s/ARTICLE_ID"

# ✅ iPhone MicroMessenger UA 绕过验证
curl -sL \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.47" \
  -H "Referer: https://mp.weixin.qq.com/" \
  "https://mp.weixin.qq.com/s/ARTICLE_ID" -o /tmp/wx_page.html
```

### 2. 提取标题 + 正文（从 meta 标签）

文章正文由 JS 渲染，不在静态 HTML 中。但微信为社交分享预览，在 `<meta>` 标签中嵌入了完整的 `og:description` 和 `description`，包含全文：

```python
import re, html

with open('/tmp/wx_page.html', 'r', encoding='utf-8', errors='ignore') as f:
    data = f.read()

# 提取 og:title（文章标题）
title_m = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', data)
title = title_m.group(1) if title_m else ''

# 提取 og:description（全文）
desc_m = re.search(r'<meta\s+property="og:description"\s+content="([^"]*)"', data)
content = desc_m.group(1) if desc_m else ''

# 美化输出
content = html.unescape(content)
content = content.replace('\\x0a', '\n')  # 微信用 \x0a 表示换行
```

### 3. 提取公众号信息（从 JS 变量）

```python
nick_m = re.search(r'var msg_nickname\s*=\s*["\']([^"\']+)["\']', data)
nick = nick_m.group(1) if nick_m else ''

account_m = re.search(r'var msg_username\s*=\s*["\']([^"\']+)["\']', data)
account = account_m.group(1) if account_m else ''

biz_m = re.search(r'var msg_biz\s*=\s*["\']([^"\']+)["\']', data)
biz = biz_m.group(1) if biz_m else ''

ts_m = re.search(r"var msg_create_at\s*=\s*['\"]([^'\"]+)['\"]", data)
ts = ts_m.group(1) if ts_m else ''
```

## 局限

- **图片不可提取** — og:description 仅含文本，文章内图片需 JS 渲染
- **长文可能截断** — og:description 有长度限制（约 500 中文字符）
- **JS 渲染内容丢失** — 投票/小程序/交互组件不包含在 meta 中
- **browser 工具超时** — WeChat JS 渲染 >60s，必须用 curl + meta 提取
- **付费/受限文章** og:description 可能为空

## 参考会话

2026-07-16: 用户发来微信文章链接 `mp.weixin.qq.com/s/WjYPvcwYesW3sQU9lDhc2w`，
标题「🚨 卧槽！本地模型时代真的要来了！」，通过上述方法成功提取全文。
