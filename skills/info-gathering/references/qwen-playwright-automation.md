# Qwen (千问) Playwright Browser Automation

Use Playwright to automate Qwen's web UI for free AI vision/text analysis without API keys.

## Setup

```bash
# Install Playwright in Hermes venv
/home/c1ay/.hermes/hermes-agent/venv/bin/pip install playwright
/home/c1ay/.hermes/hermes-agent/venv/bin/python3 -m playwright install chromium
```

This uses the existing Chromium in `~/.cache/ms-playwright/`.

## Basic Text Chat

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    ctx = browser.new_context(
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    )
    page = ctx.new_page()
    page.goto('https://www.qianwen.com/chat', wait_until='domcontentloaded', timeout=30000)
    page.wait_for_timeout(5000)

    # Remove login modal
    page.evaluate('''() => {
        const m = document.querySelector('[role="alert-biz-modal"]');
        if (m) m.remove();
        document.body.style.overflow = 'auto';
    }''')

    # Send message
    input_area = page.locator('[contenteditable="true"]')
    input_area.click()
    input_area.fill('你的问题')
    page.keyboard.press('Enter')

    # Wait for response
    page.wait_for_timeout(20000)

    # Extract response text (last answer block)
    text = page.evaluate('() => document.body.innerText')
```

## Image Upload (showOpenFilePicker override)

Qwen uses `showOpenFilePicker()` (File System Access API), not `<input type="file">`. Playwright can't intercept this natively — override it:

```python
with open('/path/to/image.jpg', 'rb') as f:
    img_b64 = base64.b64encode(f.read()).decode()

page.add_init_script(f'''() => {{
    const IMG_B64 = "{img_b64}";
    window.showOpenFilePicker = function() {{
        return new Promise((resolve) => {{
            const bc = atob(IMG_B64);
            const ba = [];
            for (let o = 0; o < bc.length; o += 512) {{
                ba.push(new Uint8Array([...bc.slice(o, o + 512)].map(c => c.charCodeAt(0))));
            }}
            const blob = new Blob(ba, {{type: 'image/jpeg'}});
            const file = new File([blob], 'image.jpg', {{type: 'image/jpeg'}});
            resolve([{{kind: 'file', name: 'image.jpg', getFile: async () => file}}]);
        }});
    }};
}}''')
```

Then trigger upload via UI:
```python
# Click attachment button
page.locator('button[aria-label="添加附件"]').click()
page.wait_for_timeout(500)

# Click "上传图片" menu item
page.evaluate('''() => {
    const items = document.querySelectorAll('[role="menuitem"]');
    for (const item of items) {
        if (item.textContent.includes('上传图片')) { item.click(); return; }
    }
}''')
```

## Login via QR Code

Image upload requires authentication. To let user scan a QR code:

```python
# Click login button
page.locator('button:has-text("登录")').first.click(force=True)
page.wait_for_timeout(5000)

# Screenshot the QR code area
qr_element = page.locator('[class*="StyledQRCodeWrapper"]')
qr_element.screenshot(path='/tmp/qwen_qrcode.png')

# Send to user via Feishu
# MEDIA:/tmp/qwen_qrcode.png
```

The login modal has these parts:
- Left: iframe (`passport.qianwen.com`) — phone login
- Right: QR code in `StyledQRCodeWrapper` div
- Login flow goes through `passport.qianwen.com/havanaone/login`

## Known Limitations

| Issue | Root Cause |
|-------|-----------|
| Image upload fails silently in headless | Qwen requires auth for CDN upload; `showOpenFilePicker` mock provides file but upload API call lacks auth cookies |
| Login QR code modal blocks clicks | Use `force=True` on clicks, or remove modal via `page.evaluate` |
| Input blocked by modal overlay | `<path fill="#FFFFFF">` from `role="alert-biz-modal"` subtree intercepts pointer events |
| Send button may be hidden | Fallback: `page.keyboard.press('Enter')` |

## UI Element Reference

| Element | Selector |
|---------|----------|
| Chat input | `[contenteditable="true"]` |
| Attach button | `button[aria-label="添加附件"]` |
| Menu: 上传图片 | `[role="menuitem"]:has-text("上传图片")` |
| Menu: 上传文档 | `[role="menuitem"]:has-text("上传文档")` |
| Send button | `button[aria-label="发送消息"]` |
| Login button | `button:has-text("登录")` |
| QR code area | `[class*="StyledQRCodeWrapper"]` |
| Login close icon | `[class*="StyledCloseIcon"]` |
| Response text | `[class*="message-select-content"]` or fallback to `document.body.innerText` |

## API Endpoints (discovered)

```
chat2-api.qianwen.com  — main chat API (v1/v2)
passport.qianwen.com   — login (Havana SSO)
api.qianwen.com        — account/QR code status
aide.qianwen.com       — config query
cms-sdk-server.qianwen.com — CMS config
```
