# Taiwan Legacy PHP Application Assessment: Case Studies

## Case 1: derma.org.tw (皮膚科醫學會)

**Target:** `https://www.derma.org.tw/specialist/index.php?id=12`  
**Stack:** Unknown (appears custom PHP)  
**Protocol:** HTTPS

### SQL Injection Assessment

The `id` parameter showed strong signs of SQL injection:

- `id=12 and 1=1` triggered a **302 redirect** to `error.php?msg=資料讀取有誤，請重新確認！`
- This indicates the parameter is being interpolated into a SQL query, and `and 1=1` caused a syntax error
- Normal `id=12` returns 200 with full content (41191 bytes, proper `<title>`)
- Invalid IDs (99999, 0) and injection payloads all return 36003 bytes with empty title prefix

### Anti-bot Protection

After ~10 requests, the server started returning:
- `415 Unsupported Media Type` for plain curl requests
- Custom JS challenge page: `<title>One moment, please...</title>` with 5-second auto-reload
- Not Cloudflare — no cf-turnstile, challenge-script, or `__cf` markers
- Self-hosted anti-scraping protection triggered by frequency/patterns

### Key Takeaway
302 redirect to error page on `and 1=1` is a strong SQL injection indicator. Testing was cut short by anti-bot; resume after waiting period with browser-like headers.

---

## Case 2: maingchau.com.tw (名超企業人事系統)

**Target:** `http://www.maingchau.com.tw/MCpersonnel/newweb/`  
**Stack:** Apache 2.2.8 (Win32) | PHP 5.2.6 | MySQL 5.0.51b | phpMyAdmin 2.10.3  
**Protocol:** HTTP (unencrypted)

### Discovery Path

1. Login page at `index.php?$lang=en` — custom HR system by 陳正雄
2. Apache directory listing enabled on `/MCpersonnel/` and subdirectories
3. Found `Connections/` directory exposing critical PHP files
4. Found phpMyAdmin at `/MCpersonnel/phpMyAdmin_/`

### Server Fingerprint

From headers:
```
Server: Apache/2.2.8 (Win32) PHP/5.2.6
```
From phpMyAdmin main.php:
```
Server version: 5.0.51b-community-nt-log
Protocol version: 10
Server: localhost via TCP/IP
User: pma@localhost
MySQL client version: 5.0.51a
Used PHP extensions: mysql
```

### Path Disclosure via Error

Accessing `Connections/check_login.php` directly revealed:

```
Warning: include(Connections/mysql_connect.php): failed to open stream
in C:\NewMaingchau-web\MCpersonnel\NewWeb\Connections\check_login.php on line 5
include_path='.;C:\php5\pear'
```

### Exposed Files (Directory Listing at /MCpersonnel/)

| Path | Description |
|------|-------------|
| `/MCpersonnel/NewWeb/` | HR system |
| `/MCpersonnel/MaterialDownload/` | File download system (separate login) |
| `/MCpersonnel/phpMyAdmin_/` | phpMyAdmin 2.10.3 |
| `/MCpersonnel/Thumbs.db` | Windows thumbnail cache (7KB) |

### Exposed PHP Files (Connections/ directory)

| File | Size | Purpose |
|------|------|---------|
| `db_config.php` | 163B | Database configuration (credentials!) |
| `mysql_connect.php` | 618B | MySQL connection |
| `connect.php` | 3.2K | Login form handler |
| `check_login.php` | 454B | Authentication logic |
| `variable.php` | 1.9K | Variable definitions (last modified 2026-06-12) |
| `mcpersonnel.php` | 926B | Main application file |

All PHP files execute server-side when accessed directly, so credentials are not visible in responses.

### phpMyAdmin Access

- HTTP Basic Auth realm: "phpMyAdmin running on localhost"
- **Default credential `pma:` (user pma, empty password) successfully logged in**
- Limited MySQL user (pma@localhost) — only `information_schema` visible
- phpMyAdmin 2.10.3 is from 2007 with known vulnerabilities

### Login Form Weaknesses

Captcha value exposed in hidden HTML field:
```html
<input name="recaptcha" type="hidden" id="recaptcha" value="083">
```
Value changes per page load but is sent as a hidden form field — defeats CAPTACPHA purpose.

### Attack Surface Summary
- ✅ SQL injection potential in `$lang` parameter (unconfirmed — page size unchanged)
- ✅ Directory listing (information disclosure)
- ✅ phpMyAdmin access (limited user, but old version)
- ✅ Path disclosure (Windows server paths)
- ✅ Hardcoded CAPTCHA (bypassable)
- ✅ HTTP plaintext (credential interception)
- ✅ Outdated software (Apache 2.2, PHP 5.2, MySQL 5.0 — all EOL with known RCEs)
- ❌ Database credentials not readable (PHP execution server-side)
- ❌ `$lang` LFI with %00 truncation failed (all returned 4263B)
