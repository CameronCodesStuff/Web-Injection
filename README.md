# Web Injection Attacks: XSS & SQL Injection

A quick reference for understanding and defending against common web injection vulnerabilities.

---

## Cross-Site Scripting (XSS)

XSS occurs when an attacker injects malicious scripts into content that other users view in their browser.

### Types

| Type | Description |
|------|-------------|
| **Reflected** | Payload is in the URL/request and echoed back immediately |
| **Stored** | Payload is saved to the database and served to all visitors |
| **DOM-based** | Payload manipulates the DOM without hitting the server |

### Basic Payloads

```html
<!-- Classic alert test -->
<script>alert('XSS')</script>

<!-- Image onerror trigger -->
<img src="x" onerror="alert('XSS')">

<!-- Event handler injection -->
<input value="" onfocus="alert('XSS')" autofocus>

<!-- href injection -->
<a href="javascript:alert('XSS')">Click me</a>

<!-- SVG vector -->
<svg onload="alert('XSS')"></svg>
```

### Common Injection Points

- Search boxes and form fields
- URL query parameters (`?q=<script>...`)
- Comment sections
- User profile fields (stored XSS)
- HTTP headers reflected in pages (e.g. `User-Agent`, `Referer`)

### Defenses

```html
<!-- 1. Escape output — encode special characters -->
&lt;script&gt;  instead of  <script>

<!-- 2. Content Security Policy header -->
Content-Security-Policy: default-src 'self'; script-src 'self'
```

- **Escape** all user-supplied output before rendering it in HTML
- **Validate & sanitize** input server-side (whitelist, not blacklist)
- Set **HttpOnly** and **Secure** flags on cookies
- Use a **CSP** header to restrict script sources
- Use framework templating (React, Angular, etc.) which auto-escapes by default

---

## SQL Injection (SQLi)

SQL injection occurs when user input is embedded directly into a SQL query without proper sanitization, allowing an attacker to alter the query's logic.

### Basic Payloads

```sql
-- Authentication bypass
' OR '1'='1
' OR '1'='1' --
admin'--

-- Always-true condition
1 OR 1=1

-- Comment out the rest of the query
' OR 1=1 --
' OR 1=1 #       (MySQL)
' OR 1=1 /*      (multi-line comment)

-- UNION-based data extraction
' UNION SELECT null, username, password FROM users --

-- Error-based (triggers DB error to leak info)
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --
```

### Example: Vulnerable vs. Safe Code

**Vulnerable (Python)**
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Safe — Parameterized Query**
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

**Safe — ORM (SQLAlchemy)**
```python
user = session.query(User).filter(User.username == username).first()
```

### Common Injection Points

- Login forms (username / password fields)
- Search boxes
- URL path parameters (`/product?id=1`)
- HTTP headers passed to queries (`X-Forwarded-For`, cookies)
- Order-by or sort parameters

### Types

| Type | Description |
|------|-------------|
| **In-band** | Results returned directly in the response |
| **Blind (Boolean)** | True/false responses used to infer data |
| **Blind (Time-based)** | `SLEEP()` / `WAITFOR DELAY` to infer data from response timing |
| **Out-of-band** | Data exfiltrated via DNS or HTTP requests from the DB server |

### Defenses

- **Parameterized queries / prepared statements** — the single most effective defense
- **ORMs** — abstract raw SQL and use parameterization by default
- **Stored procedures** — can be safe if they don't construct dynamic SQL internally
- **Whitelist input validation** — reject unexpected characters where possible
- **Least privilege** — DB accounts used by the app should have minimal permissions
- **WAF** — Web Application Firewall as an additional layer (not a replacement)
- **Error handling** — never expose raw DB error messages to users

---

## Quick Comparison

| | XSS | SQL Injection |
|--|-----|---------------|
| **Target** | User's browser | Backend database |
| **Payload language** | HTML / JavaScript | SQL |
| **Impact** | Session theft, defacement, malware | Data breach, auth bypass, data loss |
| **Primary defense** | Output escaping + CSP | Parameterized queries |

---

## Testing Tools (Legal, Authorized Testing Only)

- **Burp Suite** — intercept and modify HTTP requests
- **OWASP ZAP** — automated scanner
- **sqlmap** — automated SQL injection detection and exploitation
- **XSStrike** — advanced XSS detection tool

> ⚠️ Only test systems you own or have explicit written permission to test.
