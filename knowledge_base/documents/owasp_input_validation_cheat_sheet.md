# OWASP Input Validation Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
Input validation is performed to ensure only properly formed data enters the workflow of an information system, preventing malformed data from persisting in the database and triggering malfunction of various downstream components. Input validation must be applied at every tier of the application (client, server, and database layer). Server-side validation is mandatory — client-side validation is convenience only and can be trivially bypassed.

## Goals of Input Validation
- Prevent injection attacks (SQLi, XSS, Command Injection, LDAP Injection, XML Injection).
- Enforce business-rule constraints on data (type, length, format, range).
- Reject unexpected, malicious, or malformed data before it reaches sensitive operations.

## Validation Strategies

### Allowlist (Whitelist) Validation — Preferred Approach
Define and enforce exactly what is acceptable. Reject anything that does not match the allowlist. This is the strongest form of validation.

```python
import re

def validate_username(username: str) -> bool:
    """Only allow alphanumeric and underscore, 3–32 chars."""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,32}$', username))

def validate_integer_range(value: str, min_val: int, max_val: int) -> int:
    """Strictly parse and range-check an integer parameter."""
    try:
        n = int(value)
    except (ValueError, TypeError):
        raise ValueError(f"Expected integer, got: {value!r}")
    if not (min_val <= n <= max_val):
        raise ValueError(f"Value {n} out of allowed range [{min_val}, {max_val}].")
    return n
```

### Denylist (Blacklist) Validation — Weak, Avoid
Attempting to enumerate all dangerous inputs is fragile and easily bypassed through encoding tricks (URL encoding, HTML entity encoding, Unicode normalization). Only use denylist as an additional layer, never as a primary defense.

## SQL Injection Prevention via Parameterized Queries

All SQL queries must use parameterized queries (prepared statements) — never concatenate user data into query strings.

### Python — Parameterized Query
```python
# SAFE: parameterized with placeholder
cursor.execute(
    "SELECT id, email FROM users WHERE username = %s AND active = %s",
    (username, True)
)
```

### Java — PreparedStatement
```java
// SAFE: parameterized PreparedStatement
String sql = "SELECT id, email FROM users WHERE username = ? AND active = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ps.setBoolean(2, true);
ResultSet rs = ps.executeQuery();
```

Never use `Statement.executeQuery("SELECT ... WHERE username = '" + username + "'")`.

## OS Command Injection Prevention
Never pass user-supplied data to shell-executing functions. If system commands are unavoidable, use argument array form without invoking a shell.

### Python — Unsafe vs Safe
```python
# VULNERABLE: shell=True interprets shell metacharacters
import subprocess
subprocess.Popen("ping -c 1 " + user_input, shell=True)  # Command injection!

# SAFE: argument list, shell=False (default)
subprocess.run(["ping", "-c", "1", user_input], shell=False, timeout=5)
```

### Java — Unsafe vs Safe
```java
// VULNERABLE: passes string to shell
Runtime.getRuntime().exec("nslookup " + userInput);

// SAFE: argument array bypasses shell interpretation
String[] cmd = {"nslookup", userInput};
Runtime.getRuntime().exec(cmd);
```

## Path Traversal Prevention
Normalize and canonicalize file paths before use. Reject paths containing `..` sequences.

```python
import os
from pathlib import Path

SAFE_BASE = Path("/var/app/uploads").resolve()

def safe_file_path(user_filename: str) -> Path:
    """Reject path traversal attempts."""
    candidate = (SAFE_BASE / user_filename).resolve()
    if not str(candidate).startswith(str(SAFE_BASE)):
        raise ValueError("Path traversal detected.")
    return candidate
```

## Data Type and Length Validation
Always validate data type and length before processing:
- Strings: maximum length enforced; reject binary or non-printable characters where not expected.
- Integers/Floats: parse strictly, enforce min/max range.
- Email addresses: validate against RFC 5321 structure; never use regex alone as sole sanitization.
- File uploads: validate MIME type server-side (not client-supplied Content-Type), check magic bytes, enforce maximum file size.

## Encoding and Escaping
Validation does not replace proper output encoding. Always apply context-aware escaping at the point of output:
- HTML context: HTML-entity encode (`<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`).
- SQL context: use parameterized queries (never manual escaping).
- Shell context: avoid entirely; if unavoidable use `shlex.quote()` in Python.
- URL context: percent-encode user data.
