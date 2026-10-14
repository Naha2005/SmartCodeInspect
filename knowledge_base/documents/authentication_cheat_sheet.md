# OWASP Authentication Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
Authentication is the process of verifying that an individual, entity, or website is who they claim to be. Authentication in the context of web applications is commonly performed by submitting a username or ID and one or more items of private information that only a given user should know. Session management is a process by which a server maintains the state of a user's authentication so that the user may continue to use the system without re-authenticating.

## Password Storage Requirements
Passwords must never be stored in plaintext. Appropriate one-way hashing using modern adaptive algorithms must be used. Recommended algorithms ordered by preference:

1. **Argon2id** — memory-hard, time-cost, and parallelism parameters must be configured. Use a minimum of 64 MB memory, 3 iterations, and 4 parallel threads for interactive logins.
2. **bcrypt** — cost factor of at least 10 (recommend 12+) to protect against brute-force attacks.
3. **scrypt** — requires careful tuning of N, r, and p parameters. N=32768, r=8, p=1 is a reasonable starting point.
4. **PBKDF2** — use PBKDF2-HMAC-SHA256 with at least 600,000 iterations for passwords.

Never use MD5, SHA-1, SHA-256, or any raw (unsalted) hash for password storage. These are designed for speed, not security, and are trivially vulnerable to dictionary attacks and rainbow tables.

## Password Strength Requirements
Enforce the following minimum password policy:
- Minimum 12 characters in length.
- Allow all printable ASCII characters plus Unicode.
- Do NOT enforce composition rules (uppercase/lowercase/digit/special) — length matters more.
- Check passwords against a breach corpus such as HaveIBeenPwned or the NIST SP 800-63B word list.
- Implement a password strength meter to encourage strong choices rather than only enforcing minimum rules.

## Hardcoded Credentials in Source Code
Hardcoding passwords, API keys, tokens, or secrets directly in source code is a critical security failure corresponding to CWE-798 (Use of Hard-coded Credentials) and OWASP A07:2021.

### Vulnerable Pattern (Python)
```python
# NEVER hardcode credentials
DB_PASSWORD = "SuperSecret123!"      # Hardcoded secret — OWASP A07
API_KEY = "sk-live-abc123secret"    # Hardcoded API key — CWE-798
```

### Secure Pattern (Python)
```python
import os
DB_PASSWORD = os.getenv("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")
if not DB_PASSWORD or not API_KEY:
    raise RuntimeError("Required secrets not configured in environment variables.")
```

### Vulnerable Pattern (Java)
```java
// NEVER hardcode credentials in Java source files
private static final String API_SECRET = "AKIAIOSFODNN7EXAMPLE";  // Exposed to decompilers
private static final String DB_PASS = "RootAdmin2026!";
```

### Secure Pattern (Java)
```java
// Load secrets from environment variables or a secrets manager
private static final String API_SECRET = System.getenv("API_SECRET");
private static final String DB_PASS    = System.getenv("DB_PASSWORD");
```

Use AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or equivalent to manage production credentials externally.

## Multi-Factor Authentication (MFA)
Implement MFA for all accounts with elevated privileges. TOTP (Time-based One-Time Password, RFC 6238) using authenticator apps (e.g. Google Authenticator, Authy) is strongly recommended. Hardware security keys (FIDO2/WebAuthn) provide the strongest protection against phishing.

## Brute Force Protection
- Implement account lockout after 5–10 consecutive failed login attempts.
- Use exponential back-off or CAPTCHA after repeated failures.
- Log and alert on suspicious login patterns.
- Never reveal whether a username exists via differential error messages: always return "Invalid username or password."

## Secure Session Management
- Generate session IDs with a cryptographically secure random source of at least 128 bits of entropy.
- Regenerate session ID on privilege level change (e.g., after successful login).
- Set Secure, HttpOnly, and SameSite=Strict attributes on session cookies.
- Invalidate sessions on server-side upon logout.
- Set appropriate session timeout (idle and absolute).

## Authentication Error Messages
Never differentiate between invalid username and invalid password in error messages. Always use a generic message: "Invalid credentials." This prevents user enumeration attacks.
