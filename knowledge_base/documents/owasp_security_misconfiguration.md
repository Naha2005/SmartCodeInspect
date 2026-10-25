# OWASP Security Misconfiguration Prevention Cheat Sheet

Source: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
Retrieved: 2026-10-12
Author: OWASP Top 10 Team
Topic: Security Misconfiguration & Hardening

## Introduction
Security misconfiguration is commonly found in web applications where developers or system administrators fail to implement secure configuration defaults across all layers of the application stack, including network services, web servers, databases, and application runtimes.

## Attack Scenarios and High-Risk Patterns
1. **Enabled Debug Mode in Production:** Running frameworks with `debug=True` (e.g., Flask Werkzeug interactive debugger, Django DEBUG mode, or Spring Boot DevTools) exposes interactive consoles, secret keys, environment variables, and full stack traces.
2. **Default Accounts and Unchanged Passwords:** Deploying databases, message queues, or administrative panels with default passwords enabled.
3. **Missing Security Headers:** Failing to emit modern browser security headers allows cross-origin data theft, MIME confusion attacks, and clickjacking.
4. **Directory Listing Enabled:** Web servers serving directory indexes when default index files are missing, exposing sensitive source files and backups.

## Hardening Guidance & Mitigation

### 1. Disable Debug Runtimes in Production
Ensure production entry points strictly read boolean flags from verified environment variables and default to safe production configurations.
```python
import os

# Unsafe:
# app.run(debug=True)

# Safe:
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
app.run(host="127.0.0.1", port=5000, debug=FLASK_DEBUG)
```

### 2. Implement Essential HTTP Security Headers
All API and web responses should include:
- `Content-Security-Policy: default-src 'self'`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 3. Automated Hardening Checklist
- Remove unused features, endpoints, sample files, and documentation in production builds.
- Configure error handlers to return generic error identifiers without internal system disclosures.
- Regularly audit cloud buckets (AWS S3, GCP Buckets) for accidental public read permissions.
