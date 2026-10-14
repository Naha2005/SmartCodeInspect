# OWASP Secrets Management Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
Secrets are credentials, API keys, tokens, private keys, connection strings, passwords, or any sensitive value used by an application to authenticate itself to external services or protect data. Mismanaged secrets are a leading cause of breaches — exposed secrets in repositories, configuration files, logs, or binary artifacts have resulted in some of the most significant cloud security incidents of the last decade.

## Core Principles of Secrets Management

### 1. Never Hardcode Secrets in Source Code
Hardcoded secrets in source code violate CWE-798 and OWASP A07:2021 (Identification and Authentication Failures). Source code is frequently committed to version control, shared among teams, decompiled from binaries, or inadvertently exposed.

**Vulnerable Java:**
```java
// CRITICALLY INSECURE — extractable by javap/jadx decompiler
private static final String AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET";
private static final String DB_PASSWORD    = "RootAdmin_2026!";
```

**Vulnerable Python:**
```python
# CRITICALLY INSECURE — committed to Git, visible in logs
API_SECRET_KEY = "sk-prod-abc123-untrusted-key"
DB_PASS = "SuperSecretPassword123!"
```

**Secure Python:**
```python
import os

API_SECRET_KEY = os.environ.get("API_SECRET_KEY")
DB_PASS = os.environ.get("DB_PASSWORD")

if not API_SECRET_KEY:
    raise EnvironmentError("API_SECRET_KEY environment variable is not set.")
```

**Secure Java:**
```java
String apiSecretKey = System.getenv("API_SECRET_KEY");
String dbPassword   = System.getenv("DB_PASSWORD");
if (apiSecretKey == null || apiSecretKey.isEmpty()) {
    throw new IllegalStateException("API_SECRET_KEY environment variable is required.");
}
```

### 2. Use a Dedicated Secrets Manager
Production applications must use a dedicated secrets management system:
- **AWS Secrets Manager** — automatic secret rotation, IAM access control, audit logging.
- **HashiCorp Vault** — open-source, dynamic secrets, lease-based access, supports K8s, Nomad.
- **Azure Key Vault** — managed secrets, keys, and certificates integrated with Azure AD.
- **Google Cloud Secret Manager** — versioned secrets, IAM-based access, audit trail.
- **Kubernetes Secrets** — base64-encoded (not encrypted by default; enable etcd encryption at rest and use external secret operators like External Secrets Operator).

### 3. Secrets Must Not Appear in Logs
Implement log sanitization to prevent secrets leaking into log files, error messages, or stack traces.

```python
import logging
import re

class SecretRedactingFilter(logging.Filter):
    """Redact common secret patterns from log records."""
    SECRET_PATTERN = re.compile(
        r'((?:api[_-]?key|secret|password|token|auth)\s*[:=]\s*)[^\s,\'"]{6,}',
        re.IGNORECASE
    )

    def filter(self, record):
        record.msg = self.SECRET_PATTERN.sub(r'\1[REDACTED]', str(record.msg))
        return True
```

### 4. Rotate Secrets Regularly
- Rotate secrets on a defined schedule (e.g., API keys every 90 days, database passwords every 60 days).
- Immediately rotate any secret that may have been exposed (repository leak, terminated employee, etc.).
- Use short-lived tokens (JWT with short expiry, temporary IAM credentials) where possible to limit the blast radius of a leak.

### 5. Restrict Secret Access with Least Privilege
- Apply the principle of least privilege: each service or microservice should only have access to the secrets it strictly needs.
- Use separate credentials for development, staging, and production environments.
- Never share production credentials with developers for local development.

## Detecting Hardcoded Secrets
Use static analysis tools as part of the CI/CD pipeline to automatically detect hardcoded secrets before code is merged:
- **truffleHog** — scans Git history for high-entropy strings and regex-based secrets.
- **detect-secrets** — Yelp's tool; integrates with pre-commit hooks.
- **GitGuardian** — real-time monitoring of GitHub/GitLab commits for secret exposure.
- **Semgrep** — rule-based SAST that supports custom secret patterns.

## Environment Variable Security
When using environment variables:
- Set them at the deployment/orchestration layer (e.g., Kubernetes secrets mounted as environment variables, AWS ECS task definitions, Docker secrets).
- Never commit `.env` files containing real secrets to version control. Add `.env` to `.gitignore`.
- Use `.env.example` (with placeholder values only) as a template.

## Secret Classification
Classify secrets by sensitivity and handle accordingly:

| Secret Type          | Example                         | Storage Method            |
|---------------------|---------------------------------|---------------------------|
| Database passwords  | PostgreSQL, MySQL, MongoDB creds | Secrets Manager / env var |
| API keys            | OpenAI, Stripe, AWS API keys    | Secrets Manager / env var |
| Private keys        | TLS private key, SSH key        | Key Vault / HSM           |
| JWT signing secrets | HS256 secret key                | Secrets Manager           |
| OAuth client secrets| OAuth 2.0 client_secret         | Secrets Manager           |

## Version Control Hygiene
If a secret has ever been committed to a Git repository, assume it is compromised — even after removal via `git rm` or `git rebase`. The commit history retains the exposed value. Required remediation steps:
1. Immediately invalidate/rotate the exposed secret.
2. Use `git-filter-repo` or BFG Repo Cleaner to remove the secret from all history.
3. Force-push to all remotes and notify all collaborators to reclone.
4. Audit access logs for the period during which the secret was exposed.
