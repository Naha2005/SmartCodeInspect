# OWASP Secrets Management & Credential Protection Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)
Classification: CWE-798 (Use of Hard-coded Credentials), CWE-200 (Information Exposure), CWE-522 (Insufficiently Protected Credentials), CWE-532 (Insertion of Sensitive Information into Log File)

---

## 1. Executive Summary & Threat Architecture
Secrets represent the foundational keys to modern software infrastructure. They encompass API keys, database connection strings, symmetric encryption keys, asymmetric private keys, OAuth client secrets, JSON Web Token (JWT) signing keys, cloud provider IAM credentials, service account tokens, and TLS private certificates.

Mismanagement, exposure, and improper hardcoding of secrets constitute one of the most prolific and devastating attack vectors in cloud security. A leaked credential grants adversaries immediate, authenticated access to internal corporate networks, customer data stores, and automated production pipelines without requiring the exploitation of software vulnerabilities.

### Primary Risk Vectors:
1. **Source Code Version Control Exposure**: Secrets committed directly to Git repositories (both public and private), commit history logs, pull requests, and forks.
2. **CI/CD Pipeline and Build Leakage**: Environment variables printed to console logs during automated test runs, Docker container image layers (`docker history` or cached layers containing `ENV` or build arguments), and artifact repositories.
3. **Application Logging & Observability Leakage**: Sensitive credentials captured in application trace logs, APM systems (Datadog, Dynatrace), crash reporting systems (Sentry), HTTP access logs (query strings containing tokens), and debug stack traces.
4. **Runtime Process Introspection**: Exposing secrets in environment variables where child processes, local unprivileged users reading `/proc/$PID/environ`, or container inspection commands (`docker inspect`) can extract plaintext values.
5. **Static Long-Lived Credentials**: Failure to implement automated credential rotation, resulting in dormant keys remaining valid and exploitable months or years after an employee or third-party departure.

---

## 2. Secrets Classification & Identification Signatures

| Secret Category | Description / Typical Format | Detection Signature / Regex Pattern | Risk Level |
|---|---|---|---|
| **AWS IAM Access Key** | 20-character key starting with `AKIA` or `ASIA` | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | Critical |
| **AWS Secret Access Key** | 40-character Base64-like string | `(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]` | Critical |
| **GitHub Personal Token** | Modern GitHub token prefix | `\b(ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9_]{36,255}\b` | Critical |
| **Generic Bearer Token / JWT** | RFC 7519 JSON Web Token | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b` | High |
| **Private Cryptographic Key** | PEM-encoded RSA/EC private key block | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH\|PRIVATE) KEY-----` | Critical |
| **Stripe API Key** | Stripe payment processing secret | `\brk_test_[0-9a-zA-Z]{24,34}\b\|\bsk_test_[0-9a-zA-Z]{24,34}\b` | Critical |
| **Database Connection String** | JDBC, PostgreSQL, or MongoDB URI | `(?i)(postgres\|mysql\|mongodb(\+srv)?):\/\/[^:]+:[^@]+@` | Critical |
| **Slack Webhook URL** | Incoming webhook integrations | `https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8}\/B[0-9A-Z]{8}\/[0-9A-Za-z]{24}` | High |

---

## 3. Defense-in-Depth Lifecycle & Management Hierarchy

```
[ Developer / CI/CD ]
          │
          ▼
┌──────────────────────────────────────────────┐
│ 1. Shift-Left Pre-Commit Secret Scanning     │ -> Gitleaks, TruffleHog, pre-commit git hooks
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ 2. Centralized Secrets Vault (KMS / Vault)   │ -> HashiCorp Vault, AWS Secrets Manager,
│                                              │    Azure Key Vault, Google Secret Manager
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ 3. Ephemeral Dynamic Secrets & Short TTLs    │ -> Dynamic DB credentials leased for 1 hour,
│                                              │    automated rotation, no static passwords
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ 4. In-Memory Sanitization & Redaction        │ -> Zeroize byte/char arrays; scrub all logs;
│                                              │    prohibit printing secrets to stdout
└──────────────────────────────────────────────┘
```

### Core Architecture Directives:
1. **Zero Hardcoded Secrets in Code or Configs**: Absolutely never store passwords, API keys, tokens, or private keys in source files, property files, or Git history.
2. **Utilize Dedicated Secrets Vaults**: Integrate production workloads with dedicated secrets managers (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager).
3. **Prefer Short-Lived, Dynamic Credentials**: Whenever possible, eliminate static passwords in favor of dynamic credentials (e.g., Vault database secrets engine generating short-lived temporary database roles that expire automatically).
4. **Deliver Secrets via Memory-Backed Mounts**: When deploying containers (Kubernetes / ECS), mount secrets as memory-backed files (tmpfs) rather than raw environment variables, preventing child processes or container inspection from exposing secrets.
5. **Comprehensive Log Redaction**: Configure log formatters with automated masking filters to ensure accidental credential outputs are replaced with `[REDACTED]`.

---

## 4. Vulnerable vs. Secure Implementations in Python

### 4.1 Vulnerable Python Patterns

```python
# ==============================================================================
# VULNERABLE PYTHON PATTERNS -- DO NOT USE IN PRODUCTION
# ==============================================================================
import logging
import requests

# Flaw 1: Hardcoded credentials committed to source code (CWE-798)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_CONNECTION_STRING = "postgresql://admin:Password123!@db.internal:5432/production"

logging.basicConfig(level=logging.INFO)

def authenticate_client(api_token: str):
    # Flaw 2: Logging sensitive API tokens directly to logs (CWE-532)
    logging.info(f"Authenticating incoming request with token: {api_token}")
    
    # Flaw 3: Passing tokens via URL query parameters
    url = f"https://api.external.com/v1/data?token={api_token}"
    return requests.get(url)
```

### 4.2 Secure Enterprise Python Implementation

```python
"""
Enterprise Secrets Management & Log Redaction Service (Python 3.11+)
Compliant with OWASP Secrets Management Guidelines (2026 Edition).
Demonstrates environment/vault secrets ingestion and automatic log sanitization.
"""

import os
import re
import logging
from typing import Optional, Dict


class SensitiveDataLogFilter(logging.Filter):
    """
    High-performance logging filter that scrubs secrets, API keys, 
    and tokens using regex redaction before log records are written.
    """
    SECRET_PATTERNS = [
        # AWS Access Key ID
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        # Bearer tokens & JWTs
        re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]+", re.IGNORECASE),
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        # Passwords in URLs / queries
        re.compile(r"(password|pwd|secret|token|apiKey)=([^&\s]+)", re.IGNORECASE),
        # Generic high-entropy hex/base64 strings labeled as keys
        re.compile(r"(?i)(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9\+/=_-]{16,}['\"]?"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern in self.SECRET_PATTERNS:
                record.msg = pattern.sub(r"\1=[REDACTED]" if "(" in pattern.pattern else "[REDACTED]", record.msg)
        if record.args:
            # If arguments are provided for string interpolation, scrub them safely
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    for pattern in self.SECRET_PATTERNS:
                        arg = pattern.sub("[REDACTED]", arg)
                sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        return True


class SecureConfigurationProvider:
    """
    Secure configuration loader that loads secrets from external environment
    or secure vault mounts and prevents uninitialized access.
    """
    def __init__(self):
        self._secrets: Dict[str, str] = {}
        self._load_required_secrets()

    def _load_required_secrets(self) -> None:
        """
        Loads required production secrets with validation and strict presence checks.
        """
        required_keys = [
            "DATABASE_PASSWORD",
            "API_SIGNING_SECRET",
            "OAUTH_CLIENT_SECRET"
        ]

        missing_keys = []
        for key in required_keys:
            # Attempt to read from Docker/K8s secret file mount first (/var/run/secrets/)
            secret_file_path = f"/var/run/secrets/{key.lower()}"
            if os.path.isfile(secret_file_path):
                with open(secret_file_path, "r", encoding="utf-8") as f:
                    self._secrets[key] = f.read().strip()
            else:
                # Fallback to system environment variables
                val = os.getenv(key)
                if val:
                    self._secrets[key] = val
                else:
                    missing_keys.append(key)

        if missing_keys:
            raise RuntimeError(
                f"Fatal Security Error: Missing required secrets: {', '.join(missing_keys)}. "
                "Ensure secrets are provisioned via Vault or environment variables."
            )

    def get_secret(self, key: str) -> str:
        """Retrieves a loaded secret."""
        if key not in self._secrets:
            raise KeyError(f"Requested secret '{key}' was not found in secure configuration")
        return self._secrets[key]


# Configure root logger with sensitive data redaction filter
def configure_secure_logging() -> logging.Logger:
    logger = logging.getLogger("EnterpriseApp")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    handler.addFilter(SensitiveDataLogFilter())
    logger.addHandler(handler)
    return logger
```

---

## 5. Vulnerable vs. Secure Implementations in Java

### 5.1 Vulnerable Java Patterns

```java
// ==============================================================================
// VULNERABLE JAVA PATTERNS -- DO NOT USE IN PRODUCTION
// ==============================================================================
import java.sql.DriverManager;
import java.sql.Connection;

public class VulnerableSecretsService {
    // Flaw 1: Hardcoded credentials decompilable from class files (CWE-798)
    private static final String DB_USER = "db_admin";
    private static final String DB_PASS = "ProductionDatabasePassword2026!";
    private static final String STRIPE_KEY = "sk_test_mock_dummy_stripe_key_placeholder";

    public Connection getConnection() throws Exception {
        // Flaw 2: Hardcoded connection string
        return DriverManager.getConnection("jdbc:postgresql://db:5432/prod", DB_USER, DB_PASS);
    }

    public void logAuthAttempt(String username, String rawPassword) {
        // Flaw 3: Printing passwords and tokens to stdout/System.out (CWE-532)
        System.out.println("User: " + username + " attempted login with password: " + rawPassword);
    }
}
```

### 5.2 Secure Enterprise Java Implementation (Memory Zeroization & Vault Pattern)

```java
package com.enterprise.security.secrets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * Enterprise Secure Secrets Management Service (Java 17/21+)
 * Compliant with OWASP Secrets Management Standards (2026 Edition).
 * Demonstrates character array password handling and memory zeroization.
 */
public final class SecureSecretsProvider {

    private static final Path K8S_SECRETS_MOUNT = Path.of("/var/run/secrets/application");

    /**
     * Reads a sensitive secret into a mutable char array to allow memory zeroization.
     * Note: Avoid java.lang.String for passwords/keys because Strings are immutable
     * and remain in the JVM heap string pool until garbage collection.
     */
    public static char[] loadSecretCharArray(String secretKeyName) throws IOException {
        Objects.requireNonNull(secretKeyName, "Secret name cannot be null");

        Path secretFile = K8S_SECRETS_MOUNT.resolve(secretKeyName);
        if (Files.exists(secretFile)) {
            // Read from tmpfs / memory-backed secret volume
            String content = Files.readString(secretFile).trim();
            return content.toCharArray();
        }

        // Fallback to environment variable
        String envValue = System.getenv(secretKeyName);
        if (envValue != null && !envValue.isBlank()) {
            return envValue.toCharArray();
        }

        throw new IllegalStateException("Required secret '" + secretKeyName + "' could not be located.");
    }

    /**
     * Zeroizes the character array in memory immediately after cryptographic use.
     * Prevents credentials from lingering in JVM heap dumps or core dumps.
     */
    public static void wipeSensitiveMemory(char[] sensitiveData) {
        if (sensitiveData != null) {
            Arrays.fill(sensitiveData, '\0');
        }
    }

    /**
     * Zeroizes a byte array in memory.
     */
    public static void wipeSensitiveMemory(byte[] sensitiveBytes) {
        if (sensitiveBytes != null) {
            Arrays.fill(sensitiveBytes, (byte) 0);
        }
    }

    /**
     * Sanitizes a log message by masking sensitive keys, tokens, and authorization headers.
     */
    public static String redactLogMessage(String rawMessage) {
        if (rawMessage == null) return null;
        // Replace Bearer tokens
        String sanitized = rawMessage.replaceAll("(?i)Bearer\\s+[A-Za-z0-9\\-_\\.=]+", "Bearer [REDACTED]");
        // Replace password parameters
        sanitized = sanitized.replaceAll("(?i)(password|secret|token|apikey)\\s*=\\s*[^&\\s]+", "$1=[REDACTED]");
        // Replace AWS Access Keys
        sanitized = sanitized.replaceAll("\\b(AKIA|ASIA)[0-9A-Z]{16}\\b", "[REDACTED_AWS_KEY]");
        return sanitized;
    }
}
```

---

## 6. Static Code Analysis (SAST) Detection Rules

| Engine Rule ID | Language | Severity | Trigger Condition / Heuristic |
|---|---|---|---|
| `AUTH-PY-001` | Python | Critical | String literal assigned to variables named `password`, `secret`, `api_key`, `token` |
| `AUTH-PY-002` | Python | High | Regex match for AWS keys (`AKIA...`), GitHub tokens, or Stripe secret keys in code |
| `LOG-PY-001` | Python | High | `logging.info()`, `logger.debug()` printing variable named `password`, `token`, `secret` |
| `AUTH-JV-001` | Java | Critical | String literal containing API keys, private keys, or passwords assigned to constant fields |
| `AUTH-JV-002` | Java | High | Hardcoded database URL containing credentials (`jdbc:...password=...`) |
| `LOG-JV-001` | Java | High | `System.out.println()` or SLF4J logger writing sensitive variables to console |

---

## 7. OWASP 2026 Secrets Management Verification Checklist

- [ ] **Zero Hardcoded Secrets**: Has the entire codebase been scanned with automated tools (e.g., Gitleaks, TruffleHog) with zero hardcoded credentials detected?
- [ ] **Centralized Secrets Manager**: Are all production secrets provisioned through a managed vault (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)?
- [ ] **Git Pre-Commit Hooks**: Are pre-commit hooks configured across developer workstations to reject commits containing high-entropy keys or token patterns?
- [ ] **Memory-Backed Volumes (tmpfs)**: In containerized environments, are secrets mounted via ramdisks/tmpfs rather than plaintext environment variables?
- [ ] **Automated Key Rotation**: Are database credentials and API keys automatically rotated on a scheduled cadence (e.g., 30 to 90 days)?
- [ ] **Log Redaction Filters**: Are logging frameworks configured with automated regex masking filters to prevent accidental credential leakage in logs?
- [ ] **Memory Zeroization**: Are sensitive cryptographic keys and passwords explicitly cleared (overwritten with zeroes) immediately after use in memory?
- [ ] **Principle of Least Privilege**: Do service accounts and API tokens possess the absolute minimum required IAM permissions?
