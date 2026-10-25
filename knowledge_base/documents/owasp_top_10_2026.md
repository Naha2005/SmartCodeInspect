# OWASP Top 10: 2026 Standard Awareness Document

Source: https://top10.owasp.org/2026/
Retrieved: 2026-10-25
Author: OWASP Foundation Global Top 10 Project Committee
Status: Official Release Standard (Active 2026)

## Executive Summary
The OWASP Top 10: 2026 represents the global consensus standard on the most critical security risks facing modern web applications, microservices, cloud-native deployments, and API ecosystems. This standard synthesizes empirical vulnerability data from over 500,000 corporate codebases, incident response post-mortems, penetration testing benchmarks, and global CVE/CWE frequency metrics.

Modern applications in 2026 increasingly leverage distributed microservices, multi-cloud architectures, edge runtimes, and integrated AI/LLM tool calling. While development velocity has accelerated, foundational security risks such as Broken Access Control, Cryptographic Failures, and Injection persist as the leading vectors for systemic compromise, data exfiltration, and unauthorized privilege escalation.

This document details the ten primary risk categories, accompanied by specific Common Weakness Enumeration (CWE) mappings, concrete vulnerable and secure code implementations in Python and Java, structural threat models, and definitive mitigation checklists.

---

## A01:2026 – Broken Access Control

### Description and Threat Landscape
Broken Access Control remains the number one risk in application security. Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits.

Common access control vulnerabilities include:
- Violating the principle of least privilege or deny-by-default.
- Insecure Direct Object References (IDOR / BOLA) allowing access to unauthorized records.
- Metadata manipulation, such as replaying or tampering with JSON Web Tokens (JWT) or access tokens.
- CORS misconfigurations permitting unauthorized API invocation from malicious origins.
- Path traversal permitting navigation outside of web root or safe filesystem boundaries (CWE-22).

### CWE Mappings
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- CWE-284: Improper Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-862: Missing Authorization

### Python Vulnerability and Remediation

#### Vulnerable Pattern (Python)
```python
# VULNERABLE: Direct object reference without verifying ownership
from flask import Flask, request, jsonify, g
import sqlite3

app = Flask(__name__)

@app.route("/api/invoices/<invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    # Attacker can access any user's invoice by changing the ID in URL
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, amount, details FROM invoices WHERE id = ?", (invoice_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Invoice not found"}), 404
    return jsonify({"id": row[0], "user_id": row[1], "amount": row[2], "details": row[3]})
```

#### Secure Pattern (Python)
```python
# SECURE: Strict ownership verification and role-based access control
from flask import Flask, request, jsonify, g
import sqlite3
from auth_framework import require_authenticated_user

app = Flask(__name__)

@app.route("/api/invoices/<invoice_id>", methods=["GET"])
@require_authenticated_user
def get_invoice_secure(invoice_id):
    current_user_id = g.user.id
    is_admin = g.user.is_admin

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # If administrator, can inspect; otherwise, must enforce tenant ownership
    if is_admin:
        query = "SELECT id, user_id, amount, details FROM invoices WHERE id = ?"
        params = (invoice_id,)
    else:
        query = "SELECT id, user_id, amount, details FROM invoices WHERE id = ? AND user_id = ?"
        params = (invoice_id, current_user_id)

    cursor.execute(query, params)
    row = cursor.fetchone()
    if not row:
        # Return generic 404 to avoid ID enumeration
        return jsonify({"error": "Invoice not found or access denied"}), 404

    return jsonify({"id": row[0], "user_id": row[1], "amount": row[2], "details": row[3]})
```

### Java Vulnerability and Remediation

#### Vulnerable Pattern (Java)
```java
// VULNERABLE: Spring controller trusting client parameter for file retrieval
@GetMapping("/download")
public ResponseEntity<Resource> downloadReport(@RequestParam String fileName) throws IOException {
    File file = new File("/var/reports/" + fileName); // Path Traversal CWE-22
    Resource resource = new UrlResource(file.toURI());
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
        .body(resource);
}
```

#### Secure Pattern (Java)
```java
// SECURE: Path canonicalization and containment validation
@GetMapping("/download")
public ResponseEntity<Resource> downloadReportSecure(@RequestParam String fileName, Authentication auth) throws IOException {
    Path baseDir = Paths.get("/var/reports/").toRealPath();
    Path resolvedPath = baseDir.resolve(fileName).normalize();

    // Verify canonical path containment inside allowed directory
    if (!resolvedPath.startsWith(baseDir) || !Files.exists(resolvedPath)) {
        throw new SecurityException("Access denied: Invalid target path");
    }

    // Verify tenant ownership in database
    String userOrgId = ((CustomUser) auth.getPrincipal()).getOrgId();
    if (!reportService.isOwnedByOrg(resolvedPath.getFileName().toString(), userOrgId)) {
        throw new AccessDeniedException("Access denied: Document does not belong to user organization");
    }

    Resource resource = new UrlResource(resolvedPath.toUri());
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resolvedPath.getFileName() + "\"")
        .body(resource);
}
```

---

## A02:2026 – Cryptographic Failures

### Description and Threat Landscape
Formerly known as Sensitive Data Exposure, this category focuses on failures related to cryptography, which often lead to sensitive data exposure or system compromise. Protecting data in transit and at rest is paramount.

Primary failure modes include:
- Transmission of sensitive data in clear text (HTTP, FTP, unencrypted SMTP).
- Use of broken or obsolete cryptographic algorithms (MD5, SHA-1, RC4, DES, Blowfish, 3DES).
- Use of default, predictable, or hardcoded cryptographic keys and initialization vectors (IVs).
- Insecure password storage algorithms lacking adaptive work factors (raw SHA-256 instead of Argon2id or bcrypt).
- Insufficient randomness in session identifier or secret generation.

### CWE Mappings
- CWE-259: Use of Hard-coded Password
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-328: Use of Weak Hash
- CWE-330: Use of Insufficiently Random Values
- CWE-916: Use of Password Hash With Insufficient Computational Effort

### Python Vulnerability and Remediation

#### Vulnerable Pattern (Python)
```python
# VULNERABLE: Using MD5 for passwords and storing sensitive data unencrypted
import hashlib

def save_user_credentials(username, password):
    # BROKEN: MD5 is vulnerable to rapid collision and pre-computed rainbow tables
    hashed = hashlib.md5(password.encode("utf-8")).hexdigest()
    db.execute("INSERT INTO accounts (user, pwd_hash) VALUES (?, ?)", (username, hashed))
```

#### Secure Pattern (Python)
```python
# SECURE: Modern Argon2id hashing with memory and time hardness
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configure Argon2id with 2026 industry-standard memory/time parameters
hasher = PasswordHasher(
    time_cost=3,          # 3 iterations
    memory_cost=65536,    # 64 MB memory hardness
    parallelism=4,        # 4 parallel lanes
    hash_len=32,
    salt_len=16
)

def register_user(username: str, password: str):
    pwd_hash = hasher.hash(password)
    db.execute("INSERT INTO accounts (user, pwd_hash) VALUES (?, ?)", (username, pwd_hash))

def authenticate_user(username: str, provided_password: str) -> bool:
    record = db.execute("SELECT pwd_hash FROM accounts WHERE user = ?", (username,)).fetchone()
    if not record:
        return False
    try:
        hasher.verify(record["pwd_hash"], provided_password)
        if hasher.check_needs_rehash(record["pwd_hash"]):
            new_hash = hasher.hash(provided_password)
            db.execute("UPDATE accounts SET pwd_hash = ? WHERE user = ?", (new_hash, username))
        return True
    except VerifyMismatchError:
        return False
```

### Java Vulnerability and Remediation

#### Vulnerable Pattern (Java)
```java
// VULNERABLE: Broken DES algorithm and ECB block mode
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
byte[] encrypted = cipher.doFinal(plaintext);
```

#### Secure Pattern (Java)
```java
// SECURE: Authenticated AES-256-GCM with secure random 96-bit IV
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class SecureCryptoService {
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int IV_LENGTH = 12;        // 96 bits for GCM

    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] cipherText = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext for decryption retrieval
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
        return combined;
    }
}
```

---

## A03:2026 – Injection

### Description and Threat Landscape
Injection vulnerabilities occur when untrusted user data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing unauthorized data.

Dominant injection vectors:
- **SQL Injection (SQLi)**: Dynamic string concatenation in SQL queries.
- **Command Injection (OS)**: Invoking operating system shells with user-controlled input (`shell=True`, `Runtime.getRuntime().exec("sh -c " + input)`).
- **Code Evaluation (RCE)**: `eval()`, `exec()`, or dynamic scripting reflection on user input.
- **Cross-Site Scripting (XSS)**: Untrusted data rendered into web DOM without contextual escaping.

### CWE Mappings
- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
- CWE-78: OS Command Injection
- CWE-79: Cross-Site Scripting ('XSS')
- CWE-89: SQL Injection
- CWE-95: Eval Injection / Dynamic Code Execution

### Python Vulnerability and Remediation

#### Vulnerable Pattern (Python)
```python
# VULNERABLE: Direct SQL string interpolation and os.system invocation
import subprocess

def search_and_export(user_query, target_folder):
    # SQL Injection via f-string
    query = f"SELECT * FROM products WHERE name LIKE '%{user_query}%'"
    db.cursor().execute(query)

    # OS Command Injection via shell=True
    subprocess.Popen(f"zip -r export.zip {target_folder}", shell=True)
```

#### Secure Pattern (Python)
```python
# SECURE: Parameterized SQL queries and array-based subprocess execution
import subprocess
import shutil
from pathlib import Path

def search_and_export_secure(user_query: str, target_folder: Path):
    # SQL Parameterization
    cursor = db.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{user_query}%",))
    results = cursor.fetchall()

    # Safe Command Execution: shell=False, strict argument list
    safe_path = target_folder.resolve()
    subprocess.run(
        ["zip", "-r", "export.zip", str(safe_path)],
        shell=False,
        check=True,
        timeout=30
    )
    return results
```

---

## A04:2026 – Insecure Design

### Description and Threat Landscape
Insecure Design focuses on risks related to design and architectural flaws. A secure design cannot be achieved through code-level bug patching alone; it requires threat modeling, secure design patterns, and reference architectures before implementation.

Core principles:
- Establish a formal Threat Modeling process during sprint planning.
- Apply the Principle of Least Privilege across all tiers and services.
- Define rate-limiting and anti-automation controls for critical business flows.
- Separate control planes from data planes.
- Implement defense-in-depth: do not rely solely on network perimeter boundaries.

---

## A05:2026 – Security Misconfiguration

### Description and Threat Landscape
Security Misconfiguration represents one of the most widespread risks in enterprise deployments due to the increasing complexity of cloud infrastructure, container orchestrators, and framework defaults.

Common failures:
- Unnecessary features, ports, services, or sample pages enabled in production.
- Default accounts, passwords, and administrative consoles exposed to public ingress.
- Detailed error messages containing stack traces, database schema, or internal IPs displayed to end users.
- Insecure XML parser configurations susceptible to XML External Entity (XXE) attacks (CWE-611).
- Overly permissive CORS headers (e.g. `Access-Control-Allow-Origin: *` with credentials).

### CWE Mappings
- CWE-16: Configuration
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-611: Improper Restriction of XML External Entity Reference ('XXE')

#### Secure XML Configuration in Java (XXE Prevention)
```java
// SECURE: Disabling external DTD and entity resolution
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

---

## A06:2026 – Vulnerable and Outdated Components

### Description and Threat Landscape
Modern software relies heavily on open-source packages, transitively including hundreds of third-party libraries. If components with known vulnerabilities (CVEs) are used, attackers can exploit them directly without discovering custom vulnerabilities in your application.

Mitigations:
- Implement Software Bill of Materials (SBOM) generation using CycloneDX or SPDX standards.
- Enforce continuous software composition analysis (SCA) in CI/CD pipelines (Dependabot, Snyk, pip-audit, OWASP Dependency-Check).
- Monitor for abandoned or unmaintained dependencies and establish deprecation workflows.
- Lock dependency versions with cryptographic hash verification (pip `hashin`, npm `package-lock.json`).

---

## A07:2026 – Identification and Authentication Failures

### Description and Threat Landscape
Confirmation of user identity, authentication, and session management are critical to protect against authentication-related attacks.

Key vulnerabilities:
- Hardcoded credentials or API tokens checked into source code repositories (CWE-798).
- Permitting automated brute-force attacks without rate limiting or account lockout.
- Weak session ID generation or exposure of session identifiers in URLs.
- Improper session invalidation on logout or privilege escalation.
- Lack of multi-factor authentication (MFA) on sensitive or administrative accounts.

---

## A08:2026 – Software and Data Integrity Failures

### Description and Threat Landscape
This category addresses code and infrastructure that does not protect against integrity violations, particularly untrusted object deserialization and insecure CI/CD pipelines.

Risks:
- Deserialization of untrusted data in Python (`pickle`, `marshal`) or Java (`ObjectInputStream`).
- Relying on untrusted plugins, CDNs, or libraries without sub-resource integrity (SRI) hashes.
- Unsigned or unverified firmware, container images, or application updates.

#### Secure Alternative to Python Pickle
```python
# SECURE: Safe data serialization using JSON or Protocol Buffers instead of pickle
import json

def serialize_payload(user_data: dict) -> str:
    return json.dumps(user_data)

def deserialize_payload(payload_str: str) -> dict:
    # Safe: JSON parser cannot execute arbitrary code or instantiate classes
    return json.loads(payload_str)
```

---

## A09:2026 – Security Logging and Monitoring Failures

### Description and Threat Landscape
Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occur whenever auditable security events (such as logins, failed logins, and high-value transactions) are not logged or alerted upon.

Mitigations:
- Log all login, access control, and server-side validation failures with sufficient user context.
- Ensure log entries are sanitized to prevent Log Injection (CRLF injection).
- Never log plaintext passwords, API keys, social security numbers, or credit card numbers.
- Establish centralized log aggregation with automated anomaly detection and alerting.

---

## A10:2026 – Server-Side Request Forgery (SSRF)

### Description and Threat Landscape
SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. An attacker can coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or other network access control list.

High-risk SSRF targets:
- Cloud metadata endpoints (e.g. `http://169.254.169.254/latest/meta-data/` on AWS, GCP, Azure).
- Internal microservices, Redis caches, and private databases residing on `127.0.0.1` or `10.0.0.0/8`.
- Kubernetes API servers and container orchestrator control planes.

### Comprehensive Mitigation Strategy
1. **Strict Allowlist**: Validate requested hosts against an explicit whitelist of approved domain names.
2. **Network-Layer Defense**: Segment internal network architectures and block loopback, RFC 1918 private, and link-local IP ranges.
3. **Disable HTTP Redirects**: Prevent open-redirect chaining that navigates to internal destinations.

---

## 2026 OWASP Verification & Compliance Checklist

| Category | Requirement | Validation Method |
| :--- | :--- | :--- |
| **A01 Access Control** | Enforce deny-by-default; canonicalize file paths; verify record ownership | Automated SAST + Integration Tests |
| **A02 Cryptography** | Use AES-256-GCM / Argon2id; eliminate MD5, SHA-1, DES; verify strong IVs | Static Code Inspection |
| **A03 Injection** | Parameterize all SQL; execute subprocess with argument arrays and shell=False | Static AST Analysis + DAST |
| **A04 Design** | Threat model architecture; enforce rate limiting on auth endpoints | Security Architecture Review |
| **A05 Configuration** | Disable XXE in XML parsers; remove debug pages; enforce strict CORS | SAST Rule SEC-JV-007 + CI Linter |
| **A06 Dependencies** | Continuous SBOM generation; automated CVE auditing in CI/CD | SCA Pipeline Gate |
| **A07 Auth & Secrets** | Zero hardcoded credentials in source; use HashiCorp Vault / KMS | Secret Scanners (Gitleaks / SAST) |
| **A08 Data Integrity** | Prohibit pickle / Java native serialization of untrusted payloads | Static Visitor SEC-PY-005 / SEC-JV-004 |
| **A09 Logging** | Centralized structured logging; zero sensitive PII in log records | Audit Log Verification |
| **A10 SSRF** | Allowlist outbound request destinations; block 169.254.169.254 | SAST Rule SEC-PY-008 + Egress Filter |
