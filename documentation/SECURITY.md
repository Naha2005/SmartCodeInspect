# Security Policy & Execution Sandboxing Guarantees

This document outlines the security architecture, threat model, input validation guarantees, and responsible disclosure practices of the **Smart Code Inspection Platform with Vulnerability Detection System**.

---

## 1. Zero-Execution Guarantee

The core security foundation of this platform is **strict zero-execution static inspection**:
- **No Evaluation**: Submitted source code is **never** executed, imported, or dynamically evaluated under any circumstances.
- **Python Safety**: Python code analysis relies exclusively on `ast.parse` from the Python standard library. No `eval()`, `exec()`, or dynamic `importlib` calls are ever performed on user-submitted code.
- **Java Safety**: Java code is evaluated using the OpenJDK `javac` compiler in an isolated sandbox. Compiled bytecode (`.class` files) is **never executed** (`java` runtime is never invoked on user code).

---

## 2. Process & Execution Sandboxing

When interacting with external processes (such as `javac`), the platform implements strict process-isolation controls:

1. **No System Shell Invocations**:
   - `subprocess.run` is always called with explicit argument lists (`[javac_path, '-d', str(temp_path), '-Xlint:all', str(source_file)]`).
   - `shell=True` is **strictly prohibited** across all backend processes to eliminate shell injection risks.
2. **Deterministic Execution Timeouts**:
   - A hard timeout ceiling of **10 seconds** is enforced for compiler subprocess operations. If a compiler process hangs, loops, or takes longer than 10 seconds, it is terminated immediately via `subprocess.TimeoutExpired`.
3. **Isolated Ephemeral Workspaces**:
   - Compiler operations execute inside isolated temporary directories created via Python's `tempfile.mkdtemp(prefix="sci_java_")`.
   - Temporary directories and compiled `.class` files are purged from disk immediately upon completion of the inspection cycle.
4. **Denial-of-Service (DoS) Payload Guard**:
   - Source code payload ceiling: default **200,000 bytes (~200 KB)**, configurable via `MAX_SOURCE_BYTES` up to 1 MB.
   - Any payload exceeding the configured threshold is rejected before AST parsing or compiler invocation.

---

## 3. Regular Expression Safety (ReDoS Prevention)

To guard against Regular Expression Denial of Service (ReDoS):
- All regular expressions used in security inspection rules avoid nested quantifiers, exponential backtracks, and greedy overlapping tokens.
- Deterministic character classes and non-greedy lookaheads are utilized.
- Code blocks are analyzed line-by-line rather than matching massive multi-line blobs where possible.

---

## 4. Secret Masking & Sensitive Data Protection

When detecting hardcoded credentials, API keys, or private tokens:
- **Redaction**: Secret values discovered in the source code are automatically masked (e.g., `API_SECRET_KEY = "********"`) in the returned findings, JSON responses, and generated PDF reports.
- **Zero Storage**: Submitted source code is not permanently stored or logged in backend databases. The platform operates statelessly in memory.

---

## 5. AI Prompt Shielding, Rate Limiting & Privacy Notice

When the optional AI Advisory layer is engaged:
- **User Disclosure**: The frontend interface explicitly presents a privacy notice and requires user confirmation before sending finding metadata externally.
- **Prompt Shielding**: Only structured finding metadata (rule ID, severity, sanitized evidence excerpt, OWASP category) is included in the AI context. Raw uninspected files or system credentials are never forwarded to the AI model.
- **Quota & Rate Limiting**: Enforces a 10 requests-per-minute (RPM) sliding window and a 2.0-second inter-request spacing cooldown.
- **In-Memory Caching**: Identical finding signatures (`rule_id + title + evidence`) are cached with SHA-256 keys to conserve API quota.
- **Offline Fallback**: If an API key is missing or quota is exhausted, the system automatically defaults to an offline curated rulebook advisory without error.

---

## 6. Responsible Vulnerability Disclosure

If you discover a security vulnerability in this platform:
1. Please do not open a public GitHub issue.
2. Report the vulnerability privately to the project security maintainers.
3. Include reproducible steps, sample payloads, and environmental details.
4. Security patches will be reviewed and deployed within 48 business hours.
