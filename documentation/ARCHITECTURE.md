# System Architecture & Technical Specifications

This document outlines the architectural blueprints, component interactions, safety models, and mathematical formulations powering the **Smart Code Inspection Platform with Vulnerability Detection System**.

---

## 1. High-Level Architecture Overview

The platform uses a decoupled client-server architecture consisting of a **React 19 single-page dashboard** communicating over standard RESTful endpoints with a **Flask API**. The system enforces static analysis without executing user-supplied source code.

```mermaid
graph TB
    subgraph Client["Frontend Client (React 19 + Vite 8)"]
        UI["Cybersecurity Dashboard UI"]
        Editor["Monospaced Code Editor & Samples"]
        FindingsView["Severity-Categorized Findings Panel"]
        DiagnosticsView["Compiler Diagnostics Panel"]
        KBView["OWASP Vector Retrieval Panel"]
        AIModal["AI Advisory Modal (Disclosed)"]
    end

    subgraph Transport["REST Communication Layer"]
        CORS["Flask CORS Middleware"]
        Blueprints["Modular API Blueprints (/api/validate, /api/analyze, /api/orchestrate, etc.)"]
    end

    subgraph Orchestrator["Multi-Agent Orchestrator Engine"]
        direction TB
        CodeAgent["Code Analysis Agent (Smells, Complexity, Anti-Patterns)"]
        SecAgent["Security Vulnerability Agent (OWASP 2026, CWE Mappings)"]
        Merger["Unified Findings Aggregator (Deduplication, Security Grade, Quality Score)"]
        CodeAgent & SecAgent --> Merger
    end

    subgraph Engines["Core Inspection & Intelligence Engines"]
        PV["Python AST Validator (ast.parse)"]
        JV["Java javac Validator (Compiler Isolation)"]
        PR["Python Rule Engine (AST + Regex)"]
        JR["Java Rule Engine (Contextual Regex)"]
        VS["Zero-DLL TF-IDF Vector Engine"]
        CDB["ChromaDB Semantic Vector Index"]
        PDF["ReportLab PDF Document Builder"]
        AI["AI Advisory Agent (Gemini / Groq / Offline)"]
    end

    subgraph Knowledge["Authentic OWASP 2026 Knowledge Base"]
        OWASPDocs["15 Authentic OWASP Documents (.md)<br/>(10 Documents >= 300 Lines Each)"]
        SourcesJSON["sources.json Metadata Catalog"]
        PrecomputedIndex["vector_index.json & chunks_metadata.json (521+ Chunks)"]
    end

    UI -->|HTTP / JSON| Transport
    Transport --> Blueprints
    Blueprints --> Orchestrator
    Blueprints --> Engines
    Orchestrator --> Engines
    Engines --> Knowledge
```

---

## 2. Validation & Static Inspection Pipeline

### 2.1 Python AST Parser (`validators/python_validator.py`)
Python validation leverages Python's native `ast.parse` standard library module:
- **Zero Dynamic Execution**: `ast.parse` constructs an in-memory Abstract Syntax Tree representation of the code without executing module-level statements, functions, side effects, or imports.
- **Payload Size Ceiling**: Enforces a strict default byte limit (`200,000` bytes, configurable via `MAX_SOURCE_BYTES`) to prevent memory exhaustion.
- **Diagnostic Mapping**: Syntax errors throw standard `SyntaxError` exceptions containing accurate `lineno`, `offset`, and the exact code line excerpt, which are normalized into the platform's diagnostic schema:
  ```json
  {
    "line": 4,
    "column": 48,
    "severity": "error",
    "message": "SyntaxError: '(' was never closed",
    "evidence": "final_price = price * (1 - (discount_percent / 100)"
  }
  ```

### 2.2 Java Compiler Isolation (`validators/java_validator.py`)
Java code is validated using the local OpenJDK compiler (`javac`):
- **Temporary Isolation**: The source code is written to an isolated directory created via `tempfile.mkdtemp(prefix="sci_java_")`.
- **Primary Class Extraction**: The validator parses public class, record, interface, or enum names using regex while stripping comments (`//` and `/* ... */`), naming the `.java` file accurately to satisfy Java compiler specification requirements.
- **Execution Flags**: The compiler is invoked with:
  ```bash
  javac -d <temp_dir> -Xlint:all <SourceFile>.java
  ```
- **Bytecode Non-Execution**: The compiler outputs compiled `.class` bytecode to the temporary directory solely to verify type safety and language compliance; **bytecode is never executed** (`java` runtime is never invoked on user code).
- **Subprocess Security**: Invoked via `subprocess.run` with argument lists (never `shell=True`) and a strict 10-second timeout ceiling (`subprocess.TimeoutExpired`).
- **Diagnostic Regex Parser**: Captures compiler output matching:
  ```regex
  ^([a-zA-Z0-9_\-\.]+):(\d+):(?:\s*(\w+):)?\s*(.*)$
  ```
  Extracts precise line numbers, columns, and severity levels (`error` vs `warning`).

---

## 3. Deterministic Security Rulebook

The platform implements 11 deterministic security inspection rules across Python and Java:

| Rule ID | Language | Description | Detection Strategy | OWASP Top 10 Standard |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-PY-001` | Python | Unsafe `eval()` / `exec()` | AST `Call` node inspecting `func.id` | A03:2021-Injection |
| `SEC-PY-002` | Python | OS Command Injection | AST `Call` node with `shell=True` keyword argument | A03:2021-Injection |
| `SEC-PY-003` | Python | SQL Injection | AST `Call` matching `execute` + String Formatting (`FormattedValue`, `%`, `.format`) | A03:2021-Injection |
| `SEC-PY-004` | Python | Hardcoded Secrets | High-entropy regex patterns matching secret variable names & API keys | A07:2021-Identification |
| `SEC-PY-005` | Python | Insecure Deserialization | AST `Call` matching `pickle.loads` / `pickle.load` | A08:2021-Integrity |
| `SEC-PY-006` | Python | Broken Cryptographic Hash | AST `Call` matching `hashlib.md5()` / `hashlib.sha1()` | A02:2021-Cryptographic |
| `SEC-JV-001` | Java | SQL Injection Concatenation | Regex matching `executeQuery` / `executeUpdate` with `+` concatenations | A03:2021-Injection |
| `SEC-JV-002` | Java | OS Command Injection | Regex matching `Runtime.getRuntime().exec` / `ProcessBuilder` | A03:2021-Injection |
| `SEC-JV-003` | Java | Hardcoded Secrets | High-entropy regex matching `AWS_SECRET`, `API_KEY`, `PASSWORD` assignments | A07:2021-Identification |
| `SEC-JV-004` | Java | Insecure Deserialization | Regex matching `ObjectInputStream.readObject()` | A08:2021-Integrity |
| `SEC-JV-005` | Java | Weak Cryptographic Hash | Regex matching `MessageDigest.getInstance("MD5")` or `"SHA-1"` | A02:2021-Cryptographic |

---

## 4. Multi-Agent Orchestration Architecture (`agents/orchestrator.py`)

The platform implements an asynchronous multi-agent architecture where specialized agents evaluate submitted code in parallel:

```
                          [ Client Code Submission ]
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │  MultiAgentOrchestrator   │
                        │   (ThreadPoolExecutor)    │
                        └─────────────┬─────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
     ┌───────────────────────────┐         ┌───────────────────────────┐
     │    Code Analysis Agent    │         │Security Vulnerability Agt │
     │  (AST & Structural Smell) │         │  (OWASP Standards & CWE)  │
     └─────────────┬─────────────┘         └─────────────┬─────────────┘
                   │                                     │
                   └──────────────────┬──────────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Findings Merger & Dedup   │
                        │ - Category-Aware Keying   │
                        │ - Posture Grade (A - F)   │
                        │ - Quality Score (0 - 100) │
                        └───────────────────────────┘
```

### 4.1 Code Analysis Agent (`agents/code_analysis_agent.py`)
- **Code Smell Detection**: Identifies bloated methods/functions, excessive parameter lists (> 5 parameters), cognitive nesting complexity (> 3 levels), and duplicated logic.
- **Complexity Metrics**: Cyclomatic complexity branching points (`if`, `for`, `while`, boolean operator chains).
- **Resource Management Leaks**: Detects unclosed file descriptors, missing `with` statement context managers, and unclosed Java streams.
- **Defensive Rules**: `COMPLEX-PY-001`, `SMELL-PY-001` through `002`, `PRACTICE-PY-001` through `006`, `COMPLEX-JV-001` through `003`, `SMELL-JV-001` through `002`, `PRACTICE-JV-001` through `005`.

### 4.2 Security Vulnerability Agent (`agents/security_agent.py`)
- **OWASP 2026 Standards**: Scans for OWASP Top 10 vulnerabilities, exact CWE mappings (CWE-22, CWE-78, CWE-89, CWE-502, CWE-798, CWE-918).
- **SSRF Detection**: Evaluates URL construction, outbound HTTP client calls, scheme allowlists, and link-local IP targets (`169.254.169.254`).
- **Path Traversal**: Canonical containment verification (`is_relative_to`, `toRealPath`), dot-dot-slash sequence detection, Zip Slip prevention.
- **XXE and Insecure XML**: Scans Java `DocumentBuilderFactory` and `SAXParserFactory` for missing `disallow-doctype-decl` features.

### 4.3 Aggregation, Deduplication & Scoring
- **Category-Aware Deduplication**: Merges findings using a composite key `(rule_id, category, line)` ensuring distinct quality and security findings on the same line are both preserved.
- **Security Posture Grade**: Evaluates security-specific findings independently (High/Critical findings yield 'F'; Medium findings yield 'C' or 'D'; 0 security findings yield 'A').
- **Quality Score**: Deducts proportional penalties per finding severity, strictly bounded between 0 and 100.

---

## 5. Hybrid Knowledge Retrieval Engine (ChromaDB + Pure Python TF-IDF)

The knowledge retrieval layer provides authentic OWASP remediation guidance using a hybrid architecture:

### 5.1 Document Ingestion & Chunking
- Ingests authentic OWASP Markdown documents from `knowledge_base/documents/` (15 guidelines named `owasp_*.md`, including 10 comprehensive documents with >= 300 lines each covering OWASP Top 10 2026, SSRF Defense, Path Traversal, API Security, Cryptographic Storage, SQL Injection, Deserialization, Secrets Management, Authentication, and Command Injection).
- Splits documents into coherent semantic chunks preserving metadata (Title, Section, Category, Official URL) recorded in `knowledge_base/sources.json`. Total: 521+ indexed chunks across 4,258 vocabulary terms.

### 5.2 Primary Engine: ChromaDB Persistent Store
- Persistent vector collection stored in `knowledge_base/index/chroma/`.
- Fast semantic vector search returning top matching passages.

### 5.3 Fallback Engine: Zero-DLL Pure Python Vector Space Model
To ensure zero external native DLL dependencies in hardened or air-gapped environments:
- Pre-computed TF-IDF index stored in `knowledge_base/index/vector_index.json` and `knowledge_base/index/chunks_metadata.json`.
- **Term Frequency-Inverse Document Frequency (TF-IDF)**:
  $$\text{TF}(t, d) = \frac{f_{t, d}}{\sum_{t' \in d} f_{t', d}}$$
  $$\text{IDF}(t) = \ln\left(1 + \frac{N}{1 + n_t}\right) + 1$$
  $$\text{TF-IDF}(t, d) = \text{TF}(t, d) \times \text{IDF}(t)$$
- **Cosine Similarity Matching**:
  $$\text{Cosine Similarity}(q, d) = \frac{\mathbf{v}_q \cdot \mathbf{v}_d}{\|\mathbf{v}_q\| \|\mathbf{v}_d\|} = \frac{\sum_{t \in q \cap d} w_{t, q} \cdot w_{t, d}}{\sqrt{\sum_{t \in q} w_{t, q}^2} \sqrt{\sum_{t \in d} w_{t, d}^2}}$$

---

## 6. Multi-Provider AI Advisory Subsystem (`agents/ai_provider.py`)

The platform integrates an AI consultation agent with strict security boundaries:
1. **Multi-Provider Support**: Supports **Google Gemini** (`gemini-3.8-flash`) and **Groq** (`llama-3.1-8b-instant`).
2. **Offline Curated Advisory Fallback**: If no API key is configured or rate limits are reached, the system automatically falls back to an offline deterministic advisory generated from the local rulebook.
3. **Rate Limiting & Throttling**: Sliding window rate limiter (10 requests/min maximum) with a 2.0-second inter-request cooldown to respect free-tier quotas.
4. **In-Memory LRU Cache**: SHA-256 caching of finding signatures (`rule_id + title + evidence`) with a 1-hour TTL to prevent duplicate API queries.
5. **Prompt Shielding & Consent Disclosure**: Source code is treated as untrusted data; raw credentials are never transmitted; and the frontend requires explicit user consent before advisory generation.

---

## 6. ReportLab Executive PDF Generator (`reports/pdf_generator.py`)

The report generation pipeline builds downloadable security audit reports:
- **Title Block & Metadata**: Executive summary with target filename, inspection timestamp (UTC), language, compiler status, and tool version.
- **Executive Vulnerability Summary Table**: Color-coded risk breakdown of Total Findings, Critical, High, Medium, and Low/Info vulnerabilities.
- **Detailed Findings Registry**:
  - Rule ID, severity badge, line number.
  - Formatted monospaced code evidence box with secret token masking.
  - Risk implications and step-by-step remediation guidance.
  - Clickable OWASP reference hyperlinks.
  - Wrapped with `KeepTogether` to eliminate awkward page breaks.
- **AI Advisory Section**: Optional AI-generated advisory remediation with explicit advisory disclaimers.
- **Audit Scope & Limitations Stamp**: Legal and compliance disclaimer detailing static analysis boundaries.

---

## 7. REST API Endpoints Specification

| Method | Endpoint | Description | Request Payload | Response Schema |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | System health & AI engine status | None | `{"status": "healthy", "ai_status": {...}}` |
| `POST` | `/api/validate` | Syntax & compiler verification | `{"language", "source_code", "filename"}` | `{"valid_syntax", "diagnostics", "message", "total_lines"}` |
| `POST` | `/api/analyze` | Full security rulebook inspection | `{"language", "source_code", "filename"}` | `{"valid_syntax", "summary", "findings", "diagnostics"}` |
| `GET` | `/api/knowledge/status` | Vector knowledge base status | None | `{"status", "chunks_count", "sources_count"}` |
| `POST` | `/api/knowledge/search` | OWASP semantic vector search | `{"query", "top_k"}` | `{"query", "results": [...]}` |
| `POST` | `/api/ai/explain` | AI finding explanation | `{"finding", "owasp_passages"}` | `{"success", "explanation", "provider", "model"}` |
| `POST` | `/api/reports/pdf` | Downloadable PDF audit report | `{"analysis_data", "source_code", "language"}` | Binary PDF attachment (`application/pdf`) |

---

## 8. Milestone 2: Multi-Agent Orchestration & Quality Engine

Milestone 2 introduces a concurrent multi-agent inspection architecture that simultaneously evaluates code quality and cybersecurity posture.

```mermaid
flowchart LR
    Client["Client Request (/api/analyze)"] --> Orchestrator["Multi-Agent Orchestrator\n(ThreadPoolExecutor)"]
    
    subgraph ParallelAgents["Concurrent Inspection Agents"]
        Orchestrator --> Agent1["🔍 Code Analysis Agent\n- Code Smells (Long Methods, Params, Bloat)\n- Complexity (Cyclomatic, Deep Nesting)\n- Design Anti-Patterns (Mutable Defaults, God Class)\n- Poor Practices (Print, Resource Leaks)"]
        Orchestrator --> Agent2["🛡️ Security Vulnerability Agent\n- OWASP Top 10 (A01–A10)\n- CWE Classifications\n- Precise Location Flagging\n- Severity Scoring (1.0–10.0)"]
    end
    
    Agent1 --> Merge["Unified Findings Merger\n& Deduplication Pipeline"]
    Agent2 --> Merge
    Merge --> Output["Unified Findings Registry\n- Sorted by Severity Score (Desc)\n- Quality Score (0–100)\n- Security Posture Grade (A–F)\n- Agent Telemetry (Duration, Status)"]
```

### 8.1 Code Analysis Agent (`backend/agents/code_analysis_agent.py`)
Inspects syntax and structure for software maintainability and engineering excellence:
- **Code Smells**:
  - `SMELL-PY-001` / `SMELL-JV-001`: Long method / function body smell.
  - `SMELL-PY-002` / `SMELL-JV-002`: Long parameter list (> 5 parameters).
  - `SMELL-PY-003` / `SMELL-JV-003`: Bloated class smell (> 150 lines or > 12 methods).
  - `SMELL-PY-004` / `SMELL-JV-004`: Empty exception / catch handler suppressing runtime errors.
  - `SMELL-PY-005` / `SMELL-JV-005`: Wildcard namespace / package imports.
- **Complexity Issues**:
  - `COMPLEX-PY-001` / `COMPLEX-JV-001`: High Cyclomatic Complexity (McCabe metric > 8).
  - `COMPLEX-PY-002` / `COMPLEX-JV-002`: Deep Control Flow Nesting (Arrow anti-pattern depth >= 4).
  - `COMPLEX-PY-003` / `COMPLEX-JV-003`: Complex Boolean Expressions (>= 3 chained operators).
- **Design Anti-Patterns**:
  - `DESIGN-PY-001`: Mutable default argument trap in Python (`def f(x=[])`).
  - `DESIGN-PY-002` / `DESIGN-JV-002`: God Class / God Function anti-pattern.
  - `DESIGN-PY-003` / `DESIGN-JV-001`: Generic catch-all exception (`except Exception` / `catch (Exception e)`).
  - `DESIGN-PY-004`: Magic numbers embedded in business logic without named constants.
- **Poor Coding Practices**:
  - `PRACTICE-PY-001` / `PRACTICE-JV-001`: Console printing (`print`, `System.out.println`, `printStackTrace`) left in production.
  - `PRACTICE-PY-002` / `PRACTICE-JV-002`: Unmanaged I/O stream / file resource leaks (missing `with` or try-with-resources).
  - `PRACTICE-PY-003` / `PRACTICE-JV-003`: Language style guide naming convention violations (PEP 8 / Java camelCase).
  - `PRACTICE-PY-004`: Missing docstrings on substantial classes and functions (> 15 lines).

### 8.2 Security Vulnerability Agent (`backend/agents/security_agent.py`)
Enforces OWASP Top 10 standards with exact location flagging, CWE mapping, and severity scoring:
- `SEC-PY-001` / `SEC-JV-002`: Dynamic Code Execution / Command Injection (`eval`, `subprocess`, `Runtime.exec`) [CWE-95, CWE-78 | OWASP A03:Injection]
- `SEC-PY-003` / `SEC-JV-001`: SQL Injection via dynamic string formatting / query concatenation [CWE-89 | OWASP A03:Injection]
- `SEC-PY-004` / `SEC-JV-003`: Hardcoded API Credentials & Passwords [CWE-798 | OWASP A07:Identification]
- `SEC-PY-005` / `SEC-JV-004`: Insecure Deserialization (`pickle.loads`, `ObjectInputStream`) [CWE-502 | OWASP A08:Integrity]
- `SEC-PY-006` / `SEC-JV-005`: Broken / Weak Cryptographic Hashes (`MD5`, `SHA-1`, `DES`) [CWE-327 | OWASP A02:Crypto]
- `SEC-PY-007` / `SEC-JV-006`: Path Traversal / Arbitrary File Access (`os.path.join`, Java `File`) [CWE-22 | OWASP A01:Access Control]
- `SEC-PY-008`: Server-Side Request Forgery (`requests.get` with user target) [CWE-918 | OWASP A10:SSRF]
- `SEC-JV-007`: Insecure XML Parser Configuration / XXE (`DocumentBuilderFactory`) [CWE-611 | OWASP A05:Misconfiguration]

### 8.3 Multi-Agent Orchestrator (`backend/agents/orchestrator.py`)
- **Parallel Concurrency**: Uses `concurrent.futures.ThreadPoolExecutor(max_workers=2)` to run both agents concurrently.
- **Unified Findings Merging**: Merges, deduplicates, and sorts findings descending by `severity_score` (Critical 9.5 -> Low 2.5), then by source line.
- **Scoring Formulas**:
  - **Code Quality Score** (0–100):
    $$\text{Quality Score} = \max\left(0, 100 - \sum \text{Quality Penalties}\right)$$
  - **Security Posture Grade**:
    - `Grade A`: 0 Critical, 0 High findings
    - `Grade B`: 0 Critical, 0 High, Medium findings present
    - `Grade C`: 0 Critical, 1–2 High findings
    - `Grade D`: 0 Critical, > 2 High findings
    - `Grade F`: Critical findings detected

