# OWASP Path Traversal & Safe File Access Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)
Classification: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-23, CWE-36, CWE-73

---

## 1. Executive Summary & Threat Architecture
Path Traversal (also designated as Directory Traversal, Dot-Dot-Slash attack, or Arbitrary File Access) represents a critical structural flaw occurring when an application consumes untrusted, user-controllable input to construct filesystem paths without rigorous canonicalization, boundary validation, and privilege segregation.

An adversary who successfully exploits path traversal can break out of the intended web root or application storage boundary, enabling:
1. **Confidentiality Breach**: Unauthorized exfiltration of sensitive configuration credentials (e.g., `application.yml`, `.env`, database passwords, private cryptographic keys, `/etc/passwd`, `/etc/shadow`, Windows SAM registry hives).
2. **Integrity Violation & Remote Code Execution (RCE)**: Arbitrary file writing and overwriting, such as deploying webshells into executable web roots, overwriting system binaries, poisoning cron jobs (`/etc/cron.d/`), replacing configuration files, or exploiting archive extraction vulnerabilities (Zip Slip).
3. **Availability Disruption**: Overwriting essential application libraries, altering state files, or exhausting server storage through unbounded write primitives.

---

## 2. Comprehensive Attack Vectors & Bypass Taxonomy

### 2.1 Basic Path Manipulation
Adversaries insert relative directory stepping sequences (`../` on POSIX or `..\` on Microsoft Windows) to navigate up the directory hierarchy towards the root directory:
- `../../../../etc/passwd`
- `..\..\..\..\Windows\System32\drivers\etc\hosts`
- `../../../../var/log/nginx/access.log`

### 2.2 Encoding and Filter Evasion Techniques
Naïve sanitizers that merely strip `../` once or check for literal dot-dot sequences can be bypassed via:
- **Nested Traversal Sequences**: `....//` or `..././` where single-pass deletion of `../` collapses the remaining text into a new valid traversal token (`../`).
- **Standard URL Hex Encoding**: `%2e%2e%2f` (`../`), `%2e%2e%255c` (`..\`), `%2f` (`/`).
- **Double URL Encoding**: `%252e%252e%252f` or `%252e%252e%255c` (frequently decoded once by an API gateway / reverse proxy and a second time by the backend web framework).
- **Unicode and Overlong UTF-8 Encoding**:
  - `%c0%ae%c0%ae%c0%af` (overlong representation of `../`)
  - `%uff0e%uff0e%u2215` (full-width Unicode variants)
- **Null-Byte Injection (Legacy platforms & C-bindings)**: `%00` or `\x00` used to terminate filename strings in underlying C system calls, bypassing suffix checks (e.g., `input.pdf\x00.jpg`).

### 2.3 Absolute Path Hijacking
In many standard programming libraries, combining a base directory with an absolute user-supplied path causes the library to discard the base directory entirely:
- **Python `os.path.join` Trap**:
  ```python
  # DANGEROUS: If user_input begins with '/', base_dir is ignored!
  os.path.join("/var/app/uploads", "/etc/passwd")  # Evaluates to "/etc/passwd"
  ```
- **Java `Path.resolve` Trap**:
  ```java
  // DANGEROUS: If userPath is absolute, resolve returns userPath directly!
  Paths.get("/var/app/uploads").resolve("/etc/shadow"); // Evaluates to "/etc/shadow"
  ```

### 2.4 Windows Filesystem Specifics
- **Universal Naming Convention (UNC) Paths**: `\\attacker-controlled-host\share\malicious.dll` or `\\127.0.0.1\c$\Windows\win.ini`.
- **Alternate Data Streams (ADS)**: `secret.txt::$DATA` or `document.pdf:hidden_stream`.
- **Reserved Device Identifiers**: Filenames such as `CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`, and `LPT1` through `LPT9` cause system-level locks, hangs, or unexpected handling on Windows servers.

### 2.5 Archive Extraction Vulnerabilities (Zip Slip)
Zip, Tar, and Jar archive formats permit file path entries containing directory traversal sequences. If an unarchiving utility extracts files by naively concatenating the destination folder with `ZipEntry.getName()` or `tarinfo.name`, files will be written outside the target extraction directory, leading directly to arbitrary file overwrite and remote code execution.

---

## 3. Defense-in-Depth Mitigation Architecture

To completely eliminate path traversal vulnerabilities, applications must enforce a layered defense model:

```
[ Incoming File Request ]
          │
          ▼
┌──────────────────────────────────────────────┐
│ Layer 1: Indirect File Referencing (UUID/DB) │ -> Best Practice (No file paths from user)
└──────────────────────────────────────────────┘
          │ (If direct filenames required)
          ▼
┌──────────────────────────────────────────────┐
│ Layer 2: Strict Character & Suffix Allowlists│ -> Reject slashes, backslashes, control chars
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ Layer 3: Canonical Resolution & Boundary     │ -> Resolve symlinks, assert target is relative
│          Containment Verification            │    to designated root (is_relative_to/startsWith)
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ Layer 4: Principle of Least Privilege        │ -> Sandboxed storage, read-only mounts,
│          & System Hardening                  │    isolated non-root OS user accounts
└──────────────────────────────────────────────┘
```

### Core Defense Principles:
1. **Prefer Indirect References**: Store uploaded files under randomly generated UUIDs (e.g., `UUIDv4`) on disk and store metadata (original filename, user ID, MIME type) in an authoritative database table. Never allow clients to reference disk files via direct filesystem paths.
2. **Enforce Character Allowlists**: Filenames should strictly match a conservative alphanumeric whitelist: `^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$`. Strictly prohibit path delimiters (`/`, `\`), null bytes (`\x00`), and leading periods.
3. **Canonicalize Before Boundary Verification**: Always resolve all relative elements and symbolic links to obtain the true canonical path (`Path.resolve()` in Python, `Path.toRealPath()` in Java), and verify that the canonical path starts with the designated base directory.
4. **Isolate File Storage Outside the Web Root**: Never store user-uploaded files inside the web root, public document root, or classpath directories. Serve files through an authenticated streaming controller or signed object storage URLs (e.g., Amazon S3 Presigned URLs).

---

## 4. Vulnerable vs. Secure Implementations in Python

### 4.1 Vulnerable Python Patterns

```python
# ==============================================================================
# VULNERABLE PYTHON PATTERNS -- DO NOT USE IN PRODUCTION
# ==============================================================================
import os
from flask import Flask, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/var/app/data/uploads"

@app.route("/download_bad_1")
def download_file_vulnerable_1():
    # Flaw 1: Direct concatenation without sanitization allows ../ sequences
    filename = request.args.get("file")
    target_path = UPLOAD_DIR + "/" + filename
    return send_file(target_path)

@app.route("/download_bad_2")
def download_file_vulnerable_2():
    # Flaw 2: os.path.join discards UPLOAD_DIR if filename starts with '/'
    filename = request.args.get("file")
    target_path = os.path.join(UPLOAD_DIR, filename)  # E.g. filename = "/etc/passwd"
    with open(target_path, "rb") as f:
        return f.read()

@app.route("/download_bad_3")
def download_file_vulnerable_3():
    # Flaw 3: Ineffective string replacement allows nested bypass (e.g. "....//")
    filename = request.args.get("file").replace("../", "")
    target_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(target_path)
```

### 4.2 Secure Enterprise Python Implementation

```python
"""
Enterprise Secure File Access & Storage Service (Python 3.11+)
Compliant with OWASP Path Traversal Prevention Guidelines (2026 Edition).
"""

from pathlib import Path
import re
import uuid
import mimetypes
from typing import BinaryIO, Optional

# Enforce strict canonicalization of the base directory on service startup
BASE_STORAGE_ROOT = Path("/var/app/data/storage").resolve(strict=True)

# Whitelist pattern for allowable file names (no path separators, no leading dots)
SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]{0,254}$")
SAFE_EXTENSION_REGEX = re.compile(r"^\.(pdf|png|jpg|jpeg|docx|xlsx|txt)$", re.IGNORECASE)


class SecureFileStorageService:
    def __init__(self, root_dir: Path = BASE_STORAGE_ROOT):
        self._root_dir = root_dir.resolve(strict=True)
        if not self._root_dir.is_dir():
            raise RuntimeError(f"Base storage directory {self._root_dir} is invalid")

    def validate_filename_metadata(self, raw_filename: str) -> str:
        """
        Validates that the raw filename does not contain path separators,
        path traversal tokens, or unapproved file extensions.
        """
        if not raw_filename or len(raw_filename) > 255:
            raise ValueError("Filename length is invalid or empty")

        # Reject path separators explicitly before regex
        if "/" in raw_filename or "\\" in raw_filename or "\x00" in raw_filename:
            raise ValueError("Forbidden path separator or null byte detected in filename")

        if not SAFE_FILENAME_REGEX.match(raw_filename):
            raise ValueError("Filename contains prohibited characters")

        ext = Path(raw_filename).suffix.lower()
        if not SAFE_EXTENSION_REGEX.match(ext):
            raise ValueError(f"File extension '{ext}' is not authorized")

        return raw_filename

    def resolve_safe_path(self, relative_user_path: str) -> Path:
        """
        Canonicalizes the user path and rigorously asserts containment within root.
        """
        clean_name = self.validate_filename_metadata(relative_user_path)
        
        # Combine using Path operator
        candidate_path = (self._root_dir / clean_name).resolve()

        # Strict containment verification (Python 3.9+ is_relative_to)
        if not candidate_path.is_relative_to(self._root_dir):
            raise PermissionError(f"Path traversal detected: {candidate_path} outside {self._root_dir}")

        return candidate_path

    def read_secure_file(self, relative_user_path: str) -> bytes:
        """
        Reads verified file contents after ensuring the file is an authentic regular file.
        """
        safe_path = self.resolve_safe_path(relative_user_path)

        if not safe_path.exists():
            raise FileNotFoundError("Requested resource does not exist")

        if not safe_path.is_file():
            raise PermissionError("Target resource is not a standard file")

        # Prohibit following symbolic links outside containment root
        if safe_path.is_symlink():
            real_target = safe_path.resolve(strict=True)
            if not real_target.is_relative_to(self._root_dir):
                raise PermissionError("Symbolic link breakout detected")

        return safe_path.read_bytes()

    def store_file_indirect(self, file_stream: BinaryIO, original_filename: str) -> str:
        """
        Stores an uploaded file using an opaque UUID, avoiding client-specified disk paths.
        """
        clean_name = self.validate_filename_metadata(original_filename)
        ext = Path(clean_name).suffix.lower()
        
        # Generate random storage key
        storage_uuid = str(uuid.uuid4())
        stored_filename = f"{storage_uuid}{ext}"
        target_path = self._root_dir / stored_filename

        with open(target_path, "wb") as destination:
            while chunk := file_stream.read(64 * 1024):
                destination.write(chunk)

        return storage_uuid
```

---

## 5. Vulnerable vs. Secure Implementations in Java

### 5.1 Vulnerable Java Patterns

```java
// ==============================================================================
// VULNERABLE JAVA PATTERNS -- DO NOT USE IN PRODUCTION
// ==============================================================================
import java.io.*;
import javax.servlet.http.*;

public class VulnerableFileServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/app/uploads/";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");

        // Flaw 1: Direct File construction vulnerable to ../ and ..\ traversal
        File file = new File(BASE_DIR + filename);
        
        // Flaw 2: Direct unverified FileInputStream reads arbitrary system files
        FileInputStream fis = new FileInputStream(file);
        fis.transferTo(resp.getOutputStream());
        fis.close();
    }
}
```

### 5.2 Secure Enterprise Java Implementation (NIO.2)

```java
package com.enterprise.security.storage;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Enterprise Secure File Storage Service (Java 17/21+)
 * Compliant with OWASP Path Traversal Prevention Standards (2026 Edition).
 */
public final class SecureFileStorageService {

    private static final Pattern SAFE_FILENAME_PATTERN = 
            Pattern.compile("^[a-zA-Z0-9_\\-][a-zA-Z0-9_\\-.]{0,254}$");

    private final Path baseStorageDirectory;

    public SecureFileStorageService(Path rootStoragePath) throws IOException {
        Objects.requireNonNull(rootStoragePath, "Root storage path cannot be null");
        // Canonicalize the root directory during service initialization
        this.baseStorageDirectory = rootStoragePath.toRealPath();
        
        if (!Files.isDirectory(this.baseStorageDirectory)) {
            throw new IllegalArgumentException("Base storage path must be an active directory");
        }
    }

    /**
     * Sanitizes and verifies user input filename.
     */
    public String validateFilename(String rawFilename) {
        if (rawFilename == null || rawFilename.isBlank()) {
            throw new SecurityException("Filename cannot be blank or null");
        }
        if (rawFilename.contains("/") || rawFilename.contains("\\") || rawFilename.contains("\0")) {
            throw new SecurityException("Illegal path separator or null byte detected");
        }
        if (!SAFE_FILENAME_PATTERN.matcher(rawFilename).matches()) {
            throw new SecurityException("Filename violates security whitelist policy");
        }
        return rawFilename;
    }

    /**
     * Resolves the target file path and performs strict directory boundary containment check.
     */
    public Path resolveSecurePath(String userInputFilename) throws IOException {
        String cleanName = validateFilename(userInputFilename);

        // Normalize eliminates any relative references
        Path resolvedPath = this.baseStorageDirectory.resolve(cleanName).normalize();

        // Enforce boundary containment check before performing any I/O operation
        if (!resolvedPath.startsWith(this.baseStorageDirectory)) {
            throw new SecurityException("Access outside safe directory boundary is prohibited");
        }

        // Verify the real physical target on disk (resolves symbolic links)
        if (Files.exists(resolvedPath)) {
            Path realPath = resolvedPath.toRealPath(LinkOption.NOFOLLOW_LINKS);
            if (!realPath.startsWith(this.baseStorageDirectory)) {
                throw new SecurityException("Symbolic link points outside storage boundary");
            }
            return realPath;
        }

        return resolvedPath;
    }

    /**
     * Safely reads file bytes with comprehensive boundary and type verification.
     */
    public byte[] loadFileBytes(String userInputFilename) throws IOException {
        Path safePath = resolveSecurePath(userInputFilename);

        if (!Files.exists(safePath)) {
            throw new NoSuchFileException("Requested file was not found");
        }
        if (!Files.isRegularFile(safePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("Requested target is not a standard regular file");
        }

        return Files.readAllBytes(safePath);
    }
}
```

---

## 6. Secure Archive Extraction (Zip Slip Defense)

### 6.1 Vulnerable Zip Slip in Java
```java
// VULNERABLE: Zip Slip allows overwriting critical system files
ZipInputStream zis = new ZipInputStream(new FileInputStream("untrusted.zip"));
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File newFile = new File(destinationDir, entry.getName()); // entry.getName() can be "../../evil.sh"
    FileOutputStream fos = new FileOutputStream(newFile);
    zis.transferTo(fos);
    fos.close();
}
```

### 6.2 Secure Zip Slip Defense in Java
```java
public static void extractArchiveSafely(Path destinationDir, InputStream zipStream) throws IOException {
    Path canonicalDest = destinationDir.toRealPath();
    try (ZipInputStream zis = new ZipInputStream(zipStream)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // Resolve and normalize each entry path
            Path targetPath = canonicalDest.resolve(entry.getName()).normalize();

            // Strict containment verification
            if (!targetPath.startsWith(canonicalDest)) {
                throw new SecurityException("Zip Slip attack detected: " + entry.getName());
            }

            if (entry.isDirectory()) {
                Files.createDirectories(targetPath);
            } else {
                Files.createDirectories(targetPath.getParent());
                Files.copy(zis, targetPath, StandardCopyOption.REPLACE_EXISTING);
            }
            zis.closeEntry();
        }
    }
}
```

---

## 7. Static Code Analysis (SAST) Detection Rules

| Engine Rule ID | Language | Severity | Trigger Condition / Heuristic |
|---|---|---|---|
| `PATH-PY-001` | Python | High | `open()`, `send_file()`, `Path()` taking unvalidated parameters or string concatenation |
| `PATH-PY-002` | Python | High | `os.path.join()` invoked with user-supplied arguments lacking boundary validation |
| `PATH-PY-003` | Python | High | `zipfile.ZipFile.extractall()` without traversal sequence verification |
| `PATH-JV-001` | Java | High | `new File(base + input)` or `Paths.get(input)` without `startsWith(baseDir)` check |
| `PATH-JV-002` | Java | High | `ZipInputStream.getNextEntry()` followed by file creation without canonicalization check |
| `PATH-JV-003` | Java | Medium | Use of `File.getPath()` instead of `File.getCanonicalPath()` in access control decisions |

---

## 8. OWASP 2026 Security Verification Checklist

- [ ] **Indirect Key Identification**: Are all stored files identified via internal UUIDs or database IDs rather than direct user-supplied names?
- [ ] **Input Sanitization**: Are filenames strictly validated using an alphanumeric whitelist, discarding slashes (`/`, `\`) and null characters (`\0`)?
- [ ] **Canonicalization Verification**: Are all candidate file paths resolved to real canonical paths (`toRealPath()` or `Path.resolve()`) before file access?
- [ ] **Prefix Boundary Enforcement**: Is `path.startsWith(baseDirectory)` or `path.is_relative_to(baseDirectory)` explicitly asserted on every file operation?
- [ ] **Symlink Traversal Prevention**: Are symbolic links checked (`LinkOption.NOFOLLOW_LINKS` / `is_symlink()`) to prevent escaping directory boundaries?
- [ ] **Zip Slip Protection**: Do archive extraction routines (Zip, Tar, Jar) validate entry names prior to disk writes?
- [ ] **Minimal OS Privileges**: Is the application executing under a non-root, restricted service user with minimal filesystem write permissions?
- [ ] **Storage Segregation**: Are upload and temporary directories positioned completely outside the web root and classpath?
