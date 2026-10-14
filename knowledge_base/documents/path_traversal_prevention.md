# OWASP Path Traversal & Safe File Access Cheat Sheet

Source: https://owasp.org/www-community/attacks/Path_Traversal
Retrieved: 2026-10-12
Author: OWASP Cheat Sheet Series Team
Topic: Path Traversal & Safe File Operations

## Introduction
Path Traversal (also known as Directory Traversal or Dot-Dot-Slash attack) occurs when an application uses user-controllable input to construct file paths without proper sanitization or boundary verification. Attackers exploit this to read or write files outside the intended target directory, accessing sensitive source code, configuration files, system credentials, or overwriting application binaries.

## Attack Vectors
1. **Dot-Dot-Slash Sequences:** Input containing `../../etc/passwd` or `..\..\windows\system32\config\sam`.
2. **URL and Unicode Encoding Bypass:** Patterns like `%2e%2e%2f`, `..%252f`, or null-byte injections (`%00`) in legacy platforms.
3. **Absolute Path Overwrites:** Passing `/etc/shadow` or `C:\boot.ini` directly into path join methods that overwrite the base root prefix.

## Prevention and Defense Techniques

### 1. Canonicalization and Boundary Verification
Always resolve paths to their canonical, absolute representation (`Path.resolve()` in Python or `Path.normalize().toRealPath()` in Java) and verify that the target path begins strictly within the intended base directory.

### Secure Python Implementation
```python
from pathlib import Path

BASE_STORAGE_DIR = Path("/var/app/data/uploads").resolve()

def safe_read_user_file(filename: str) -> bytes:
    # Reject path separators in bare filenames
    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid filename structure")

    target_file = (BASE_STORAGE_DIR / filename).resolve()
    
    # Boundary check: ensure target path is within base storage directory
    if not target_file.is_relative_to(BASE_STORAGE_DIR):
        raise PermissionError("Path traversal attempt detected")

    if not target_file.is_file():
        raise FileNotFoundError("Requested file does not exist")

    return target_file.read_bytes()
```

### Secure Java Implementation
```java
import java.nio.file.*;
import java.io.IOException;

public class FileService {
    private final Path baseDir = Paths.get("/var/app/uploads").toRealPath();

    public byte[] loadFile(String userFilename) throws IOException {
        Path targetPath = baseDir.resolve(userFilename).normalize().toRealPath();
        if (!targetPath.startsWith(baseDir)) {
            throw new SecurityException("Access outside safe directory boundary prohibited");
        }
        return Files.readAllBytes(targetPath);
    }
}
```

## Remediation Guidelines
- Avoid using direct user input to locate files; store file descriptors or GUIDs in a database table mapping to disk paths.
- Run the application process under a dedicated non-privileged user account with minimal filesystem read/write privileges.
