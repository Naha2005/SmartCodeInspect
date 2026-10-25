# OWASP OS Command Injection Defense Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)

## 1. Introduction and Threat Landscape
Command Injection (classified under CWE-77 and CWE-78) occurs when an application passes unsafe user-supplied data to a system shell (e.g., `/bin/sh`, `/bin/bash`, `cmd.exe`, or `powershell.exe`). In this vulnerability, the attacker-supplied operating system commands are executed with the privileges of the vulnerable application.

Command injection is considered a **Critical** severity flaw (often scoring CVSS 9.8–10.0) because it grants adversaries immediate remote code execution (RCE) on the underlying host, allowing them to:
- Download and execute rootkits, ransomware, and reverse shells.
- Exfiltrate sensitive environment variables, database credentials, and cloud metadata tokens.
- Pivot across internal networks, container networks, and Kubernetes clusters.
- Establish persistence via cron jobs, scheduled tasks, or unauthorized SSH authorized keys.

---

## 2. Anatomy of Shell Metacharacter Interpretation

Operating system shells do not treat input strings as plain characters. They parse command lines and assign special syntactic meaning to shell metacharacters:

### 2.1 Unix / Linux POSIX Shell Metacharacters
- `;` (Command separator): `cat file.txt; id`
- `&` and `&&` (Background / Boolean AND): `ping 8.8.8.8 && cat /etc/passwd`
- `|` and `||` (Pipe / Boolean OR): `ls non_existent || whoami`
- `` `command` `` and `$(command)` (Command substitution): `echo "User is $(whoami)"`
- `>` and `>>` (Output redirection): `echo "compromised" > /var/www/html/defaced.html`
- `<` and `<<` (Input redirection): `mail admin < /etc/shadow`
- `\n` (Newline): Interpreted as a hard command terminator, executing multiple commands sequentially.
- `*` and `?` (Globbing / Wildcards): Can expand to arbitrary filenames or trigger command-line argument injection.

### 2.2 Windows Command Shell (cmd.exe / PowerShell) Metacharacters
- `&` and `&&` (Command concatenation): `dir & whoami`
- `|` (Pipe): `type file.txt | findstr secret`
- `^` (Escape character): `c^a^t f^i^l^e`
- `%VAR%` (Variable expansion): Leaks sensitive environment variables.
- `;` (PowerShell command separator).

---

## 3. The Core Golden Rule: Avoid System Shells Entirely

The single most effective defense against command injection is to **never invoke system shells**. In over 95% of software architectures, invoking an operating system utility via a shell is an unnecessary anti-pattern where a native programming language API or third-party library already exists.

### 3.1 Prefer Native Language APIs Over Shell Utilities

| Shell Command Task | Vulnerable Shell Invocation | Safe Native Python API | Safe Native Java API |
| :--- | :--- | :--- | :--- |
| **Delete file** | `rm -f <file>` | `os.remove(path)` | `Files.deleteIfExists(path)` |
| **Copy file** | `cp <src> <dst>` | `shutil.copy2(src, dst)` | `Files.copy(src, dst)` |
| **Create directory** | `mkdir -p <dir>` | `os.makedirs(path, exist_ok=True)` | `Files.createDirectories(path)` |
| **Compress archive** | `zip -r out.zip <dir>` | `shutil.make_archive()` / `zipfile` | `java.util.zip.ZipOutputStream` |
| **Network HTTP** | `curl <url>` | `requests.get()` / `httpx` | `java.net.http.HttpClient` |
| **Process lookup** | `ps aux \| grep <name>` | `psutil.process_iter()` | `ProcessHandle.allProcesses()` |
| **Compute hash** | `md5sum <file>` | `hashlib.sha256()` | `MessageDigest.getInstance()` |

---

## 4. Python Command Execution: Vulnerable vs Secure Patterns

### 4.1 Prohibited Functions in Python
The following functions invoke an intermediate shell or interpret command strings dynamically and are strictly flagged under rule `SEC-PY-002`:
- `os.system(cmd)`
- `os.popen(cmd)`
- `subprocess.Popen(cmd, shell=True)`
- `subprocess.call(cmd, shell=True)`
- `subprocess.run(cmd, shell=True)`
- `subprocess.check_output(cmd, shell=True)`

### 4.2 Vulnerable Python Pattern
```python
# VULNERABLE: Invoking shell with concatenated user input (CWE-78 / OWASP A03)
import os
import subprocess
from flask import request

@app.route("/api/ping", methods=["POST"])
def ping_server():
    target_host = request.json.get("host") # Attacker sends: "8.8.8.8; cat /etc/passwd"
    
    # CRITICAL RCE: os.system executes through /bin/sh
    os.system("ping -c 1 " + target_host)

    # CRITICAL RCE: shell=True passes full string to shell interpreter
    result = subprocess.Popen(f"ping -c 1 {target_host}", shell=True, stdout=subprocess.PIPE)
    return result.communicate()[0]
```

### 4.3 Secure Python Pattern (subprocess with Argument Array & shell=False)
```python
# SECURE: Argument array, shell=False, strict regex validation, timeout enforcement
import subprocess
import re
import ipaddress

# Step 1: Validate input format strictly before execution
def is_valid_hostname_or_ip(host_str: str) -> bool:
    if not host_str or len(host_str) > 255:
        return False
    # Check if valid IPv4 or IPv6 address
    try:
        ipaddress.ip_address(host_str)
        return True
    except ValueError:
        pass
    # Check if valid RFC 1123 hostname
    hostname_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    return bool(re.match(hostname_regex, host_str))

@app.route("/api/ping", methods=["POST"])
def ping_server_secure():
    target_host = request.json.get("host", "").strip()

    if not is_valid_hostname_or_ip(target_host):
        return {"error": "Invalid target hostname format"}, 400

    try:
        # SECURE: shell=False (default). Arguments passed as individual array items.
        # The operating system's execve() system call receives each element as an immutable parameter.
        completed = subprocess.run(
            ["ping", "-c", "1", target_host],
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            timeout=10 # Prevent denial of service hangs
        )
        return {"output": completed.stdout}
    except subprocess.TimeoutExpired:
        return {"error": "Ping command timed out"}, 504
    except subprocess.CalledProcessError as exc:
        return {"error": "Ping failed", "code": exc.returncode}, 500
```

---

## 5. Java Command Execution: Vulnerable vs Secure Patterns

### 5.1 Prohibited Patterns in Java
The following constructs pass strings directly to the runtime system and are flagged under rule `SEC-JV-002`:
- `Runtime.getRuntime().exec("sh -c " + cmd)`
- `Runtime.getRuntime().exec("cmd.exe /c " + cmd)`
- `Runtime.getRuntime().exec(cmdString)` (where `cmdString` contains dynamic concatenation)

### 5.2 Vulnerable Java Pattern
```java
// VULNERABLE: Executing runtime shell with concatenated parameters
public class VulnerableBackupManager {
    public void executeBackup(String backupFolder, String targetArchive) throws Exception {
        // Attack payload in backupFolder: "data; rm -rf /"
        String command = "tar -czf " + targetArchive + " " + backupFolder;
        
        // Command Injection: runtime passes command to operating system
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
}
```

### 5.3 Secure Java Pattern (ProcessBuilder with Argument Array)
```java
// SECURE: ProcessBuilder with List arguments, strict validation, environment isolation
package com.smartcodeinspect.security.process;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public class SecureBackupManager {

    private static final Pattern SAFE_ARCHIVE_NAME = Pattern.compile("^[a-zA-Z0-9_-]{1,64}\\.tar\\.gz$");

    public void executeBackupSecure(File baseDir, String archiveName, File sourceFolder) throws Exception {
        // Step 1: Validate argument names against strict character allowlist
        if (!SAFE_ARCHIVE_NAME.matcher(archiveName).matches()) {
            throw new IllegalArgumentException("Invalid archive filename format.");
        }

        // Step 2: Validate filesystem containment
        File canonicalTarget = new File(baseDir, archiveName).getCanonicalFile();
        File canonicalSource = sourceFolder.getCanonicalFile();

        if (!canonicalTarget.getPath().startsWith(baseDir.getCanonicalPath()) ||
            !canonicalSource.getPath().startsWith(baseDir.getCanonicalPath())) {
            throw new SecurityException("Target path escapes restricted directory.");
        }

        // Step 3: ProcessBuilder with List<String> arguments (NO SHELL)
        // Each argument is passed directly to the kernel execve syscall.
        List<String> commandList = List.of(
            "tar",
            "-czf",
            canonicalTarget.getAbsolutePath(),
            "-C",
            canonicalSource.getParent(),
            canonicalSource.getName()
        );

        ProcessBuilder pb = new ProcessBuilder(commandList);
        pb.directory(baseDir);
        
        // Prevent inheritance of sensitive master environment variables
        pb.environment().clear();
        pb.environment().put("PATH", "/usr/bin:/bin");

        Process process = pb.start();

        // Enforce execution timeout
        boolean finished = process.waitFor(15, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("Backup process timed out after 15 seconds.");
        }

        if (process.exitValue() != 0) {
            throw new IOException("Backup command terminated with error code " + process.exitValue());
        }
    }
}
```

---

## 6. Argument Injection (Command-Line Parameter Hijacking)

Even when `shell=False` is employed, an attacker who controls command-line arguments can inject parameters (flags) that alter application logic. This is known as **Argument Injection**.

### 6.1 Notable Real-World Argument Injection Vectors
- **`tar` Utility**:
  - Flag `--checkpoint=1` combined with `--checkpoint-action=exec=sh malicious.sh` causes `tar` to execute arbitrary scripts.
  - Mitigation: Prepend `--` before user filenames: `tar -czf archive.tar.gz -- file1 file2`.
- **`curl` / `wget`**:
  - Flag `-o /etc/cron.d/job` or `--output` overwrites arbitrary filesystem locations.
  - Mitigation: Never allow user input to supply flags directly; use an HTTP client library instead.
- **`git`**:
  - `git clone --upload-pack="malicious_command" <repo>` executes arbitrary commands.
  - Mitigation: Validate repository URLs strictly against `https://` schemes.

---

## 7. Input Sanitization and Allowlisting

If external values must be passed to system tools, developers must enforce **strict character allowlisting** rather than denylisting:

```python
# SECURE: Strict allowlist pattern for file identifiers
import re

def sanitize_identifier(input_str: str) -> str:
    # Allow only alphanumeric characters, underscores, and hyphens
    if not re.match(r"^[A-Za-z0-9_-]+$", input_str):
        raise ValueError("Invalid identifier: special characters not permitted.")
    return input_str
```

Never attempt to "sanitize" shell metacharacters with string replacement (e.g. `cmd.replace(";", "").replace("&", "")`). Attackers bypass naive replacement filters using:
- Newlines (`\n`, `\r`)
- Alternate separators (`\x00`, `%0a`)
- Nested encoding (`%2526`)
- Variable interpolation (`$IFS`)

---

## 8. Operating System Least Privilege & Container Sandboxing

Defense-in-depth requires that the host environment restricts damage if an execution flaw occurs:
1. **Dedicated Service Accounts**: Run web applications under dedicated service accounts (`www-data`, `appuser`) with `nologin` shells. Never run applications as `root` or `Administrator`.
2. **Read-Only Root Filesystems**: In Docker and Kubernetes, mount application containers with `readOnlyRootFilesystem: true` and `securityContext: runAsNonRoot: true`.
3. **Drop Linux Capabilities**: Drop unnecessary capabilities: `cap_drop: ["ALL"]`, add back only `NET_BIND_SERVICE` if required.
4. **AppArmor / SELinux / Seccomp**: Apply strict seccomp profiles that block unauthorized system calls (`execve`, `ptrace`, `chroot`).

---

## 9. Automated SAST Detection Heuristics

Automated static analysis tools (SAST) such as SmartCodeInspect implement AST-based pattern matching to flag command injection vulnerabilities deterministically without executing code:

### 9.1 Python SAST Rules
- **Rule SEC-PY-002**: Inspects `ast.Call` nodes. Flags:
  - Any call to `os.system` or `os.popen`.
  - Any call to `subprocess.Popen`, `subprocess.run`, `subprocess.call`, `subprocess.check_call`, or `subprocess.check_output` where the keyword argument `shell` is set to `True` (`kw.arg == "shell" and kw.value.value is True`).
  - Calls where the command argument is built using string concatenation (`ast.BinOp` with `Add`) or formatted strings (`ast.JoinedStr`).

### 9.2 Java SAST Rules
- **Rule SEC-JV-002**: Inspects method invocations. Flags:
  - Direct invocations of `Runtime.getRuntime().exec(...)` when arguments are constructed via string concatenation (`+`).
  - `ProcessBuilder` invocations when constructed with single-string arguments rather than strongly typed `List<String>`.

---

## 10. Verification and Integration Testing

Applications must verify that command execution boundaries remain impervious to hostile metacharacters through automated security unit tests:

```python
import pytest
import subprocess

def test_command_runner_neutralizes_shell_metacharacters():
    """Verify that shell separators do not cause additional commands to execute."""
    hostile_input = "127.0.0.1; touch /tmp/pwned.txt"
    with pytest.raises(Exception):
        # Must fail input validation before executing
        ping_server_secure(hostile_input)
    
    # Confirm injection failed to execute
    import os
    assert not os.path.exists("/tmp/pwned.txt")
```

---

## 11. Comprehensive OS Command Injection Defense Checklist

- [ ] Native programming language APIs (file, network, compression) utilized instead of shell utilities.
- [ ] `shell=True`, `os.system()`, and `os.popen()` completely eliminated from Python codebases.
- [ ] `Runtime.getRuntime().exec(string)` passing shell commands completely eliminated from Java codebases.
- [ ] All external process execution uses array/List of arguments (`subprocess.run(["cmd", "arg"])` / `ProcessBuilder`).
- [ ] Strict alphanumeric allowlist regex validation enforced on all user-supplied command arguments.
- [ ] Double-dash `--` used to terminate options before passing user arguments to utilities (`tar`, `grep`, `git`).
- [ ] Explicit execution timeouts configured for every spawned process to prevent DoS deadlocks.
- [ ] Application processes run as non-root, unprivileged service users in read-only containers.
- [ ] Automated static analysis (SAST) rules `SEC-PY-002` and `SEC-JV-002` enforced in CI/CD pipeline.

