# OWASP OS Command Injection Defense Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection vulnerabilities occur when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are executed with the privileges of the vulnerable application.

## Primary Defense: Avoid Calling OS Commands Directly
The primary defense against command injection is to avoid calling external system commands directly whenever built-in API functions or programming language libraries exist. For example, instead of running `os.system("rm " + filename)` or `Runtime.getRuntime().exec("del " + filename)`, use language APIs like `os.remove(filename)` or Java's `Files.delete(path)`.

## Defense: Parameterization and Avoiding the System Shell
If an external command must be executed, never invoke it through a command shell (such as `/bin/sh`, `/bin/bash`, `cmd.exe`, or `powershell.exe`).

### Python Subprocess Guidance
In Python:
- Use `subprocess.run()` or `subprocess.Popen()`.
- Pass arguments as a discrete list of strings rather than a concatenated string.
- Keep `shell=False` (which is the default).
```python
# SAFE: Arguments are passed directly to execve without shell expansion
import subprocess
result = subprocess.run(["ping", "-c", "4", target_host], shell=False, capture_output=True, text=True)
```
- NEVER set `shell=True` when handling user input.
- NEVER use `os.system()` or `os.popen()` because they always invoke the system shell.

### Java ProcessBuilder Guidance
In Java:
- Use `ProcessBuilder` with an array or List of arguments:
```java
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", targetHost);
Process process = pb.start();
```
- Never pass arguments to `Runtime.getRuntime().exec("sh -c " + command)` or `cmd.exe /c`.

## Defense: Strict Allow-list Input Validation
Validate all inputs against an allow-list of known safe characters (e.g. alphanumeric characters only) before passing them to any process or system command.
