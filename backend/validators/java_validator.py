import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

MAX_DEFAULT_SOURCE_BYTES = 200000
DEFAULT_COMPILE_TIMEOUT = 10
MAX_OUTPUT_BYTES = 65536


def detect_javac_availability() -> Dict[str, Any]:
    """Check if the Java compiler (javac) is available on the system PATH."""
    javac_path = shutil.which("javac")
    if not javac_path:
        return {
            "available": False,
            "path": None,
            "version": None,
            "message": "JDK not found. 'javac' is not installed or not present on system PATH."
        }

    try:
        proc = subprocess.run(
            [javac_path, "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=5
        )
        version_output = (proc.stdout or proc.stderr).strip()
        return {
            "available": True,
            "path": javac_path,
            "version": version_output,
            "message": f"Java compiler available: {version_output}"
        }
    except Exception as exc:
        return {
            "available": False,
            "path": javac_path,
            "version": None,
            "message": f"Failed to query javac version: {str(exc)}"
        }


def extract_primary_java_class(source_code: str) -> Optional[str]:
    """Extract public class, interface, record, or enum name from Java source code."""
    # Strip block comments and single-line comments
    clean_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
    clean_code = re.sub(r'//.*', '', clean_code)

    # Matches: public class Foo, public interface Bar, public record Baz, public enum Qux
    match = re.search(
        r'\bpublic\s+(?:final\s+|abstract\s+)?(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)',
        clean_code
    )
    if match:
        return match.group(1)

    # Fallback: find any top-level class
    fallback_match = re.search(
        r'\b(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)',
        clean_code
    )
    if fallback_match:
        return fallback_match.group(1)

    return None



def parse_javac_output(output: str, source_filename: str) -> list:
    """Parse javac compiler diagnostics into structured line/column/message records."""
    diagnostics = []
    lines = output.splitlines()
    i = 0

    # Typical javac output format:
    # Filename.java:12: error: ';' expected
    # or Filename.java:15: warning: [deprecation] ...
    error_pattern = re.compile(r'^(?:.*[/\\])?([^/\\]+\.java):(\d+):\s*(error|warning):\s*(.+)$')

    while i < len(lines):
        line = lines[i].strip()
        match = error_pattern.match(line)
        if match:
            fname, line_str, severity, msg = match.groups()
            line_no = int(line_str)
            evidence = ""
            col_offset = 0

            # Inspect subsequent lines for snippet and caret indicator (^)
            if i + 1 < len(lines) and not error_pattern.match(lines[i + 1].strip()):
                evidence = lines[i + 1].strip()
                if i + 2 < len(lines) and "^" in lines[i + 2]:
                    caret_line = lines[i + 2]
                    col_offset = caret_line.find("^")
                    i += 2
                else:
                    i += 1

            diagnostics.append({
                "line": line_no,
                "column": col_offset,
                "severity": severity,
                "message": msg.strip(),
                "evidence": evidence
            })
        else:
            if line and not line.endswith("error") and not line.endswith("errors") and not line.endswith("warnings"):
                # Non-matching notice or general error
                if "error:" in line.lower() or "fatal" in line.lower():
                    diagnostics.append({
                        "line": 1,
                        "column": 0,
                        "severity": "error",
                        "message": line,
                        "evidence": ""
                    })
        i += 1

    return diagnostics


def validate_java_source(
    source_code: Any,
    filename: Optional[str] = None,
    timeout_seconds: int = DEFAULT_COMPILE_TIMEOUT,
    max_bytes: int = MAX_DEFAULT_SOURCE_BYTES
) -> Dict[str, Any]:
    """
    Validate Java source code via genuine javac compilation in an isolated temporary directory.
    NEVER executes the compiled bytecode. Bounded compilation execution and strict cleanup.
    """
    if source_code is None:
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": filename or "Main.java",
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": "Source code cannot be null or empty."
            }],
            "message": "Submission rejected: empty source code.",
            "total_lines": 0,
            "total_bytes": 0
        }

    if not isinstance(source_code, str):
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": filename or "Main.java",
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Expected source code as string, got {type(source_code).__name__}."
            }],
            "message": "Submission rejected: invalid data type.",
            "total_lines": 0,
            "total_bytes": 0
        }

    encoded_bytes = len(source_code.encode("utf-8"))
    if encoded_bytes == 0:
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": filename or "Main.java",
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": "Source code contains 0 bytes."
            }],
            "message": "Submission rejected: empty source code.",
            "total_lines": 0,
            "total_bytes": 0
        }

    if encoded_bytes > max_bytes:
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": filename or "Main.java",
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Source code exceeds maximum allowed size ({encoded_bytes} bytes > {max_bytes} bytes)."
            }],
            "message": f"Source code payload too large ({encoded_bytes} bytes).",
            "total_lines": source_code.count("\n") + 1,
            "total_bytes": encoded_bytes
        }

    # Verify javac availability
    javac_info = detect_javac_availability()
    if not javac_info["available"]:
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": filename or "Main.java",
            "compiler_unavailable": True,
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": javac_info["message"]
            }],
            "message": "JDK compiler unavailable on server.",
            "total_lines": source_code.count("\n") + 1,
            "total_bytes": encoded_bytes
        }

    # Determine filename
    class_name = extract_primary_java_class(source_code)
    target_filename = f"{class_name}.java" if class_name else (filename or "Main.java")
    if not target_filename.endswith(".java"):
        target_filename += ".java"

    total_lines = source_code.count("\n") + 1

    temp_dir = tempfile.mkdtemp(prefix="sci_java_")
    try:
        temp_path = Path(temp_dir)
        source_file = temp_path / target_filename
        source_file.write_text(source_code, encoding="utf-8")

        # Run javac without execution, isolated in temp_dir
        cmd = [
            javac_info["path"],
            "-d", str(temp_path),
            "-Xlint:all",
            str(source_file)
        ]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            cwd=str(temp_path),
            timeout=timeout_seconds
        )

        raw_output = (proc.stderr or "") + "\n" + (proc.stdout or "")
        diagnostics = parse_javac_output(raw_output, target_filename)

        # Check if compilation succeeded
        if proc.returncode == 0:
            return {
                "language": "java",
                "valid_syntax": True,
                "filename": target_filename,
                "compiler_version": javac_info["version"],
                "diagnostics": diagnostics,  # Might have warnings
                "message": f"Java compilation successful ({total_lines} lines).",
                "total_lines": total_lines,
                "total_bytes": encoded_bytes
            }
        else:
            if not diagnostics:
                diagnostics.append({
                    "line": 1,
                    "column": 0,
                    "severity": "error",
                    "message": raw_output.strip() or "Compilation failed without diagnostic output."
                })

            error_count = sum(1 for d in diagnostics if d.get("severity") == "error")
            return {
                "language": "java",
                "valid_syntax": False,
                "filename": target_filename,
                "compiler_version": javac_info["version"],
                "diagnostics": diagnostics,
                "message": f"Java compilation failed with {error_count} error(s).",
                "total_lines": total_lines,
                "total_bytes": encoded_bytes
            }

    except subprocess.TimeoutExpired:
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": target_filename,
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Compilation timed out after {timeout_seconds} seconds."
            }],
            "message": f"Compilation timed out ({timeout_seconds}s limit).",
            "total_lines": total_lines,
            "total_bytes": encoded_bytes
        }
    except Exception as exc:
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": target_filename,
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Unexpected compiler error: {str(exc)}"
            }],
            "message": f"Compiler exception: {str(exc)}",
            "total_lines": total_lines,
            "total_bytes": encoded_bytes
        }
    finally:
        # Guarantee cleanup of temporary directory and class files
        shutil.rmtree(temp_dir, ignore_errors=True)
