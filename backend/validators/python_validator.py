import ast
from typing import Dict, Any, Optional

MAX_DEFAULT_SOURCE_BYTES = 200000


def validate_python_source(
    source_code: Any,
    filename: Optional[str] = None,
    max_bytes: int = MAX_DEFAULT_SOURCE_BYTES
) -> Dict[str, Any]:
    """
    Validate Python source code syntax using Python's built-in `ast.parse`.
    NEVER dynamically executes, imports, or evaluates submitted code.
    
    Returns structured dictionary with:
      - language: 'python'
      - valid_syntax: bool
      - diagnostics: list of error/warning diagnostics with line, column, and message
      - message: summary message
      - ast_tree: ast.AST (omitted in JSON serialization)
      - total_lines: int
      - total_bytes: int
    """
    if source_code is None:
        return {
            "language": "python",
            "valid_syntax": False,
            "filename": filename or "untitled.py",
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
            "language": "python",
            "valid_syntax": False,
            "filename": filename or "untitled.py",
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
            "language": "python",
            "valid_syntax": False,
            "filename": filename or "untitled.py",
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
            "language": "python",
            "valid_syntax": False,
            "filename": filename or "untitled.py",
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

    lines = source_code.splitlines()
    total_lines = len(lines) if lines else 1

    try:
        # ast.parse does not execute code; it purely builds an AST
        parsed_tree = ast.parse(source_code, filename=filename or "<input>")
        return {
            "language": "python",
            "valid_syntax": True,
            "filename": filename or "untitled.py",
            "diagnostics": [],
            "message": f"Python syntax valid ({total_lines} lines parsed successfully).",
            "total_lines": total_lines,
            "total_bytes": encoded_bytes,
            "parsed_ast": parsed_tree  # Available in memory for analyzer
        }
    except SyntaxError as syn_err:
        line_num = syn_err.lineno or 1
        col_offset = syn_err.offset or 0
        err_msg = syn_err.msg or "Syntax error encountered during parsing."
        text_snippet = (syn_err.text or "").strip()

        diagnostic = {
            "line": line_num,
            "column": col_offset,
            "severity": "error",
            "message": f"SyntaxError: {err_msg}",
            "evidence": text_snippet
        }

        return {
            "language": "python",
            "valid_syntax": False,
            "filename": filename or "untitled.py",
            "diagnostics": [diagnostic],
            "message": f"Python syntax invalid at line {line_num}, column {col_offset}: {err_msg}",
            "total_lines": total_lines,
            "total_bytes": encoded_bytes,
            "parsed_ast": None
        }
    except Exception as exc:
        return {
            "language": "python",
            "valid_syntax": False,
            "filename": filename or "untitled.py",
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Parser error: {str(exc)}"
            }],
            "message": f"Parser encountered unexpected error: {str(exc)}",
            "total_lines": total_lines,
            "total_bytes": encoded_bytes,
            "parsed_ast": None
        }
