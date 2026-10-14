from typing import Dict, Any, Optional

try:
    from validators.python_validator import validate_python_source
    from analyzers.rules.python_rules import PythonSecurityVisitor
except ImportError:
    from ..validators.python_validator import validate_python_source
    from .rules.python_rules import PythonSecurityVisitor


def analyze_python_source(
    source_code: Any,
    filename: Optional[str] = None,
    max_bytes: int = 200000
) -> Dict[str, Any]:
    """
    Perform full syntax validation followed by static security rule analysis on Python code.
    Only executes deterministic security analysis after successful AST parsing.
    """
    validation_result = validate_python_source(source_code, filename=filename, max_bytes=max_bytes)

    if not validation_result.get("valid_syntax"):
        return {
            "language": "python",
            "valid_syntax": False,
            "filename": validation_result.get("filename", filename or "untitled.py"),
            "diagnostics": validation_result.get("diagnostics", []),
            "message": validation_result.get("message", "Syntax validation failed."),
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0
            },
            "total_lines": validation_result.get("total_lines", 0),
            "total_bytes": validation_result.get("total_bytes", 0)
        }

    parsed_ast = validation_result.get("parsed_ast")
    source_lines = source_code.splitlines() if isinstance(source_code, str) else []

    try:
        visitor = PythonSecurityVisitor(source_lines=source_lines)
        visitor.visit(parsed_ast)
        findings = [f.to_dict() for f in visitor.findings]
    except Exception as exc:
        return {
            "language": "python",
            "valid_syntax": True,
            "filename": validation_result.get("filename", filename or "untitled.py"),
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Rule evaluation error: {str(exc)}"
            }],
            "message": f"Inspection rule evaluation failed: {str(exc)}",
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0
            },
            "total_lines": validation_result.get("total_lines", 0),
            "total_bytes": validation_result.get("total_bytes", 0)
        }

    summary = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
        "informational": sum(1 for f in findings if f["severity"] == "Informational")
    }

    return {
        "language": "python",
        "valid_syntax": True,
        "filename": validation_result.get("filename", filename or "untitled.py"),
        "diagnostics": validation_result.get("diagnostics", []),
        "message": f"Syntax valid. Security analysis completed with {len(findings)} finding(s).",
        "findings": findings,
        "summary": summary,
        "total_lines": validation_result.get("total_lines", 0),
        "total_bytes": validation_result.get("total_bytes", 0)
    }
