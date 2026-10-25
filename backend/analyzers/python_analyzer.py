from typing import Dict, Any, Optional

try:
    from validators.python_validator import validate_python_source
except ImportError:
    try:
        from backend.validators.python_validator import validate_python_source
    except ImportError:
        from ..validators.python_validator import validate_python_source


def analyze_python_source(
    source_code: Any,
    filename: Optional[str] = None,
    max_bytes: int = 200000
) -> Dict[str, Any]:
    """
    Perform full syntax validation followed by parallel multi-agent static analysis on Python code.
    Executes Code Analysis Agent and Security Vulnerability Agent concurrently, merging
    their findings into a unified registry with composite quality and security metrics.
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
                "informational": 0,
                "security_findings_count": 0,
                "code_quality_findings_count": 0,
                "average_severity_score": 0.0,
                "code_quality_score": 0,
                "security_posture": "N/A (Syntax Error)"
            },
            "orchestration": {
                "parallel_execution": False,
                "agents": {}
            },
            "total_lines": validation_result.get("total_lines", 0),
            "total_bytes": validation_result.get("total_bytes", 0)
        }

    try:
        try:
            from agents.orchestrator import get_orchestrator
        except ImportError:
            try:
                from backend.agents.orchestrator import get_orchestrator
            except ImportError:
                from ..agents.orchestrator import get_orchestrator

        orchestrator = get_orchestrator()
        orchestration_result = orchestrator.run_parallel_analysis(
            source_code=source_code,
            language="python",
            filename=filename
        )
        findings = orchestration_result["findings"]
        summary = orchestration_result["summary"]
        orchestration = orchestration_result["orchestration"]
    except Exception as exc:
        return {
            "language": "python",
            "valid_syntax": True,
            "filename": validation_result.get("filename", filename or "untitled.py"),
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Multi-agent inspection error: {str(exc)}"
            }],
            "message": f"Multi-agent inspection execution failed: {str(exc)}",
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
                "security_findings_count": 0,
                "code_quality_findings_count": 0,
                "average_severity_score": 0.0,
                "code_quality_score": 0,
                "security_posture": "Error"
            },
            "orchestration": {
                "parallel_execution": False,
                "errors": [str(exc)]
            },
            "total_lines": validation_result.get("total_lines", 0),
            "total_bytes": validation_result.get("total_bytes", 0)
        }

    sec_count = summary.get("security_findings_count", 0)
    qual_count = summary.get("code_quality_findings_count", 0)
    msg = (
        f"Syntax valid. Multi-agent analysis completed with {len(findings)} finding(s) "
        f"(Security: {sec_count}, Code Quality: {qual_count})."
    )

    return {
        "language": "python",
        "valid_syntax": True,
        "filename": validation_result.get("filename", filename or "untitled.py"),
        "diagnostics": validation_result.get("diagnostics", []),
        "message": msg,
        "findings": findings,
        "summary": summary,
        "orchestration": orchestration,
        "total_lines": validation_result.get("total_lines", 0),
        "total_bytes": validation_result.get("total_bytes", 0)
    }

