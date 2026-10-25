from typing import Dict, Any, Optional

try:
    from validators.java_validator import validate_java_source
except ImportError:
    try:
        from backend.validators.java_validator import validate_java_source
    except ImportError:
        from ..validators.java_validator import validate_java_source


def analyze_java_source(
    source_code: Any,
    filename: Optional[str] = None,
    timeout_seconds: int = 10,
    max_bytes: int = 200000
) -> Dict[str, Any]:
    """
    Perform Java compilation validation followed by parallel multi-agent static analysis.
    Executes Code Analysis Agent and Security Vulnerability Agent concurrently,
    merging findings into a unified registry with composite quality and security metrics.
    """
    validation_result = validate_java_source(
        source_code,
        filename=filename,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes
    )

    if validation_result.get("total_bytes", 0) == 0 or not isinstance(source_code, str):
        return {
            "language": "java",
            "valid_syntax": False,
            "filename": validation_result.get("filename", filename or "Main.java"),
            "diagnostics": validation_result.get("diagnostics", []),
            "message": validation_result.get("message", "Input validation rejected."),
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
                "security_posture": "N/A (Input Rejected)"
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
            language="java",
            filename=filename
        )
        findings = orchestration_result["findings"]
        summary = orchestration_result["summary"]
        orchestration = orchestration_result["orchestration"]
    except Exception as exc:
        findings = []
        summary = {
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
        }
        orchestration = {
            "parallel_execution": False,
            "errors": [str(exc)]
        }

    status_msg = "Compilation succeeded." if validation_result.get("valid_syntax") else "Compilation diagnostics reported."
    sec_count = summary.get("security_findings_count", 0)
    qual_count = summary.get("code_quality_findings_count", 0)
    full_msg = f"{status_msg} Multi-agent analysis completed with {len(findings)} finding(s) (Security: {sec_count}, Code Quality: {qual_count})."

    return {
        "language": "java",
        "valid_syntax": validation_result.get("valid_syntax", False),
        "filename": validation_result.get("filename", filename or "Main.java"),
        "compiler_version": validation_result.get("compiler_version"),
        "compiler_unavailable": validation_result.get("compiler_unavailable", False),
        "diagnostics": validation_result.get("diagnostics", []),
        "message": full_msg,
        "findings": findings,
        "summary": summary,
        "orchestration": orchestration,
        "total_lines": validation_result.get("total_lines", 0),
        "total_bytes": validation_result.get("total_bytes", 0)
    }

