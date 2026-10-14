from typing import Dict, Any, Optional

try:
    from validators.java_validator import validate_java_source
    from analyzers.rules.java_rules import JavaSecurityAnalyzer
except ImportError:
    from ..validators.java_validator import validate_java_source
    from .rules.java_rules import JavaSecurityAnalyzer


def analyze_java_source(
    source_code: Any,
    filename: Optional[str] = None,
    timeout_seconds: int = 10,
    max_bytes: int = 200000
) -> Dict[str, Any]:
    """
    Perform Java compilation validation followed by deterministic security rules analysis.
    Distinguishes compiler diagnostics from security findings.
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
                "informational": 0
            },
            "total_lines": validation_result.get("total_lines", 0),
            "total_bytes": validation_result.get("total_bytes", 0)
        }

    try:
        analyzer = JavaSecurityAnalyzer(source_code)
        rule_findings = analyzer.analyze()
        findings = [f.to_dict() for f in rule_findings]
    except Exception as exc:
        findings = []

    summary = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
        "informational": sum(1 for f in findings if f["severity"] == "Informational")
    }

    status_msg = "Compilation succeeded." if validation_result.get("valid_syntax") else "Compilation diagnostics reported."
    full_msg = f"{status_msg} Security analysis detected {len(findings)} finding(s)."

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
        "total_lines": validation_result.get("total_lines", 0),
        "total_bytes": validation_result.get("total_bytes", 0)
    }
