from flask import Blueprint, request, jsonify

try:
    from analyzers.python_analyzer import analyze_python_source
    from analyzers.java_analyzer import analyze_java_source
    from config import Config
except ImportError:
    from ..analyzers.python_analyzer import analyze_python_source
    from ..analyzers.java_analyzer import analyze_java_source
    from ..config import Config

analyze_bp = Blueprint("analyze", __name__)


@analyze_bp.route("/analyze", methods=["POST"])
def analyze_code():
    """
    Validate code and run deterministic security inspection rules.
    Returns syntax diagnostics, detected findings with line/evidence,
    mitigations, OWASP citations, and summary metrics.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({
            "error": "Invalid request: Expected JSON object.",
            "valid_syntax": False,
            "findings": []
        }), 400

    language = payload.get("language", "").strip().lower()
    source_code = payload.get("source_code")
    filename = payload.get("filename")

    if language not in ("python", "java"):
        return jsonify({
            "error": f"Unsupported language '{language}'. Supported languages are 'python' and 'java'.",
            "valid_syntax": False,
            "findings": []
        }), 400

    try:
        if language == "python":
            result = analyze_python_source(
                source_code=source_code,
                filename=filename,
                max_bytes=Config.MAX_SOURCE_BYTES
            )
        else:
            result = analyze_java_source(
                source_code=source_code,
                filename=filename,
                timeout_seconds=Config.JAVA_COMPILE_TIMEOUT_SECONDS,
                max_bytes=Config.MAX_SOURCE_BYTES
            )

        return jsonify(result), 200
    except Exception as exc:
        return jsonify({
            "error": f"Analysis execution failed: {str(exc)}",
            "language": language,
            "valid_syntax": False,
            "filename": filename or ("untitled.py" if language == "python" else "Untitled.java"),
            "diagnostics": [{
                "line": 1,
                "column": 0,
                "severity": "error",
                "message": f"Server inspection error: {str(exc)}"
            }],
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0
            }
        }), 200
