from flask import Blueprint, request, jsonify

try:
    from validators.python_validator import validate_python_source
    from validators.java_validator import validate_java_source
    from config import Config
except ImportError:
    from ..validators.python_validator import validate_python_source
    from ..validators.java_validator import validate_java_source
    from ..config import Config

validate_bp = Blueprint("validate", __name__)


@validate_bp.route("/validate", methods=["POST"])
def validate_code():
    """
    Validate Python syntax via ast.parse or Java compilation via javac.
    Returns parser/compiler diagnostics without executing submitted code.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({
            "error": "Invalid request: Expected JSON object.",
            "valid_syntax": False
        }), 400

    language = payload.get("language", "").strip().lower()
    source_code = payload.get("source_code")
    filename = payload.get("filename")

    if language not in ("python", "java"):
        return jsonify({
            "error": f"Unsupported language '{language}'. Supported languages are 'python' and 'java'.",
            "valid_syntax": False
        }), 400

    if language == "python":
        result = validate_python_source(
            source_code=source_code,
            filename=filename,
            max_bytes=Config.MAX_SOURCE_BYTES
        )
    else:
        result = validate_java_source(
            source_code=source_code,
            filename=filename,
            timeout_seconds=Config.JAVA_COMPILE_TIMEOUT_SECONDS,
            max_bytes=Config.MAX_SOURCE_BYTES
        )
    clean_result = {k: v for k, v in result.items() if k != "parsed_ast"}
    return jsonify(clean_result), 200
