from flask import Blueprint, request, jsonify

try:
    from agents.ai_provider import get_ai_explanation
except ImportError:
    from ..agents.ai_provider import get_ai_explanation

ai_bp = Blueprint("ai", __name__)


@ai_bp.route("/ai/explain", methods=["POST"])
def explain_finding():
    """
    Generate AI explanation for a validated finding and retrieved OWASP guidance.
    Clearly labels advice as AI-generated and not verified evidence.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object.", "success": False}), 400

    finding = payload.get("finding")
    if not isinstance(finding, dict):
        return jsonify({"error": "Missing or invalid 'finding' object in request.", "success": False}), 400

    owasp_passages = payload.get("owasp_passages", [])
    result = get_ai_explanation(finding=finding, owasp_passages=owasp_passages)

    status_code = 200 if result.get("success") else 502
    return jsonify(result), status_code
