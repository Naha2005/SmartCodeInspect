from flask import Blueprint, request, jsonify

try:
    from agents.ai_provider import get_ai_explanation
    from agents.conversational_agent import get_conversational_assistant
    from agents.remediation_agent import get_remediation_agent
    from agents.pr_summary_agent import get_pr_summary_agent
except ImportError:
    from ..agents.ai_provider import get_ai_explanation
    from ..agents.conversational_agent import get_conversational_assistant
    from ..agents.remediation_agent import get_remediation_agent
    from ..agents.pr_summary_agent import get_pr_summary_agent

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
    try:
        result = get_ai_explanation(finding=finding, owasp_passages=owasp_passages)
        status_code = 200 if result.get("success") else 200
        return jsonify(result), status_code
    except Exception as exc:
        try:
            from agents.ai_provider import _build_offline_advisory
        except ImportError:
            from ..agents.ai_provider import _build_offline_advisory
        fallback = _build_offline_advisory(finding, reason=f"Fallback advisory: {str(exc)}")
        return jsonify(fallback), 200


@ai_bp.route("/chat", methods=["POST"])
@ai_bp.route("/ai/chat", methods=["POST"])
def conversational_chat():
    """
    Conversational Code Assistant endpoint:
    RAG-powered conversational interface grounded in authentic OWASP knowledge base.
    Handles follow-up queries on code, flagged findings, and secure coding guidelines.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object.", "success": False}), 400

    query = payload.get("query", "").strip()
    if not query:
        return jsonify({"error": "Query parameter cannot be empty.", "success": False}), 400

    history = payload.get("history", [])
    context = payload.get("context", {})

    try:
        assistant = get_conversational_assistant()
        result = assistant.ask(
            query=query,
            history=history,
            context=context
        )
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Conversational assistant error: {str(exc)}",
            "response": "An unexpected error occurred while processing your request. Please try again.",
            "citations": [],
            "provider": "offline_fallback"
        }), 200


@ai_bp.route("/remediate", methods=["POST"])
def remediate_finding():
    """
    Remediation Agent endpoint:
    Generate a specific fix recommendation with corrected code examples,
    best practice explanation, and diff for a finding.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object."}), 400

    finding = payload.get("finding")
    if not isinstance(finding, dict):
        return jsonify({"error": "Missing or invalid 'finding' parameter."}), 400

    source_code = payload.get("source_code")
    language = payload.get("language")

    try:
        agent = get_remediation_agent()
        remediation = agent.generate_remediation(
            finding=finding,
            source_code=source_code,
            language=language
        )
        return jsonify({"success": True, "remediation": remediation}), 200
    except Exception as exc:
        return jsonify({"error": f"Remediation generation failed: {str(exc)}", "success": False}), 500


@ai_bp.route("/pr-summary", methods=["POST"])
def generate_pr_summary_endpoint():
    """
    PR Summary Agent endpoint:
    Compiles findings, summary, and metadata into a structured pull request review.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object."}), 400

    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    metadata = payload.get("metadata", {})

    try:
        agent = get_pr_summary_agent()
        result = agent.generate_pr_summary(
            findings=findings,
            summary=summary,
            metadata=metadata
        )
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": f"PR summary generation failed: {str(exc)}"}), 500
