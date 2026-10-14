from flask import Blueprint, request, jsonify, send_file

try:
    from reports.pdf_generator import generate_pdf_report
    from analyzers.python_analyzer import analyze_python_source
    from analyzers.java_analyzer import analyze_java_source
except ImportError:
    from ..reports.pdf_generator import generate_pdf_report
    from ..analyzers.python_analyzer import analyze_python_source
    from ..analyzers.java_analyzer import analyze_java_source

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports/pdf", methods=["POST"])
def download_pdf_report():
    """
    Generate and stream an authentic PDF vulnerability report.
    Independently validates analysis provenance: if source_code is provided,
    performs fresh server-side deterministic verification to prevent forged findings.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object."}), 400

    source_code = payload.get("source_code")
    language = str(payload.get("language", "")).strip().lower()
    filename = payload.get("filename", "inspected_source")

    analysis_data = None
    if source_code and language in ("python", "java"):
        if language == "python":
            analysis_data = analyze_python_source(source_code, filename=filename)
        else:
            analysis_data = analyze_java_source(source_code, filename=filename)
        
        if "ai_explanation" in payload:
            analysis_data["ai_explanation"] = payload["ai_explanation"]
    else:
        analysis_data = payload.get("analysis_data")
        if not isinstance(analysis_data, dict):
            return jsonify({"error": "Missing valid 'analysis_data' or 'source_code' for report generation."}), 400

    try:
        pdf_stream = generate_pdf_report(analysis_data)
        safe_filename = filename.replace("/", "_").replace("\\", "_")
        if not safe_filename.endswith(".pdf"):
            safe_filename += "_security_report.pdf"

        return send_file(
            pdf_stream,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=safe_filename
        )
    except Exception as exc:
        return jsonify({"error": f"Failed to generate PDF report: {str(exc)}"}), 500
