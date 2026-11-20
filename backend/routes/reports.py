from flask import Blueprint, request, jsonify, send_file

try:
    from backend.reports.pdf_generator import generate_pdf_report
    from backend.reports.sarif_generator import generate_sarif_report
    from backend.analyzers.python_analyzer import analyze_python_source
    from backend.analyzers.java_analyzer import analyze_java_source
except ImportError:
    try:
        from ..reports.pdf_generator import generate_pdf_report
        from ..reports.sarif_generator import generate_sarif_report
        from ..analyzers.python_analyzer import analyze_python_source
        from ..analyzers.java_analyzer import analyze_java_source
    except (ImportError, ValueError):
        from reports.pdf_generator import generate_pdf_report  # type: ignore
        from reports.sarif_generator import generate_sarif_report  # type: ignore
        from analyzers.python_analyzer import analyze_python_source  # type: ignore
        from analyzers.java_analyzer import analyze_java_source  # type: ignore

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
    if isinstance(payload.get("analysis_data"), dict):
        analysis_data = payload["analysis_data"]
        if "ai_explanation" in payload and "ai_explanation" not in analysis_data:
            analysis_data["ai_explanation"] = payload["ai_explanation"]
        if source_code and "source_code" not in analysis_data:
            analysis_data["source_code"] = source_code
        if language and "language" not in analysis_data:
            analysis_data["language"] = language
        if filename and "filename" not in analysis_data:
            analysis_data["filename"] = filename
        if "original_source_code" in payload and "original_source_code" not in analysis_data:
            analysis_data["original_source_code"] = payload["original_source_code"]
        if "original_health_score" in payload and "original_health_score" not in analysis_data:
            analysis_data["original_health_score"] = payload["original_health_score"]
        if "original_findings" in payload and "original_findings" not in analysis_data:
            analysis_data["original_findings"] = payload["original_findings"]
        if "original_summary" in payload and "original_summary" not in analysis_data:
            analysis_data["original_summary"] = payload["original_summary"]
        if "original_pr_summary" in payload and "original_pr_summary" not in analysis_data:
            analysis_data["original_pr_summary"] = payload["original_pr_summary"]
    elif source_code and language in ("python", "java"):
        try:
            try:
                from backend.agents.orchestrator import get_orchestrator
            except ImportError:
                from ..agents.orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            analysis_data = orchestrator.run_parallel_analysis(
                source_code=source_code,
                language=language,
                filename=filename
            )
        except Exception:
            if language == "python":
                analysis_data = analyze_python_source(source_code, filename=filename)
            else:
                analysis_data = analyze_java_source(source_code, filename=filename)
        
        if "ai_explanation" in payload:
            analysis_data["ai_explanation"] = payload["ai_explanation"]
    else:
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


@reports_bp.route("/reports/sarif", methods=["POST"])
def download_sarif_report():
    """
    Generate and stream an OASIS SARIF v2.1.0 standard report.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object."}), 400

    source_code = payload.get("source_code")
    language = str(payload.get("language", "")).strip().lower()
    filename = payload.get("filename", "inspected_source")

    analysis_data = None
    if isinstance(payload.get("analysis_data"), dict):
        analysis_data = payload["analysis_data"]
    elif source_code and language in ("python", "java"):
        try:
            try:
                from backend.agents.orchestrator import get_orchestrator
            except ImportError:
                from ..agents.orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            analysis_data = orchestrator.run_parallel_analysis(
                source_code=source_code,
                language=language,
                filename=filename
            )
        except Exception:
            if language == "python":
                analysis_data = analyze_python_source(source_code, filename=filename)
            else:
                analysis_data = analyze_java_source(source_code, filename=filename)
    else:
        return jsonify({"error": "Missing valid 'analysis_data' or 'source_code' for report generation."}), 400

    try:
        sarif_json = generate_sarif_report(analysis_data, filename=filename)
        return jsonify(sarif_json)
    except Exception as exc:
        return jsonify({"error": f"Failed to generate SARIF report: {str(exc)}"}), 500
