from flask import Blueprint, jsonify

try:
    from validators.java_validator import detect_javac_availability
    from knowledge_base.retriever import OWASPRetriever
    from config import Config
except ImportError:
    from ..validators.java_validator import detect_javac_availability
    from ..knowledge_base.retriever import OWASPRetriever
    from ..config import Config

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """
    Return backend operational status, Java compiler availability,
    knowledge base readiness, and safe AI configuration status.
    Never exposes API keys or server credentials.
    """
    java_status = detect_javac_availability()
    retriever = OWASPRetriever(Config.INDEX_DIR)
    kb_status = retriever.get_status()
    ai_status = Config.get_ai_status()

    return jsonify({
        "status": "healthy",
        "service": "Smart Code Inspection Platform API",
        "version": "1.0.0",
        "java_compiler": {
            "available": java_status.get("available", False),
            "version": java_status.get("version"),
            "path": java_status.get("path")
        },
        "knowledge_base": {
            "status": kb_status.get("status", "unindexed"),
            "documents_count": kb_status.get("documents_count", 0),
            "chunks_count": kb_status.get("chunks_count", 0),
            "algorithm": kb_status.get("vector_algorithm", "Pure Python TF-IDF Vector Space Model")
        },
        "ai_integration": ai_status
    }), 200
