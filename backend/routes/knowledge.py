from flask import Blueprint, request, jsonify

try:
    from knowledge_base.retriever import OWASPRetriever
    from knowledge_base.ingest import run_ingestion
    from config import Config
except ImportError:
    from ..knowledge_base.retriever import OWASPRetriever
    from ..knowledge_base.ingest import run_ingestion
    from ..config import Config

knowledge_bp = Blueprint("knowledge", __name__)


@knowledge_bp.route("/knowledge/search", methods=["POST"])
def search_knowledge():
    """
    Search authentic OWASP knowledge base using genuine vector cosine similarity.
    Returns matched excerpts, section metadata, official URLs, and genuine similarity scores.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid request: Expected JSON object.", "results": []}), 400

    query = str(payload.get("query", "")).strip()
    top_k = int(payload.get("top_k", 4))
    min_score = float(payload.get("min_score", 0.05))

    if not query:
        return jsonify({"results": [], "query": "", "message": "Query parameter cannot be empty."}), 200

    retriever = OWASPRetriever(Config.INDEX_DIR)
    results = retriever.search(query=query, top_k=top_k, min_score=min_score)

    return jsonify({
        "query": query,
        "results": results,
        "total_results": len(results),
        "algorithm": "ChromaDB Vector Store (with TF-IDF Hybrid Fallback)"
    }), 200


@knowledge_bp.route("/knowledge/ingest", methods=["POST"])
def rebuild_index():
    """Trigger ingestion pipeline and rebuild persistent vector index."""
    result = run_ingestion()
    return jsonify(result), 200
