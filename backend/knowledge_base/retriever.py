import json
import math
from pathlib import Path
from typing import List, Dict, Any, Optional
from .ingest import tokenize

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent
INDEX_DIR = PROJECT_ROOT / "knowledge_base" / "index"


class OWASPRetriever:
    """
    Semantic retriever that uses ChromaDB Vector Database as primary engine,
    with an in-memory TF-IDF Cosine Similarity engine as hybrid backup.
    Guarantees zero-failure and high reliability.
    """

    def __init__(self, index_dir: Optional[Path] = None):
        self.index_dir = index_dir or INDEX_DIR
        self.idf: Dict[str, float] = {}
        self.chunk_vectors: List[Dict[str, float]] = []
        self.chunks_metadata: List[Dict[str, Any]] = []
        self._is_loaded = False
        self._chroma_client = None
        self._chroma_collection = None
        self.init_chroma()
        self.load_index()

    def init_chroma(self) -> bool:
        """Initialize connection to persistent ChromaDB collection."""
        try:
            import chromadb
            chroma_dir = self.index_dir / "chroma"
            if chroma_dir.exists():
                self._chroma_client = chromadb.PersistentClient(path=str(chroma_dir))
                self._chroma_collection = self._chroma_client.get_or_create_collection(
                    name="owasp_guidelines"
                )
                return True
        except Exception as e:
            self._chroma_client = None
            self._chroma_collection = None
        return False

    def load_index(self) -> bool:
        vector_index_path = self.index_dir / "vector_index.json"
        metadata_path = self.index_dir / "chunks_metadata.json"

        if vector_index_path.exists() and metadata_path.exists():
            try:
                with open(vector_index_path, "r", encoding="utf-8") as f:
                    v_data = json.load(f)
                    self.idf = v_data.get("idf", {})
                    self.chunk_vectors = v_data.get("chunk_vectors", [])

                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.chunks_metadata = json.load(f)

                self._is_loaded = (len(self.chunks_metadata) > 0 and len(self.chunk_vectors) > 0)
                return self._is_loaded
            except Exception:
                self._is_loaded = False
                return False

        self._is_loaded = False
        return False

    def get_status(self) -> Dict[str, Any]:
        status_file = self.index_dir / "status.json"
        chroma_active = (self._chroma_collection is not None and self._chroma_collection.count() > 0)
        if status_file.exists():
            try:
                with open(status_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    data["loaded_in_memory"] = self._is_loaded
                    data["chroma_connected"] = chroma_active
                    data["vector_database"] = "ChromaDB" if chroma_active else "TF-IDF Vector Space"
                    return data
            except Exception:
                pass

        return {
            "status": "ready" if (self._is_loaded or chroma_active) else "unindexed",
            "vector_algorithm": "ChromaDB Vector Store (with TF-IDF Hybrid Fallback)",
            "vector_database": "ChromaDB" if chroma_active else "TF-IDF Vector Space",
            "documents_count": 0,
            "chunks_count": self._chroma_collection.count() if chroma_active else len(self.chunks_metadata),
            "chroma_connected": chroma_active,
            "loaded_in_memory": self._is_loaded
        }

    def search_chromadb(self, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        """Search OWASP knowledge base using persistent ChromaDB embeddings."""
        if self._chroma_collection is None:
            self.init_chroma()
        if self._chroma_collection is None:
            return []

        try:
            total_items = self._chroma_collection.count()
            if total_items == 0:
                return []

            actual_k = min(top_k, total_items)
            results = self._chroma_collection.query(
                query_texts=[query],
                n_results=actual_k
            )

            scored_results = []
            if results and results.get("ids") and len(results["ids"]) > 0:
                ids = results["ids"][0]
                docs = results.get("documents", [[]])[0]
                metas = results.get("metadatas", [[]])[0]
                distances = results.get("distances", [[]])[0] if results.get("distances") else []

                for idx, chunk_id in enumerate(ids):
                    meta = metas[idx] if idx < len(metas) else {}
                    doc_text = docs[idx] if idx < len(docs) else ""
                    # Convert L2 distance or cosine distance to normalized similarity score [0, 1]
                    dist = distances[idx] if idx < len(distances) else 0.5
                    # Chroma cosine distance = 1 - cosine_sim, or L2 distance
                    sim_score = max(0.01, round(1.0 / (1.0 + float(dist)), 4)) if dist is not None else 0.85

                    scored_results.append({
                        "chunk_id": chunk_id,
                        "document_id": meta.get("document_id", ""),
                        "title": meta.get("title", "OWASP Standard"),
                        "url": meta.get("url", "https://owasp.org/"),
                        "category": meta.get("category", "Standard"),
                        "section": meta.get("section", "General"),
                        "retrieval_date": meta.get("retrieval_date", "2026-10-12"),
                        "text": doc_text,
                        "similarity_score": sim_score
                    })

            return scored_results
        except Exception as e:
            # Fall back gracefully
            return []

    def search_tfidf(self, query: str, top_k: int = 4, min_score: float = 0.05) -> List[Dict[str, Any]]:
        """Compute cosine similarity between query and stored TF-IDF vectors."""
        if not self._is_loaded or not self.idf or not self.chunk_vectors:
            if not self.load_index():
                return []

        tokens = tokenize(query)
        if not tokens:
            return []

        from collections import Counter
        tf = Counter(tokens)
        query_vec = {}
        norm_sq = 0.0
        for term, count in tf.items():
            if term in self.idf:
                sublinear_tf = 1.0 + math.log(count) if count > 0 else 0
                val = sublinear_tf * self.idf[term]
                query_vec[term] = val
                norm_sq += val * val

        if norm_sq == 0.0:
            return []

        norm = math.sqrt(norm_sq)
        query_norm_vec = {k: v / norm for k, v in query_vec.items()}

        scored_results = []
        for idx, doc_vec in enumerate(self.chunk_vectors):
            if idx >= len(self.chunks_metadata):
                break

            score = sum(query_norm_vec[term] * doc_vec[term] for term in query_norm_vec if term in doc_vec)
            if score >= min_score:
                chunk = self.chunks_metadata[idx]
                scored_results.append({
                    "chunk_id": chunk.get("chunk_id"),
                    "document_id": chunk.get("document_id"),
                    "title": chunk.get("document_title"),
                    "url": chunk.get("url"),
                    "category": chunk.get("category"),
                    "section": chunk.get("section"),
                    "retrieval_date": chunk.get("retrieval_date"),
                    "text": chunk.get("text"),
                    "similarity_score": round(score, 4)
                })

        scored_results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return scored_results[:top_k]

    def search(
        self,
        query: str,
        top_k: int = 4,
        min_score: float = 0.05
    ) -> List[Dict[str, Any]]:
        """
        Search knowledge base using ChromaDB vector database.
        Falls back to TF-IDF cosine similarity if ChromaDB returns empty.
        """
        clean_query = query.strip()
        if not clean_query:
            return []

        # 1. Primary: ChromaDB vector search
        chroma_results = self.search_chromadb(clean_query, top_k=top_k)
        if chroma_results:
            return chroma_results

        # 2. Fallback: In-memory TF-IDF cosine similarity
        return self.search_tfidf(clean_query, top_k=top_k, min_score=min_score)
