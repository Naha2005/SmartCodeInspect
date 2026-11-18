import json
import math
from pathlib import Path
from typing import List, Dict, Any, Optional
from .ingest import tokenize

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent
INDEX_DIR = PROJECT_ROOT / "knowledge_base" / "index"

# High-precision semantic query expansion mapping for OWASP, CWE, and SmartCodeInspect rules
QUERY_EXPANSIONS = {
    # Python Security Rules
    "sec-py-001": "eval exec dynamic arbitrary code execution CWE-95 CWE-94 ast.literal_eval",
    "sec-py-002": "subprocess os.system shell=True command injection CWE-78 shlex.quote argument list",
    "sec-py-003": "sql injection sqlite3 cursor execute string formatting CWE-89 parameterized query placeholder",
    "sec-py-004": "hardcoded api key secret password token credential CWE-798 os.environ dotenv",
    "sec-py-005": "pickle insecure deserialization untrusted yaml load CWE-502 safe json schema",
    "sec-py-006": "path traversal directory traversal os.path.join CWE-22 normalize resolve",
    "sec-py-007": "weak broken hash md5 sha1 cryptographic failures CWE-327 sha256 hashlib",

    # Java Security Rules
    "sec-jv-001": "sql injection jdbc createStatement query string concatenation CWE-89 PreparedStatement setString",
    "sec-jv-002": "command injection Runtime.getRuntime().exec ProcessBuilder CWE-78 argument array",
    "sec-jv-003": "hardcoded db password secret credential token CWE-798 System.getenv",
    "sec-jv-004": "insecure deserialization ObjectInputStream readObject CWE-502 ObjectInputFilter allowlist",
    "sec-jv-005": "path traversal directory traversal File CWE-22 getCanonicalPath getPath startsWith",
    "sec-jv-006": "weak hash md5 sha1 MessageDigest CWE-327 SHA-256",
    "sec-jv-007": "xml external entity xxe DocumentBuilderFactory setFeature CWE-611 disallow-doctype-decl",

    # Risky Call AST Rules
    "risk-py-001": "network request requests.get post missing timeout CWE-400 resource exhaustion",
    "risk-py-002": "unhandled network socket exception connection error RequestException try-except",
    "risk-py-003": "database connection transaction unhandled DatabaseError rollback cursor commit",
    "risk-jv-001": "jdbc connection unmanaged resource leak try-with-resources AutoCloseable SQLException",
    "risk-jv-002": "HttpURLConnection socket network missing connect read timeout",

    # Code Quality & Smells
    "smell-py-001": "mutable default argument list dict anti-pattern default parameter",
    "smell-py-002": "print statement debugging console log production logging",
    "smell-py-003": "resource leak unmanaged file open without with context manager",
    "smell-py-004": "empty exception handler silenced pass broad except Exception",

    # Common Acronyms & Short Queries
    "sqli": "sql injection CWE-89 parameterized query prepared statement",
    "xss": "cross-site scripting CWE-79 context-aware output encoding CSP",
    "xxe": "xml external entity injection CWE-611 disallow doctype declaration",
    "rce": "remote code execution command injection CWE-78 CWE-94",
    "ssrf": "server-side request forgery CWE-918 allowlist validation",
    "csrf": "cross-site request forgery CWE-352 anti-csrf token samesite",
    "cors": "cross-origin resource sharing access-control-allow-origin misconfiguration",
    "deser": "insecure deserialization CWE-502 gadget chains filter allowlist",
}


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

    def expand_query(self, query: str) -> str:
        """
        Augment user or agent query with canonical CWE, OWASP, and remediation terminology.
        Preserves original query tokens while boosting semantic recall across vectors.
        """
        clean_q = query.strip()
        if not clean_q:
            return ""

        q_lower = clean_q.lower()
        expanded_terms = []
        for trigger, expansion in QUERY_EXPANSIONS.items():
            if trigger in q_lower:
                expanded_terms.append(expansion)

        if expanded_terms:
            return f"{clean_q} {' '.join(expanded_terms)}"
        return clean_q

    def search_chromadb(self, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        """Search OWASP knowledge base using persistent ChromaDB embeddings with query expansion."""
        if self._chroma_collection is None:
            self.init_chroma()
        if self._chroma_collection is None:
            return []

        try:
            total_items = self._chroma_collection.count()
            if total_items == 0:
                return []

            expanded_query = self.expand_query(query)
            fetch_k = min(max(top_k * 2, 6), total_items)
            results = self._chroma_collection.query(
                query_texts=[expanded_query],
                n_results=fetch_k
            )

            scored_results = []
            if results and results.get("ids") and len(results["ids"]) > 0:
                ids = results["ids"][0]
                docs = results.get("documents", [[]])[0]
                metas = results.get("metadatas", [[]])[0]
                distances = results.get("distances", [[]])[0] if results.get("distances") else []

                seen_sections = set()
                for idx, chunk_id in enumerate(ids):
                    meta = metas[idx] if idx < len(metas) else {}
                    doc_text = docs[idx] if idx < len(docs) else ""
                    title = meta.get("title", "OWASP Standard")
                    section = meta.get("section", "General")
                    sec_key = (title, section)
                    if sec_key in seen_sections:
                        continue
                    seen_sections.add(sec_key)

                    dist = distances[idx] if idx < len(distances) else 0.5
                    sim_score = max(0.01, round(1.0 / (1.0 + float(dist)), 4)) if dist is not None else 0.85

                    scored_results.append({
                        "chunk_id": chunk_id,
                        "document_id": meta.get("document_id", ""),
                        "title": title,
                        "url": meta.get("url", "https://owasp.org/"),
                        "category": meta.get("category", "Standard"),
                        "section": section,
                        "retrieval_date": meta.get("retrieval_date", "2026-10-12"),
                        "text": doc_text,
                        "content": doc_text,  # Guarantee dual key compatibility
                        "similarity_score": sim_score
                    })
                    if len(scored_results) >= top_k:
                        break

            return scored_results
        except Exception:
            return []

    def search_tfidf(self, query: str, top_k: int = 4, min_score: float = 0.05) -> List[Dict[str, Any]]:
        """Compute cosine similarity between query and stored TF-IDF vectors with query expansion."""
        if not self._is_loaded or not self.idf or not self.chunk_vectors:
            if not self.load_index():
                return []

        expanded_query = self.expand_query(query)
        tokens = tokenize(expanded_query)
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
        seen_sections = set()
        for idx, doc_vec in enumerate(self.chunk_vectors):
            if idx >= len(self.chunks_metadata):
                break

            score = sum(query_norm_vec[term] * doc_vec[term] for term in query_norm_vec if term in doc_vec)
            if score >= min_score:
                chunk = self.chunks_metadata[idx]
                title = chunk.get("document_title", "OWASP Standard")
                section = chunk.get("section", "General")
                sec_key = (title, section)
                if sec_key in seen_sections:
                    continue
                seen_sections.add(sec_key)

                txt = chunk.get("text", "")
                scored_results.append({
                    "chunk_id": chunk.get("chunk_id"),
                    "document_id": chunk.get("document_id"),
                    "title": title,
                    "url": chunk.get("url"),
                    "category": chunk.get("category"),
                    "section": section,
                    "retrieval_date": chunk.get("retrieval_date"),
                    "text": txt,
                    "content": txt,  # Guarantee dual key compatibility
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
