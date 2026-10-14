import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any
from bs4 import BeautifulSoup

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent
DOCUMENTS_DIR = PROJECT_ROOT / "knowledge_base" / "documents"
INDEX_DIR = PROJECT_ROOT / "knowledge_base" / "index"
SOURCES_FILE = PROJECT_ROOT / "knowledge_base" / "sources.json"

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can", "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does",
    "doesn't", "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had",
    "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her",
    "here", "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd",
    "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself",
    "let's", "me", "more", "most", "mustn't", "my", "myself", "no", "nor", "not", "of", "off",
    "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own",
    "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there",
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through",
    "to", "too", "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're",
    "we've", "were", "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would", "wouldn't", "you",
    "you'd", "you'll", "you're", "you've", "your", "yours", "yourself", "yourselves"
}


def clean_html_or_markdown(raw_text: str) -> str:
    soup = BeautifulSoup(raw_text, "html.parser")
    text = soup.get_text(separator=" ")
    text = re.sub(r'```[a-zA-Z]*\n', '', text)
    text = text.replace('```', '')
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def tokenize(text: str) -> List[str]:
    words = re.findall(r'[a-zA-Z0-9_\-]+', text.lower())
    return [w for w in words if len(w) > 1 and w not in STOPWORDS]


def chunk_document(
    doc_id: str,
    doc_title: str,
    doc_url: str,
    category: str,
    raw_content: str,
    chunk_size: int = 500,
    overlap: int = 100
) -> List[Dict[str, Any]]:
    chunks = []
    sections = re.split(r'\n(?=##?\s+)', raw_content)
    chunk_index = 0

    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue

        lines = sec.splitlines()
        section_title = lines[0].replace("#", "").strip() if lines else "General"
        cleaned_body = clean_html_or_markdown(sec)

        if len(cleaned_body) <= chunk_size:
            chunks.append({
                "chunk_id": f"{doc_id}_{chunk_index}",
                "document_id": doc_id,
                "document_title": doc_title,
                "url": doc_url,
                "category": category,
                "section": section_title,
                "retrieval_date": "2026-10-11",
                "text": cleaned_body
            })
            chunk_index += 1
        else:
            start = 0
            while start < len(cleaned_body):
                end = min(start + chunk_size, len(cleaned_body))
                chunk_slice = cleaned_body[start:end].strip()
                if chunk_slice:
                    chunks.append({
                        "chunk_id": f"{doc_id}_{chunk_index}",
                        "document_id": doc_id,
                        "document_title": doc_title,
                        "url": doc_url,
                        "category": category,
                        "section": section_title,
                        "retrieval_date": "2026-10-11",
                        "text": chunk_slice
                    })
                    chunk_index += 1
                if end == len(cleaned_body):
                    break
                start += (chunk_size - overlap)

    return chunks


def build_pure_python_vector_index(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a pure-Python TF-IDF vector space model and inverted index.
    Zero C DLL requirements, completely immune to Windows DLL AppLocker policies.
    """
    num_docs = len(chunks)
    doc_term_freqs = []
    doc_freqs = Counter()

    for chunk in chunks:
        tokens = tokenize(chunk["text"])
        tf = Counter(tokens)
        doc_term_freqs.append(tf)
        for term in tf.keys():
            doc_freqs[term] += 1

    # Compute IDF: log((N + 1) / (df + 1)) + 1
    idf = {}
    for term, df in doc_freqs.items():
        idf[term] = math.log((num_docs + 1) / (df + 1)) + 1.0

    # Build normalized TF-IDF vectors for all chunks
    chunk_vectors = []
    for tf in doc_term_freqs:
        vec = {}
        norm_sq = 0.0
        for term, count in tf.items():
            # sublinear tf: 1 + log(tf)
            sublinear_tf = 1.0 + math.log(count) if count > 0 else 0
            val = sublinear_tf * idf.get(term, 1.0)
            vec[term] = val
            norm_sq += val * val

        norm = math.sqrt(norm_sq) if norm_sq > 0 else 1.0
        # Normalize unit vector
        normalized_vec = {k: v / norm for k, v in vec.items()}
        chunk_vectors.append(normalized_vec)

    return {
        "idf": idf,
        "chunk_vectors": chunk_vectors,
        "vocabulary_size": len(idf)
    }


def run_ingestion() -> Dict[str, Any]:
    """
    Execute full ingestion pipeline:
    1. Read sources metadata catalog
    2. Read authentic OWASP document texts
    3. Generate chunks with overlap and metadata
    4. Compute persistent TF-IDF Vector Space Model
    5. Save persistent vector model and chunks metadata to disk
    """
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)

    sources_by_file = {
        "owasp_top_ten_2025.md": ("owasp-top-10", "OWASP Top 10: 2025", "https://top10.owasp.org/2025/", "Standard"),
        "sql_injection_prevention.md": ("sql-injection-prevention", "OWASP SQL Injection Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "Cheat Sheet"),
        "os_command_injection_defense.md": ("os-command-injection", "OWASP OS Command Injection Defense Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html", "Cheat Sheet"),
        "xss_prevention.md": ("xss-prevention", "OWASP Cross Site Scripting Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", "Cheat Sheet"),
        "deserialization_cheat_sheet.md": ("deserialization-prevention", "OWASP Deserialization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html", "Cheat Sheet"),
        "cryptographic_storage.md": ("cryptographic-storage", "OWASP Cryptographic Storage Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html", "Cheat Sheet"),
        # New secure coding standard documents
        "authentication_cheat_sheet.md": ("authentication", "OWASP Authentication Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "Cheat Sheet"),
        "input_validation_cheat_sheet.md": ("input-validation", "OWASP Input Validation Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html", "Cheat Sheet"),
        "secrets_management_cheat_sheet.md": ("secrets-management", "OWASP Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html", "Cheat Sheet"),
        "broken_access_control.md": ("broken-access-control", "OWASP Broken Access Control Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html", "Cheat Sheet"),
        "security_misconfiguration.md": ("security-misconfiguration", "OWASP Security Misconfiguration Cheat Sheet", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "Standard"),
        "ssrf_prevention.md": ("ssrf-prevention", "OWASP Server-Side Request Forgery Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html", "Cheat Sheet"),
        "path_traversal_prevention.md": ("path-traversal-prevention", "OWASP Path Traversal & Safe File Access Cheat Sheet", "https://owasp.org/www-community/attacks/Path_Traversal", "Cheat Sheet"),
        "secure_file_uploads.md": ("secure-file-uploads", "OWASP Secure File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html", "Cheat Sheet"),
        "api_security.md": ("api-security", "OWASP API Security Best Practices Cheat Sheet", "https://owasp.org/www-project-api-security/", "Standard"),
    }

    all_chunks: List[Dict[str, Any]] = []
    doc_files = list(DOCUMENTS_DIR.glob("*.md")) + list(DOCUMENTS_DIR.glob("*.html"))

    for file_path in doc_files:
        meta = sources_by_file.get(file_path.name, (
            file_path.stem,
            file_path.stem.replace("_", " ").title(),
            "https://owasp.org/",
            "Security Document"
        ))
        raw_text = file_path.read_text(encoding="utf-8")
        file_chunks = chunk_document(
            doc_id=meta[0],
            doc_title=meta[1],
            doc_url=meta[2],
            category=meta[3],
            raw_content=raw_text
        )
        all_chunks.extend(file_chunks)

    if not all_chunks:
        return {
            "status": "empty",
            "message": "No documents found to ingest.",
            "documents_count": 0,
            "chunks_count": 0
        }

    # Build TF-IDF Vector Index
    vector_index = build_pure_python_vector_index(all_chunks)

    # Persist chunks metadata
    with open(INDEX_DIR / "chunks_metadata.json", "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, indent=2)

    # Persist vector index
    with open(INDEX_DIR / "vector_index.json", "w", encoding="utf-8") as f:
        json.dump(vector_index, f, indent=2)

    # Persist into ChromaDB Collection
    chroma_indexed = False
    try:
        import chromadb
        chroma_dir = INDEX_DIR / "chroma"
        chroma_dir.mkdir(parents=True, exist_ok=True)
        chroma_client = chromadb.PersistentClient(path=str(chroma_dir))
        
        # Reset or re-populate collection
        try:
            chroma_client.delete_collection("owasp_guidelines")
        except Exception:
            pass
            
        collection = chroma_client.get_or_create_collection(
            name="owasp_guidelines",
            metadata={"description": "OWASP Security Guidelines Knowledge Base"}
        )
        
        # Batch add documents
        c_ids = [c["chunk_id"] for c in all_chunks]
        c_docs = [c["text"] for c in all_chunks]
        c_metas = [
            {
                "document_id": str(c.get("document_id", "")),
                "title": str(c.get("document_title", "")),
                "url": str(c.get("url", "")),
                "category": str(c.get("category", "")),
                "section": str(c.get("section", "")),
                "retrieval_date": str(c.get("retrieval_date", ""))
            }
            for c in all_chunks
        ]
        
        # Chroma supports batching
        batch_size = 100
        for i in range(0, len(c_ids), batch_size):
            collection.add(
                ids=c_ids[i:i + batch_size],
                documents=c_docs[i:i + batch_size],
                metadatas=c_metas[i:i + batch_size]
            )
        chroma_indexed = True
    except Exception as e:
        print(f"Warning: ChromaDB indexing encountered an issue: {e}")

    status_data = {
        "status": "ready",
        "vector_algorithm": "ChromaDB Vector Store (with TF-IDF Hybrid Fallback)",
        "documents_count": len(doc_files),
        "chunks_count": len(all_chunks),
        "chroma_indexed": chroma_indexed,
        "vocabulary_size": vector_index["vocabulary_size"],
        "index_directory": str(INDEX_DIR),
        "timestamp": "2026-10-12T19:00:00"
    }

    with open(INDEX_DIR / "status.json", "w", encoding="utf-8") as f:
        json.dump(status_data, f, indent=2)

    return status_data


if __name__ == "__main__":
    result = run_ingestion()
    print("Ingestion Result:", json.dumps(result, indent=2))
