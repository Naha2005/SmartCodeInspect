import pytest
from knowledge_base.ingest import chunk_document, clean_html_or_markdown, tokenize, build_pure_python_vector_index
from knowledge_base.retriever import OWASPRetriever


def test_clean_html_or_markdown():
    raw = "<h3>Title</h3><p>Text with <code>code</code> and ```bash\nrm -rf /```</p>"
    cleaned = clean_html_or_markdown(raw)
    assert "Title" in cleaned
    assert "Text with" in cleaned
    assert "<p>" not in cleaned


def test_chunk_document_preserves_metadata():
    raw_doc = """## Section 1: Introduction
This is the introduction text for security testing.

## Section 2: Implementation Details
This is the second section discussing prevention techniques in detail.
"""
    chunks = chunk_document(
        doc_id="test-doc",
        doc_title="Test Document",
        doc_url="https://owasp.org/test",
        category="Standard",
        raw_content=raw_doc,
        chunk_size=200,
        overlap=50
    )
    assert len(chunks) >= 2
    first_chunk = chunks[0]
    assert first_chunk["document_id"] == "test-doc"
    assert first_chunk["document_title"] == "Test Document"
    assert first_chunk["url"] == "https://owasp.org/test"
    assert "retrieval_date" in first_chunk
    assert len(first_chunk["text"]) > 0


def test_pure_python_vector_indexing():
    sample_chunks = [
        {"chunk_id": "c1", "text": "SQL injection prevention using parameterized prepared statements."},
        {"chunk_id": "c2", "text": "Cross-site scripting XSS prevention through HTML output encoding."},
        {"chunk_id": "c3", "text": "Command injection defense by avoiding system shells and execve."}
    ]
    index_data = build_pure_python_vector_index(sample_chunks)
    assert "idf" in index_data
    assert "chunk_vectors" in index_data
    assert len(index_data["chunk_vectors"]) == 3
    assert index_data["vocabulary_size"] > 0


def test_retriever_search_live_index():
    retriever = OWASPRetriever()
    status = retriever.get_status()
    assert status["status"] == "ready"
    assert status["chunks_count"] > 0

    results = retriever.search("parameterized queries sql injection", top_k=3)
    assert len(results) > 0
    top = results[0]
    assert "similarity_score" in top
    assert top["similarity_score"] > 0
    assert "url" in top
    assert "title" in top


def test_retriever_empty_query():
    retriever = OWASPRetriever()
    assert retriever.search("") == []
    assert retriever.search("   ") == []
