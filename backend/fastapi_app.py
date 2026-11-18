import io
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from config import Config
from validators.python_validator import validate_python_source
from validators.java_validator import validate_java_source, detect_javac_availability
from analyzers.python_analyzer import analyze_python_source
from analyzers.java_analyzer import analyze_java_source
from knowledge_base.retriever import OWASPRetriever
from knowledge_base.ingest import run_ingestion
from agents.ai_provider import get_ai_explanation
from agents.remediation_agent import get_remediation_agent
from agents.pr_summary_agent import get_pr_summary_agent
from agents.conversational_agent import get_conversational_assistant
from agents.orchestrator import get_orchestrator
from reports.pdf_generator import generate_pdf_report
from reports.sarif_generator import generate_sarif_report

logger = logging.getLogger("smart_code_inspect")

app = FastAPI(
    title="Smart Code Inspection Platform API",
    description="Enterprise AST Static Analysis and OWASP Compliance API built with FastAPI and ChromaDB",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request schemas
class ValidateRequest(BaseModel):
    language: str
    source_code: str
    filename: Optional[str] = None


class AnalyzeRequest(BaseModel):
    language: str
    source_code: str
    filename: Optional[str] = None


class KnowledgeSearchRequest(BaseModel):
    query: str
    top_k: Optional[int] = 4
    min_score: Optional[float] = 0.05


class AIExplainRequest(BaseModel):
    finding: Dict[str, Any]
    owasp_passages: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


class ReportPDFRequest(BaseModel):
    source_code: Optional[str] = None
    language: Optional[str] = None
    filename: Optional[str] = "inspected_source"
    analysis_data: Optional[Dict[str, Any]] = None
    ai_explanation: Optional[Dict[str, Any]] = None


class ChatRequest(BaseModel):
    query: str
    history: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


class RemediationRequest(BaseModel):
    finding: Dict[str, Any]
    source_code: Optional[str] = None
    language: Optional[str] = None


class PRSummaryRequest(BaseModel):
    findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    summary: Optional[Dict[str, Any]] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class OrchestrateRequest(BaseModel):
    language: str
    source_code: str
    filename: Optional[str] = None


# Endpoints
@app.get("/api/health")
@app.get("/health")
def health_check():
    """Return backend operational status, Java compiler availability, and ChromaDB status."""
    java_status = detect_javac_availability()
    retriever = OWASPRetriever(Config.INDEX_DIR)
    kb_status = retriever.get_status()
    ai_status = Config.get_ai_status()

    return {
        "status": "healthy",
        "service": "Smart Code Inspection Platform API (FastAPI)",
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
            "algorithm": kb_status.get("vector_algorithm", "ChromaDB Vector Store"),
            "vector_database": kb_status.get("vector_database", "ChromaDB")
        },
        "ai_integration": ai_status
    }


@app.post("/api/validate")
@app.post("/validate")
def validate_code(req: ValidateRequest):
    """Validate Python syntax via ast.parse or Java compilation via javac."""
    lang = req.language.strip().lower()
    if lang not in ("python", "java"):
        raise HTTPException(status_code=400, detail=f"Unsupported language '{lang}'. Supported: python, java.")

    if lang == "python":
        res = validate_python_source(
            source_code=req.source_code,
            filename=req.filename,
            max_bytes=Config.MAX_SOURCE_BYTES
        )
    else:
        res = validate_java_source(
            source_code=req.source_code,
            filename=req.filename,
            timeout_seconds=Config.JAVA_COMPILE_TIMEOUT_SECONDS,
            max_bytes=Config.MAX_SOURCE_BYTES
        )

    clean_res = {k: v for k, v in res.items() if k != "parsed_ast"}
    return clean_res


@app.post("/api/analyze")
@app.post("/analyze")
def analyze_code(req: AnalyzeRequest):
    """Run deterministic static inspection rules on Python or Java source."""
    lang = req.language.strip().lower()
    if lang not in ("python", "java"):
        raise HTTPException(status_code=400, detail=f"Unsupported language '{lang}'. Supported: python, java.")

    try:
        if lang == "python":
            result = analyze_python_source(
                source_code=req.source_code,
                filename=req.filename,
                max_bytes=Config.MAX_SOURCE_BYTES
            )
        else:
            result = analyze_java_source(
                source_code=req.source_code,
                filename=req.filename,
                timeout_seconds=Config.JAVA_COMPILE_TIMEOUT_SECONDS,
                max_bytes=Config.MAX_SOURCE_BYTES
            )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis execution failed: {str(exc)}")


@app.post("/api/knowledge/search")
@app.post("/knowledge/search")
def search_knowledge(req: KnowledgeSearchRequest):
    """Search authentic OWASP knowledge base using ChromaDB vector database."""
    query = req.query.strip()
    if not query:
        return {"query": "", "results": [], "total_results": 0, "message": "Query parameter cannot be empty."}

    retriever = OWASPRetriever(Config.INDEX_DIR)
    results = retriever.search(query=query, top_k=req.top_k or 4, min_score=req.min_score or 0.05)

    return {
        "query": query,
        "results": results,
        "total_results": len(results),
        "algorithm": "ChromaDB Vector Store (with TF-IDF Hybrid Fallback)"
    }


@app.post("/api/knowledge/ingest")
@app.post("/knowledge/ingest")
def rebuild_knowledge():
    """Trigger ingestion pipeline and rebuild persistent ChromaDB vector store."""
    return run_ingestion()


@app.post("/api/ai/explain")
@app.post("/ai/explain")
def explain_finding(req: AIExplainRequest):
    """Generate advisory explanation for findings using Gemini/Groq or offline expert engine."""
    result = get_ai_explanation(finding=req.finding, owasp_passages=req.owasp_passages or [])
    if not result.get("success"):
        return JSONResponse(status_code=502, content=result)
    return result


@app.post("/api/reports/pdf")
@app.post("/reports/pdf")
def download_pdf(req: ReportPDFRequest):
    """Generate cryptographic audit PDF report using ReportLab."""
    analysis_data = None
    lang = (req.language or "").strip().lower()

    if req.analysis_data and isinstance(req.analysis_data, dict):
        analysis_data = req.analysis_data
        if req.ai_explanation and "ai_explanation" not in analysis_data:
            analysis_data["ai_explanation"] = req.ai_explanation
    elif req.source_code and lang in ("python", "java"):
        try:
            orchestrator = get_orchestrator()
            analysis_data = orchestrator.run_parallel_analysis(
                source_code=req.source_code,
                language=lang,
                filename=req.filename or "inspected_source"
            )
        except Exception:
            if lang == "python":
                analysis_data = analyze_python_source(req.source_code, filename=req.filename)
            else:
                analysis_data = analyze_java_source(req.source_code, filename=req.filename)
        if req.ai_explanation:
            analysis_data["ai_explanation"] = req.ai_explanation
    else:
        raise HTTPException(status_code=400, detail="Missing valid analysis_data or source_code.")

    try:
        pdf_stream = generate_pdf_report(analysis_data)
        safe_filename = (req.filename or "inspected_source").replace("/", "_").replace("\\", "_")
        if not safe_filename.endswith(".pdf"):
            safe_filename += "_security_report.pdf"

        return StreamingResponse(
            pdf_stream,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(exc)}")


@app.post("/api/reports/sarif")
@app.post("/reports/sarif")
def download_sarif(req: ReportPDFRequest):
    """Generate OASIS SARIF v2.1.0 standard report for CI/CD and GitHub Code Scanning."""
    analysis_data = None
    lang = (req.language or "").strip().lower()

    if req.analysis_data and isinstance(req.analysis_data, dict):
        analysis_data = req.analysis_data
    elif req.source_code and lang in ("python", "java"):
        try:
            orchestrator = get_orchestrator()
            analysis_data = orchestrator.run_parallel_analysis(
                source_code=req.source_code,
                language=lang,
                filename=req.filename or "inspected_source"
            )
        except Exception:
            if lang == "python":
                analysis_data = analyze_python_source(req.source_code, filename=req.filename)
            else:
                analysis_data = analyze_java_source(req.source_code, filename=req.filename)
    else:
        raise HTTPException(status_code=400, detail="Missing valid analysis_data or source_code.")

    try:
        sarif_json = generate_sarif_report(analysis_data, filename=req.filename)
        return sarif_json
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate SARIF report: {str(exc)}")


@app.post("/api/orchestrate")
@app.post("/orchestrate")
def orchestrate_code(req: OrchestrateRequest):
    """Execute parallel multi-agent analysis (Code Analysis + Security + Remediation + PR Summary)."""
    lang = req.language.strip().lower()
    if lang not in ("python", "java"):
        raise HTTPException(status_code=400, detail=f"Unsupported language '{lang}'.")
    try:
        orchestrator = get_orchestrator()
        return orchestrator.run_parallel_analysis(
            source_code=req.source_code,
            language=lang,
            filename=req.filename
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Orchestration failed: {str(exc)}")


@app.post("/api/chat")
@app.post("/api/ai/chat")
@app.post("/chat")
def conversational_chat(req: ChatRequest):
    """Conversational Code Assistant grounded in authentic OWASP knowledge base."""
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    try:
        assistant = get_conversational_assistant()
        return assistant.ask(
            query=req.query,
            history=req.history,
            context=req.context
        )
    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "response": "An error occurred while answering your question.",
            "citations": []
        }


@app.post("/api/remediate")
@app.post("/remediate")
def remediate_finding(req: RemediationRequest):
    """Generate specific fix recommendation with corrected code example."""
    try:
        agent = get_remediation_agent()
        remediation = agent.generate_remediation(
            finding=req.finding,
            source_code=req.source_code,
            language=req.language
        )
        return {"success": True, "remediation": remediation}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/pr-summary")
@app.post("/pr-summary")
def pr_summary(req: PRSummaryRequest):
    """Generate structured PR Review summary and markdown report."""
    try:
        agent = get_pr_summary_agent()
        return agent.generate_pr_summary(
            findings=req.findings,
            summary=req.summary,
            metadata=req.metadata
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("fastapi_app:app", host=Config.HOST, port=Config.PORT, reload=Config.FLASK_DEBUG)
