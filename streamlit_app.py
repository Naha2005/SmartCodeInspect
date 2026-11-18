import io
import json
# pyrefly: ignore [missing-import]
import streamlit as st
from pathlib import Path
import sys

# Ensure backend directory is in path
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
try:
    from backend.validators.python_validator import validate_python_source
    from backend.validators.java_validator import validate_java_source, detect_javac_availability
    from backend.analyzers.python_analyzer import analyze_python_source
    from backend.analyzers.java_analyzer import analyze_java_source
    from backend.knowledge_base.retriever import OWASPRetriever
    from backend.knowledge_base.ingest import run_ingestion
    from backend.agents.ai_provider import get_ai_explanation
    from backend.agents.orchestrator import get_orchestrator
    from backend.agents.remediation_agent import get_remediation_agent
    from backend.agents.pr_summary_agent import get_pr_summary_agent
    from backend.agents.conversational_agent import get_conversational_assistant
    from backend.reports.pdf_generator import generate_pdf_report
    from backend.config import Config
except ImportError:
    from validators.python_validator import validate_python_source  # type: ignore
    from validators.java_validator import validate_java_source, detect_javac_availability  # type: ignore
    from analyzers.python_analyzer import analyze_python_source  # type: ignore
    from analyzers.java_analyzer import analyze_java_source  # type: ignore
    from knowledge_base.retriever import OWASPRetriever  # type: ignore
    from knowledge_base.ingest import run_ingestion  # type: ignore
    from agents.ai_provider import get_ai_explanation  # type: ignore
    from agents.orchestrator import get_orchestrator  # type: ignore
    from agents.remediation_agent import get_remediation_agent  # type: ignore
    from agents.pr_summary_agent import get_pr_summary_agent  # type: ignore
    from agents.conversational_agent import get_conversational_assistant  # type: ignore
    from reports.pdf_generator import generate_pdf_report  # type: ignore
    from config import Config  # type: ignore

# Streamlit Page Setup
st.set_page_config(
    page_title="Smart Code Inspection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #94a3b8;
        font-size: 1.0rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 12px;
        border: 1px solid #334155;
    }
    .finding-critical {
        border-left: 4px solid #ef4444;
        background-color: rgba(239, 68, 68, 0.1);
        padding: 10px;
        border-radius: 4px;
        margin-bottom: 8px;
    }
    .finding-high {
        border-left: 4px solid #f97316;
        background-color: rgba(249, 115, 22, 0.1);
        padding: 10px;
        border-radius: 4px;
        margin-bottom: 8px;
    }
    .finding-medium {
        border-left: 4px solid #eab308;
        background-color: rgba(234, 179, 8, 0.1);
        padding: 10px;
        border-radius: 4px;
        margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Sample Code Library (3 Distinct Complexity Tiers)
SAMPLE_PYTHON_CLEAN = '''import math
from typing import List, Union

def calculate_statistics(numbers: List[Union[int, float]]) -> dict:
    """Safely calculate basic statistical metrics without eval or unsafe execution."""
    if not numbers:
        return {"mean": 0.0, "variance": 0.0, "std_dev": 0.0}
    
    mean = sum(numbers) / len(numbers)
    variance = sum((x - mean) ** 2 for x in numbers) / len(numbers)
    std_dev = math.sqrt(variance)
    
    return {
        "count": len(numbers),
        "mean": round(mean, 4),
        "variance": round(variance, 4),
        "std_dev": round(std_dev, 4)
    }
'''

SAMPLE_PYTHON_MODERATE = '''import json
from typing import Dict, Any, List

# Quality: Mutable default argument anti-pattern
def process_pipeline_batch(records: List[Dict[str, Any]], error_log=[]):
    """Processes batch ETL records with maintainability smells."""
    # Quality: Print statement in production
    print(f"Starting batch of {len(records)} items")
    
    # Quality: Resource leak / unmanaged file descriptor
    metrics_file = open("pipeline.log", "a")
    metrics_file.write(f"Processed: {len(records)}\\n")
    
    results = []
    for item in records:
        if item.get("status") == "ACTIVE":
            results.append(item.get("id"))
        else:
            # Quality: Silenced error / empty exception handler
            try:
                error_log.append(item.get("id"))
            except Exception:
                pass
                
    metrics_file.close()
    return results
'''

SAMPLE_PYTHON_VULNERABLE = '''import os
import subprocess
import sqlite3
import pickle

def run_user_cmd(cmd):
    # SEC-PY-002 OS Command Injection
    os.system("echo " + cmd)
    subprocess.Popen(cmd, shell=True)

def query_user(user_id):
    conn = sqlite3.connect("users.db")
    # SEC-PY-003 SQL Injection
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return conn.execute(query).fetchall()

def dangerous_exec(code):
    # SEC-PY-001 Code Execution
    eval(code)
'''

SAMPLE_JAVA_CLEAN = '''import java.math.BigDecimal;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class SecureBankTransfer {
    private final String accountId;
    private BigDecimal balance;

    public SecureBankTransfer(String accountId, BigDecimal initialBalance) {
        this.accountId = accountId;
        this.balance = initialBalance;
    }

    public synchronized void transfer(BigDecimal amount) {
        if (amount != null && amount.compareTo(BigDecimal.ZERO) > 0 && this.balance.compareTo(amount) >= 0) {
            this.balance = this.balance.subtract(amount);
        }
    }
}
'''

SAMPLE_JAVA_MODERATE = '''import java.util.*;

public class OrderNotificationManager {
    // Quality: Long parameter list smell
    public void dispatchOrderAlert(
        long orderId,
        String customerEmail,
        String customerPhone,
        double orderTotal,
        int priorityTier,
        boolean isExpressShipping,
        String destinationRegion
    ) {
        // Quality: Console output left in production code
        System.out.println("Processing order: " + orderId);

        // Quality: Empty catch block / swallowed exception
        try {
            if (orderTotal > 0) {
                // routing logic
            }
        } catch (Exception e) {
        }
    }
}
'''

SAMPLE_JAVA_VULNERABLE = '''import java.sql.*;
import java.io.IOException;

public class SecurityDemo {
    public void getUser(Connection conn, String input) throws SQLException {
        // SEC-JV-001 SQL Injection
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + input + "'");
    }

    public void runCommand(String userCmd) throws IOException {
        // SEC-JV-002 Command Injection
        Runtime.getRuntime().exec("sh -c " + userCmd);
    }
}
'''

# Sidebar Configuration
with st.sidebar:
    st.image("https://raw.githubusercontent.com/github/explore/main/topics/security/security.png", width=64)
    st.title("Settings & Status")

    # System Status
    retriever = OWASPRetriever(Config.INDEX_DIR)
    kb_status = retriever.get_status()
    javac_status = detect_javac_availability()

    st.subheader("Engine Status")
    st.write(f"**Vector DB:** `{kb_status.get('vector_database', 'ChromaDB')}`")
    st.write(f"**OWASP Chunks:** `{kb_status.get('chunks_count', 0)}` indexed")
    st.write(f"**Java Compiler:** `{'Available' if javac_status.get('available') else 'Not Found'}`")
    
    st.divider()

    language = st.selectbox(
        "Inspection Language",
        options=["Python", "Java"],
        index=0
    )

    sample_choice = st.selectbox(
        "Load Sample Template (3 Tiers)",
        options=[
            "None",
            "🟢 Low Complexity: Clean & Secure",
            "🟡 Moderate Complexity: Code Smells",
            "🔴 High Complexity: OWASP Vulnerable"
        ]
    )

    if st.button("🔄 Reindex ChromaDB", use_container_width=True):
        with st.spinner("Ingesting OWASP documents into ChromaDB..."):
            ingest_res = run_ingestion()
            st.success(f"Indexed {ingest_res.get('chunks_count')} chunks successfully!")
            st.rerun()

# Main Header
st.markdown('<div class="main-header">🛡️ Smart Code Inspection Platform</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Zero-Execution AST Static Security Analysis &bull; OWASP Top 10 &bull; ChromaDB Vector Engine</div>', unsafe_allow_html=True)

# Default code value
default_code = ""
if "Low Complexity" in sample_choice:
    default_code = SAMPLE_PYTHON_CLEAN if language == "Python" else SAMPLE_JAVA_CLEAN
elif "Moderate Complexity" in sample_choice:
    default_code = SAMPLE_PYTHON_MODERATE if language == "Python" else SAMPLE_JAVA_MODERATE
elif "High Complexity" in sample_choice or sample_choice == "Vulnerable Sample":
    default_code = SAMPLE_PYTHON_VULNERABLE if language == "Python" else SAMPLE_JAVA_VULNERABLE

# Code Input
col_editor, col_search = st.columns([7, 3])

with col_editor:
    filename = st.text_input("Source Filename", value=f"InspectSample.{'py' if language == 'Python' else 'java'}")
    source_code = st.text_area(
        "Source Code to Inspect",
        value=default_code,
        height=320,
        placeholder="// Paste your source code here..."
    )

    btn_validate, btn_analyze, _ = st.columns([1, 1, 3])
    do_validate = btn_validate.button("🔍 Validate Syntax", use_container_width=True)
    do_analyze = btn_analyze.button("⚡ Inspect Code", type="primary", use_container_width=True)

with col_search:
    st.subheader("📚 OWASP ChromaDB Search")
    kb_query = st.text_input("Semantic Query", placeholder="e.g. prepared statement, command injection")
    if kb_query:
        kb_results = retriever.search(kb_query, top_k=3)
        if kb_results:
            for item in kb_results:
                with st.expander(f"{item.get('title')} ({item.get('similarity_score')})"):
                    st.caption(f"Section: {item.get('section')}")
                    st.write(item.get("text", "")[:350] + "...")
                    if item.get("url"):
                        st.markdown(f"[Official Documentation]({item.get('url')})")
        else:
            st.info("No OWASP matches found.")

# Trigger Analysis
if do_validate and source_code.strip():
    with st.spinner("Validating syntax..."):
        lang_key = language.lower()
        if lang_key == "python":
            val_res = validate_python_source(source_code, filename=filename)
        else:
            val_res = validate_java_source(source_code, filename=filename)

        if val_res.get("valid_syntax"):
            st.success(f"Syntax valid! {val_res.get('total_lines', 0)} lines analyzed safely.")
        else:
            st.error("Syntax errors or diagnostics detected:")
            for d in val_res.get("diagnostics", []):
                st.warning(f"Line {d.get('line')}: {d.get('message')}")

if do_analyze and source_code.strip():
    with st.spinner("Executing Multi-Agent Pipeline (Code Analysis + Security + Remediation + PR Summary)..."):
        lang_key = language.lower()
        orchestrator = get_orchestrator()
        orch_res = orchestrator.run_parallel_analysis(source_code, lang_key, filename=filename)

        # Enrich findings with Remediation Agent
        remediation_agent = get_remediation_agent()
        raw_findings = orch_res.get("findings", [])
        enriched_findings = []
        for f in raw_findings:
            rem = remediation_agent.generate_remediation(f, language=lang_key, source_code=source_code)
            f_copy = dict(f)
            f_copy["remediation"] = rem
            enriched_findings.append(f_copy)

        # Generate PR Summary with PR Summary Agent
        pr_agent = get_pr_summary_agent()
        pr_summary = pr_agent.generate_pr_summary(
            findings=enriched_findings,
            summary=orch_res.get("summary", {}),
            metadata={"filename": filename, "language": lang_key}
        )

        st.session_state["latest_analysis"] = {
            "findings": enriched_findings,
            "summary": orch_res.get("summary", {}),
            "pr_summary": pr_summary,
            "language": lang_key,
            "filename": filename,
            "source_code": source_code
        }

if "latest_analysis" in st.session_state:
    analysis = st.session_state["latest_analysis"]
    summary = analysis.get("summary", {})
    findings = analysis.get("findings", [])
    pr_summary = analysis.get("pr_summary", {})

    st.divider()

    # Tabs for Milestone 3 Developer Experience
    tab_findings, tab_pr_summary, tab_assistant = st.tabs([
        f"🚨 Findings & Remediation ({len(findings)})",
        "📋 PR Review Summary",
        "💬 Conversational Assistant (ChromaDB RAG)"
    ])

    # ── TAB 1: FINDINGS & REMEDIATION ──
    with tab_findings:
        st.subheader("📊 Multi-Agent Inspection Metrics")

        # Metrics Row
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Health Score", f"{summary.get('overall_code_health_score', 85)}/100")
        m2.metric("Total Findings", summary.get("total_findings", len(findings)))
        m3.metric("Critical", summary.get("critical", 0))
        m4.metric("High", summary.get("high", 0))
        m5.metric("Medium", summary.get("medium", 0))
        m6.metric("Low", summary.get("low", 0))

        # ── 6-DIMENSIONAL QUALITY RADAR OVERVIEW ──
        radar_scores = summary.get("radar_scores")
        if radar_scores:
            st.markdown("##### 🕸️ 6-Dimensional Code Quality Assessment")
            r1, r2, r3, r4, r5, r6 = st.columns(6)
            dims = [
                ("Code Quality", "🔍", r1),
                ("Security", "🛡️", r2),
                ("Complexity", "⚡", r3),
                ("Maintainability", "🧩", r4),
                ("Best Practices", "✨", r5),
                ("Input Validation", "🚪", r6),
            ]
            for name, icon, col in dims:
                val = radar_scores.get(name, 100)
                col.metric(f"{icon} {name}", f"{val}/100")

            breakdown = summary.get("score_breakdown")
            if breakdown and breakdown.get("narrative_explanation"):
                st.caption(f"ℹ️ **Scoring Engine Explanation:** {breakdown['narrative_explanation']}")

        if findings:
            for idx, f in enumerate(findings):
                sev = f.get("severity", "MEDIUM").upper()
                css_class = "finding-critical" if sev == "CRITICAL" else ("finding-high" if sev == "HIGH" else "finding-medium")
                rule_id = f.get("rule_id", "RULE")
                title = f.get("title", "Finding")
                line_no = f.get("line") or f.get("line_number", "N/A")
                agent = f.get("agent", "Security Agent")

                with st.container():
                    st.markdown(f"""
                    <div class="{css_class}">
                        <strong>[{rule_id}] {title}</strong> &bull; 
                        <span>Line {line_no}</span> &bull; 
                        <span style="font-weight:bold;">{sev}</span> &bull;
                        <span style="color:#94a3b8; font-size:0.85rem;">Agent: {agent}</span>
                        <p style="margin-top: 4px; margin-bottom: 2px;">{f.get('description', '')}</p>
                    </div>
                    """, unsafe_allow_html=True)

                    if f.get("evidence"):
                        st.code(f.get("evidence"), language=language.lower())

                    # Remediation details from Remediation Agent
                    rem = f.get("remediation")
                    if rem:
                        st.info(f"💡 **Remediation Recommendation:** {rem.get('recommendation', 'Apply secure pattern.')}")
                        if rem.get("corrected_code"):
                            with st.expander("🛠️ View Corrected Code Example"):
                                st.code(rem.get("corrected_code"), language=language.lower())
                                if rem.get("best_practice_explanation"):
                                    st.caption(f"**Best Practice:** {rem.get('best_practice_explanation')}")

                    if f.get("owasp_citations"):
                        st.caption(f"📚 OWASP Standards: {', '.join(f.get('owasp_citations'))}")
        else:
            st.success("🎉 No security vulnerabilities or code defects detected in the submitted source code!")

        # Downloads Row
        st.divider()
        col_pdf, col_clean = st.columns([1, 1])
        with col_pdf:
            pdf_buf = generate_pdf_report(analysis)
            st.download_button(
                label="📄 Download Official PDF Audit Report",
                data=pdf_buf.getvalue(),
                file_name=f"{filename}_security_audit.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        with col_clean:
            st.download_button(
                label=f"📥 Download Clean Code (.{'py' if language == 'Python' else 'java'})",
                data=source_code,
                file_name=f"clean_{filename}",
                mime="text/plain",
                use_container_width=True
            )

    # ── TAB 2: PR SUMMARY AGENT REVIEW ──
    with tab_pr_summary:
        st.subheader("📋 Pull Request Code Review & Merge Audit")

        verdict = pr_summary.get("verdict", {})
        decision = verdict.get("decision", "CHANGES_REQUESTED")
        if decision == "APPROVED":
            st.success(f"### {verdict.get('label', '🟢 Approved')}\n{verdict.get('reason', 'Safe for merge.')}")
        else:
            st.error(f"### {verdict.get('label', '🔴 Changes Requested')}\n{verdict.get('reason', 'Blockers detected.')}")

        st.markdown("#### 📝 Merge Readiness Checklist")
        checklist = pr_summary.get("merge_checklist", [])
        for item in checklist:
            st.checkbox(item, value=False, key=f"chk_{item}")

        st.markdown("#### 📄 PR Comment Markdown")
        md_text = pr_summary.get("markdown", "")
        st.text_area("Copy for GitHub / GitLab PR Comment", value=md_text, height=180)
        st.download_button(
            label="📥 Download PR_REVIEW.md",
            data=md_text,
            file_name=f"{filename}_PR_REVIEW.md",
            mime="text/markdown"
        )

    # ── TAB 3: CONVERSATIONAL CODE ASSISTANT (CHROMADB RAG) ──
    with tab_assistant:
        st.subheader("💬 Conversational Code Assistant")
        st.caption("Ask questions about flagged vulnerabilities, OWASP standards, and secure coding practices grounded in ChromaDB.")

        if "chat_history" not in st.session_state:
            st.session_state["chat_history"] = []

        # Display conversation history
        for msg in st.session_state["chat_history"]:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                if msg.get("citations"):
                    st.caption(f"📚 Citations: {', '.join([c.get('title', '') for c in msg.get('citations')])}")

        # Chat Input
        user_query = st.chat_input("Ask about vulnerabilities, e.g. 'How to fix SQL injection in Python?'")
        if user_query:
            st.session_state["chat_history"].append({"role": "user", "content": user_query})
            with st.chat_message("user"):
                st.markdown(user_query)

            with st.chat_message("assistant"):
                with st.spinner("Consulting ChromaDB knowledge base..."):
                    assistant = get_conversational_assistant()
                    reply = assistant.ask(
                        query=user_query,
                        # pyrefly: ignore[unexpected-keyword]
                        source_code=source_code,
                        # pyrefly: ignore[unexpected-keyword]
                        language=language.lower(),
                        # pyrefly: ignore[unexpected-keyword]
                        filename=filename,
                        # pyrefly: ignore[unexpected-keyword]
                        findings=findings
                    )

                    ans_text = reply.get("response", "I could not find a relevant guidance.")
                    citations = reply.get("citations", [])

                    st.markdown(ans_text)
                    if citations:
                        with st.expander(f"📚 Grounded OWASP Citations ({len(citations)})"):
                            for cit in citations:
                                st.write(f"**{cit.get('title')}** (Similarity: `{cit.get('score', cit.get('similarity_score', 0.9))}`)")
                                if cit.get("url"):
                                    st.markdown(f"[Documentation Link]({cit.get('url')})")

                    st.session_state["chat_history"].append({
                        "role": "assistant",
                        "content": ans_text,
                        "citations": citations
                    })
