import io
import json
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

# Sample Code Library
SAMPLE_PYTHON = '''import os
import subprocess
import sqlite3

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

SAMPLE_JAVA = '''import java.sql.*;
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
        "Load Sample Template",
        options=["None", "Vulnerable Sample"]
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
if sample_choice == "Vulnerable Sample":
    default_code = SAMPLE_PYTHON if language == "Python" else SAMPLE_JAVA

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
    with st.spinner("Running deterministic security inspection & ChromaDB lookups..."):
        lang_key = language.lower()
        if lang_key == "python":
            analysis = analyze_python_source(source_code, filename=filename)
        else:
            analysis = analyze_java_source(source_code, filename=filename)

        st.session_state["latest_analysis"] = analysis

if "latest_analysis" in st.session_state:
    analysis = st.session_state["latest_analysis"]
    summary = analysis.get("summary", {})

    st.divider()
    st.subheader("📊 Inspection Report")

    # Metrics Summary
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Findings", summary.get("total_findings", 0))
    m2.metric("Critical", summary.get("critical", 0))
    m3.metric("High", summary.get("high", 0))
    m4.metric("Medium", summary.get("medium", 0))
    m5.metric("Low", summary.get("low", 0))

    # Findings Breakdown
    findings = analysis.get("findings", [])
    if findings:
        st.subheader("🚨 Detected Vulnerabilities")
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            css_class = "finding-critical" if sev == "CRITICAL" else ("finding-high" if sev == "HIGH" else "finding-medium")

            with st.container():
                st.markdown(f"""
                <div class="{css_class}">
                    <strong>[{f.get('rule_id')}] {f.get('title')}</strong> &bull; 
                    <span>Line {f.get('line_number', 'N/A')}</span> &bull; 
                    <span style="font-weight:bold;">{sev}</span>
                    <p style="margin-top: 4px; margin-bottom: 2px;">{f.get('description')}</p>
                </div>
                """, unsafe_allow_html=True)

                if f.get("evidence"):
                    st.code(f.get("evidence"), language=language.lower())

                col_mit, col_ai = st.columns([7, 3])
                with col_mit:
                    st.info(f"**Remediation:** {f.get('mitigation')}")
                    if f.get("owasp_citations"):
                        st.caption(f"OWASP Standards: {', '.join(f.get('owasp_citations'))}")

                with col_ai:
                    if st.button("🤖 AI Explain", key=f"ai_{f.get('rule_id')}_{f.get('line_number')}"):
                        with st.spinner("Fetching AI advisory..."):
                            # Retrieve ChromaDB context
                            chroma_hits = retriever.search(f.get("title") + " " + f.get("description"), top_k=2)
                            ai_res = get_ai_explanation(finding=f, owasp_passages=chroma_hits)
                            st.session_state[f"ai_exp_{f.get('rule_id')}"] = ai_res.get("explanation")

                if f"ai_exp_{f.get('rule_id')}" in st.session_state:
                    st.markdown("##### 💡 AI Advisory Recommendation")
                    st.write(st.session_state[f"ai_exp_{f.get('rule_id')}"])
    else:
        st.success("🎉 No security vulnerabilities detected in the submitted source code!")

    # PDF Download
    st.divider()
    pdf_buf = generate_pdf_report(analysis)
    st.download_button(
        label="📥 Download Cryptographic PDF Audit Report",
        data=pdf_buf.getvalue(),
        file_name=f"{filename}_security_report.pdf",
        mime="application/pdf"
    )
