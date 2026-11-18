"""
Automated Validation Suite for the 6 Project Evaluation Criteria:
1. Accuracy and coverage of Code Analysis Agent in detecting code smells, design issues, and poor practices.
2. Effectiveness of Security Vulnerability Agent in identifying OWASP-standard vulnerabilities with correct severity classification.
3. Quality and specificity of Remediation Agent fix recommendations and corrected code examples.
4. Relevance and groundedness of Conversational Code Assistant responses against secure coding knowledge base.
5. Clarity and completeness of PR summary and exported code review report.
6. Completeness of implementation, testing, documentation, and final demonstration.
"""

import io
import pytest
from agents.code_analysis_agent import CodeAnalysisAgent
from agents.security_agent import SecurityVulnerabilityAgent, CWE_MAPPING, OWASP_CATEGORY_MAPPING
from agents.remediation_agent import RemediationAgent, REMEDIATION_CATALOG
from agents.conversational_agent import ConversationalCodeAssistant
from agents.pr_summary_agent import PRSummaryAgent
from agents.orchestrator import MultiAgentOrchestrator
from reports.pdf_generator import generate_pdf_report
from knowledge_base.retriever import OWASPRetriever


# ─────────────────────────────────────────────────────────────────────────────
# CRITERION 1: CODE ANALYSIS AGENT ACCURACY & COVERAGE
# ─────────────────────────────────────────────────────────────────────────────

def test_criterion_1_code_analysis_agent_python():
    agent = CodeAnalysisAgent()
    sample_code = """import os
from math import *

def complex_pipeline(a, b, c, d, e, f, cache=[]):
    print("Executing pipeline batch:", a)
    log_file = open("pipeline.log", "a")
    log_file.write(str(a))
    
    val = 0
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    val = 1
    try:
        val += 1
    except Exception:
        pass
        
    return val
"""
    findings = agent.analyze(sample_code, language="python", filename="pipeline.py")
    rule_ids = {f.rule_id for f in findings}

    # 1. Wildcard import smell
    assert "SMELL-PY-005" in rule_ids
    # 2. Long parameter list smell
    assert "SMELL-PY-002" in rule_ids
    # 3. Mutable default argument design issue
    assert "DESIGN-PY-001" in rule_ids
    # 4. Print statement left in production code
    assert "PRACTICE-PY-001" in rule_ids
    # 5. Potential resource leak (open without with)
    assert "PRACTICE-PY-002" in rule_ids
    # 6. Deep nesting / cyclomatic complexity
    assert any("COMPLEX" in r for r in rule_ids)
    # 7. Empty exception handler / silenced error
    assert "SMELL-PY-004" in rule_ids or "PRACTICE-PY-006" in rule_ids

    # All findings have valid line numbers and severity scores
    for f in findings:
        assert f.line > 0
        assert 0.0 <= f.severity_score <= 10.0
        assert f.agent == "Code Analysis Agent"


def test_criterion_1_code_analysis_agent_java():
    agent = CodeAnalysisAgent()
    sample_code = """import java.util.*;

public class OrderManager {
    public void processOrder(long orderId, String customer, String email, double total, int tier, boolean express) {
        System.out.println("Processing order: " + orderId);
        try {
            if (total > 100) {
                // routing
            }
        } catch (Exception e) {
        }
    }
}
"""
    findings = agent.analyze(sample_code, language="java", filename="OrderManager.java")
    rule_ids = {f.rule_id for f in findings}

    # 1. Console output in production code
    assert "SMELL-JV-002" in rule_ids
    # 2. Wildcard package import
    assert "SMELL-JV-005" in rule_ids
    # 3. Generic Exception catch
    assert "PRACTICE-JV-001" in rule_ids


# ─────────────────────────────────────────────────────────────────────────────
# CRITERION 2: SECURITY VULNERABILITY AGENT EFFECTIVENESS & CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def test_criterion_2_security_vulnerability_agent_python():
    sec_agent = SecurityVulnerabilityAgent()
    vulnerable_py = """import os
import subprocess
import sqlite3
import pickle
import hashlib

API_SECRET = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY"

def handle_request(payload, filename):
    eval(payload)
    subprocess.Popen("rm -rf " + payload, shell=True)
    conn = sqlite3.connect("test.db")
    conn.execute(f"SELECT * FROM users WHERE name = '{payload}'")
    pickle.loads(payload.encode())
    hashlib.md5(payload.encode()).hexdigest()
    f = open("/tmp/" + filename)
"""
    findings = sec_agent.analyze(vulnerable_py, language="python", filename="vuln.py")
    rule_map = {f.rule_id: f for f in findings}

    # Check detection and exact severity classification
    assert "SEC-PY-001" in rule_map  # eval RCE
    assert rule_map["SEC-PY-001"].severity == "Critical"
    assert CWE_MAPPING["SEC-PY-001"] == "CWE-95"

    assert "SEC-PY-002" in rule_map  # Command Injection
    assert rule_map["SEC-PY-002"].severity == "Critical"
    assert CWE_MAPPING["SEC-PY-002"] == "CWE-78"

    assert "SEC-PY-003" in rule_map  # SQL Injection
    assert rule_map["SEC-PY-003"].severity in ("Critical", "High")
    assert CWE_MAPPING["SEC-PY-003"] == "CWE-89"

    assert "SEC-PY-004" in rule_map  # Hardcoded credentials
    assert rule_map["SEC-PY-004"].severity == "High"
    assert CWE_MAPPING["SEC-PY-004"] == "CWE-798"

    assert "SEC-PY-005" in rule_map  # Insecure Deserialization
    assert rule_map["SEC-PY-005"].severity == "Critical"
    assert CWE_MAPPING["SEC-PY-005"] == "CWE-502"

    assert "SEC-PY-006" in rule_map  # Weak Hash (MD5)
    assert rule_map["SEC-PY-006"].severity in ("Medium", "High")
    assert CWE_MAPPING["SEC-PY-006"] == "CWE-327"


def test_criterion_2_security_vulnerability_agent_java():
    sec_agent = SecurityVulnerabilityAgent()
    vulnerable_java = """import java.sql.*;
import java.io.*;

public class VulnPortal {
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    public void run(Connection conn, String input, InputStream stream) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + input + "'");
        Runtime.getRuntime().exec("sh " + input);
        ObjectInputStream ois = new ObjectInputStream(stream);
        ois.readObject();
    }
}
"""
    findings = sec_agent.analyze(vulnerable_java, language="java", filename="VulnPortal.java")
    rule_map = {f.rule_id: f for f in findings}

    assert "SEC-JV-001" in rule_map  # SQLi
    assert rule_map["SEC-JV-001"].severity in ("Critical", "High")
    assert "SEC-JV-002" in rule_map  # Command Injection
    assert rule_map["SEC-JV-002"].severity in ("Critical", "High")
    assert "SEC-JV-003" in rule_map  # Hardcoded credentials
    assert rule_map["SEC-JV-003"].severity == "High"
    assert "SEC-JV-004" in rule_map  # Deserialization
    assert rule_map["SEC-JV-004"].severity == "Critical"


# ─────────────────────────────────────────────────────────────────────────────
# CRITERION 3: REMEDIATION AGENT FIX QUALITY & SPECIFICITY
# ─────────────────────────────────────────────────────────────────────────────

def test_criterion_3_remediation_agent_quality():
    rem_agent = RemediationAgent()
    
    # Test catalog completeness
    key_rules = ["SEC-PY-001", "SEC-PY-002", "SEC-PY-003", "SEC-JV-001", "SEC-JV-002", "SMELL-PY-001", "DESIGN-PY-001"]
    for r in key_rules:
        assert r in REMEDIATION_CATALOG
        entry = REMEDIATION_CATALOG[r]
        assert "title" in entry
        assert "recommendation" in entry
        assert "corrected_code" in entry
        assert "explanation" in entry
        assert "best_practices" in entry
        assert "diff_example" in entry
        assert len(entry["best_practices"]) >= 2

    # Test generating remediation for a finding
    mock_finding = {
        "rule_id": "SEC-PY-003",
        "title": "SQL Injection",
        "severity": "Critical",
        "line": 15,
        "evidence": 'cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")',
        "language": "python"
    }
    rem = rem_agent.generate_remediation(mock_finding, "cursor.execute(f'SELECT * ...')", language="python")
    assert rem is not None
    assert "recommendation" in rem
    assert "parameterized" in rem["recommendation"].lower() or "placeholder" in rem["recommendation"].lower()
    assert "corrected_code" in rem
    assert "execute" in rem["corrected_code"]
    # The corrected code must NOT contain dangerous f-string formatting
    assert "f\"SELECT" not in rem["corrected_code"]


# ─────────────────────────────────────────────────────────────────────────────
# CRITERION 4: CONVERSATIONAL CODE ASSISTANT RELEVANCE & GROUNDEDNESS
# ─────────────────────────────────────────────────────────────────────────────

def test_criterion_4_conversational_code_assistant_groundedness():
    assistant = ConversationalCodeAssistant()
    
    # Query regarding SQL injection prevention
    context = {
        "language": "python",
        "filename": "query_handler.py",
        "selected_finding": {
            "rule_id": "SEC-PY-003",
            "title": "SQL Injection via Unsanitized Formatting",
            "severity": "Critical",
            "line": 22,
            "evidence": "cursor.execute(f'SELECT * FROM accounts WHERE user = {uid}')"
        }
    }
    ans = assistant.ask("How should I refactor this SQL query safely?", context=context)
    assert ans["success"] is True
    assert "response" in ans
    response_text = ans["response"].lower()
    
    # Assert grounded in OWASP knowledge base
    assert "sql" in response_text
    assert "parameter" in response_text or "prepared" in response_text or "placeholder" in response_text
    assert "citations" in ans
    assert len(ans["citations"]) > 0


# ─────────────────────────────────────────────────────────────────────────────
# CRITERION 5: PR SUMMARY & EXPORTED REPORT CLARITY & COMPLETENESS
# ─────────────────────────────────────────────────────────────────────────────

def test_criterion_5_pr_summary_and_exported_report():
    pr_agent = PRSummaryAgent()
    orchestrator = MultiAgentOrchestrator()
    
    sample_code = """import os
import subprocess

def run_task(cmd):
    eval(cmd)
    subprocess.Popen(cmd, shell=True)
"""
    result = orchestrator.run_parallel_analysis(sample_code, language="python", filename="task_runner.py")
    
    # 1. PR Summary Agent verification
    pr_summary = result["pr_summary"]
    assert pr_summary["verdict"]["decision"] == "CHANGES_REQUESTED"
    assert pr_summary["overall_health_score"] < 50
    assert len(pr_summary["prioritized_fix_list"]["p0_blockers"]) >= 2
    assert "markdown" in pr_summary
    assert "Pull Request Code Review" in pr_summary["markdown"]
    assert "Code Health & Security Posture" in pr_summary["markdown"]
    assert "Severity Breakdown" in pr_summary["markdown"]
    assert "Prioritized Action Items" in pr_summary["markdown"]
    
    # 2. PDF Report completeness
    pdf_stream = generate_pdf_report(result)
    assert isinstance(pdf_stream, io.BytesIO)
    pdf_bytes = pdf_stream.getvalue()
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 8000  # Detailed 4-pillar report


# ─────────────────────────────────────────────────────────────────────────────
# CRITERION 6: COMPLETENESS ACROSS 3 COMPLEXITY TIERS
# ─────────────────────────────────────────────────────────────────────────────

def test_criterion_6_multi_tier_orchestration_accuracy():
    orchestrator = MultiAgentOrchestrator()
    
    # Clean tier (Low complexity)
    clean_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    res_clean = orchestrator.run_parallel_analysis(clean_code, language="python", filename="add.py")
    assert res_clean["summary"]["total_findings"] == 0
    assert res_clean["summary"]["overall_code_health_score"] == 100
    assert res_clean["pr_summary"]["verdict"]["decision"] == "APPROVED"
    
    # Moderate tier (Code smells)
    moderate_code = "def do_work(a, b, c, d, e, f, cache=[]):\n    print('test')\n    return a\n"
    res_mod = orchestrator.run_parallel_analysis(moderate_code, language="python", filename="mod.py")
    assert res_mod["summary"]["security_findings_count"] == 0
    assert res_mod["summary"]["code_quality_findings_count"] >= 2
    assert "A" in res_mod["summary"]["security_posture"]
    
    # High tier (Critical vulnerabilities)
    vuln_code = "import os\ndef pwn(x):\n    eval(x)\n"
    res_vuln = orchestrator.run_parallel_analysis(vuln_code, language="python", filename="vuln.py")
    assert res_vuln["summary"]["critical"] >= 1
    assert "F" in res_vuln["summary"]["security_posture"]
    assert res_vuln["pr_summary"]["verdict"]["decision"] == "CHANGES_REQUESTED"
