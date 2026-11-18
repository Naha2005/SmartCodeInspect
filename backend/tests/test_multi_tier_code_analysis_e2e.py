"""
Enterprise End-to-End Multi-Tier Code Analysis & Audit Test Suite:
1. Multi-Agent Detection Accuracy across 3 Complexity Tiers (Python & Java)
2. Remediation Quality & Actionability Verification
3. ChromaDB RAG Semantic Retrieval Relevance
4. Enterprise PDF Report Completeness & Binary Integrity
"""

import pytest
import io
from agents.orchestrator import MultiAgentOrchestrator
from reports.pdf_generator import generate_pdf_report
from knowledge_base.retriever import OWASPRetriever
from app import create_app

# ─────────────────────────────────────────────────────────────────────────────
# 3 DISTINCT COMPLEXITY CODE SAMPLES (PYTHON)
# ─────────────────────────────────────────────────────────────────────────────

PYTHON_LOW_COMPLEXITY_CLEAN = '''import math
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

PYTHON_MODERATE_COMPLEXITY_SMELLS = '''import json
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

PYTHON_HIGH_COMPLEXITY_VULNERABLE = '''import os
import subprocess
import pickle
import sqlite3

# Security: Hardcoded Credentials
API_SECRET_KEY = "AIzaSyD-untrusted-production-key-999"

def execute_untrusted(user_input: str):
    # Security: Code Execution
    eval(user_input)
    
    # Security: Command Injection
    subprocess.Popen("cat " + user_input, shell=True)
    
    # Security: SQL Injection
    conn = sqlite3.connect("app.db")
    conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

def restore_cache(payload_bytes: bytes):
    # Security: Insecure Deserialization
    return pickle.loads(payload_bytes)
'''

# ─────────────────────────────────────────────────────────────────────────────
# 3 DISTINCT COMPLEXITY CODE SAMPLES (JAVA)
# ─────────────────────────────────────────────────────────────────────────────

JAVA_LOW_COMPLEXITY_CLEAN = '''import java.math.BigDecimal;
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

JAVA_MODERATE_COMPLEXITY_SMELLS = '''import java.util.*;

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

JAVA_HIGH_COMPLEXITY_VULNERABLE = '''import java.io.*;
import java.sql.*;

public class LegacyPortalService {
    // Security: Hardcoded Credentials
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    public void authenticateUser(Connection conn, String user, String pass) throws Exception {
        Statement stmt = conn.createStatement();
        // Security: SQL Injection
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "' AND pass = '" + pass + "'");
    }

    public void executeAdminScript(String scriptName) throws Exception {
        // Security: OS Command Injection
        Runtime.getRuntime().exec("sh /opt/scripts/" + scriptName);
    }

    public Object deserializeSession(InputStream stream) throws Exception {
        // Security: Insecure Deserialization
        ObjectInputStream ois = new ObjectInputStream(stream);
        return ois.readObject();
    }
}
'''


@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator()


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


# ─────────────────────────────────────────────────────────────────────────────
# 1. TEST 3 DISTINCT TIERS FOR PYTHON
# ─────────────────────────────────────────────────────────────────────────────

def test_python_tier1_low_complexity_clean(orchestrator):
    result = orchestrator.run_parallel_analysis(
        PYTHON_LOW_COMPLEXITY_CLEAN, language="python", filename="secure_calculator.py"
    )
    summary = result["summary"]
    pr_review = result["pr_summary"]

    assert summary["critical"] == 0
    assert summary["high"] == 0
    assert summary["security_findings_count"] == 0
    assert "A" in summary["security_posture"]
    assert summary["overall_code_health_score"] >= 95
    assert pr_review["verdict"]["decision"] == "APPROVED"


def test_python_tier2_moderate_complexity_smells(orchestrator):
    result = orchestrator.run_parallel_analysis(
        PYTHON_MODERATE_COMPLEXITY_SMELLS, language="python", filename="data_pipeline_service.py"
    )
    summary = result["summary"]
    pr_review = result["pr_summary"]
    findings = result["findings"]

    # Zero critical security exploits
    assert summary["critical"] == 0
    assert summary["security_findings_count"] == 0
    # Accurately flags code smells
    assert summary["code_quality_findings_count"] >= 3
    rule_ids = [f["rule_id"] for f in findings]
    assert any("SMELL" in r or "PRACTICE" in r or "DESIGN" in r for r in rule_ids)
    # Quality score reflects detected smells
    assert summary["code_quality_score"] < 100
    assert "A" in summary["security_posture"]


def test_python_tier3_high_complexity_vulnerable(orchestrator):
    result = orchestrator.run_parallel_analysis(
        PYTHON_HIGH_COMPLEXITY_VULNERABLE, language="python", filename="vulnerable_service.py"
    )
    summary = result["summary"]
    pr_review = result["pr_summary"]
    findings = result["findings"]

    # Must flag critical security flaws
    assert summary["critical"] >= 2
    assert summary["security_findings_count"] >= 3
    assert "F" in summary["security_posture"]
    assert pr_review["verdict"]["decision"] == "CHANGES_REQUESTED"
    assert len(pr_review["prioritized_fix_list"]["p0_blockers"]) >= 2

    # Verify rule IDs detected
    sec_rules = [f["rule_id"] for f in findings]
    assert "SEC-PY-001" in sec_rules  # eval
    assert "SEC-PY-002" in sec_rules  # command injection
    assert "SEC-PY-003" in sec_rules  # SQL injection
    assert "SEC-PY-005" in sec_rules  # pickle deserialization


# ─────────────────────────────────────────────────────────────────────────────
# 2. TEST 3 DISTINCT TIERS FOR JAVA
# ─────────────────────────────────────────────────────────────────────────────

def test_java_tier1_low_complexity_clean(orchestrator):
    result = orchestrator.run_parallel_analysis(
        JAVA_LOW_COMPLEXITY_CLEAN, language="java", filename="SecureBankTransfer.java"
    )
    summary = result["summary"]
    pr_review = result["pr_summary"]

    assert summary["critical"] == 0
    assert summary["high"] == 0
    assert summary["security_findings_count"] == 0
    assert "A" in summary["security_posture"]
    assert summary["overall_code_health_score"] >= 95
    assert pr_review["verdict"]["decision"] == "APPROVED"


def test_java_tier2_moderate_complexity_smells(orchestrator):
    result = orchestrator.run_parallel_analysis(
        JAVA_MODERATE_COMPLEXITY_SMELLS, language="java", filename="OrderNotificationManager.java"
    )
    summary = result["summary"]
    findings = result["findings"]

    assert summary["critical"] == 0
    assert summary["security_findings_count"] == 0
    assert summary["code_quality_findings_count"] >= 2
    rule_ids = [f["rule_id"] for f in findings]
    # Flags long parameter list, empty catch, or system.out
    assert any("SMELL" in r or "PRACTICE" in r or "COMPLEX" in r for r in rule_ids)
    assert summary["code_quality_score"] < 100


def test_java_tier3_high_complexity_vulnerable(orchestrator):
    result = orchestrator.run_parallel_analysis(
        JAVA_HIGH_COMPLEXITY_VULNERABLE, language="java", filename="LegacyPortalService.java"
    )
    summary = result["summary"]
    pr_review = result["pr_summary"]
    findings = result["findings"]

    assert summary["critical"] >= 2
    assert summary["security_findings_count"] >= 3
    assert "F" in summary["security_posture"]
    assert pr_review["verdict"]["decision"] == "CHANGES_REQUESTED"

    sec_rules = [f["rule_id"] for f in findings]
    assert "SEC-JV-001" in sec_rules  # SQL injection
    assert "SEC-JV-002" in sec_rules  # Command injection
    assert "SEC-JV-004" in sec_rules  # Deserialization


# ─────────────────────────────────────────────────────────────────────────────
# 3. TEST REMEDIATION QUALITY & ACTIONABILITY
# ─────────────────────────────────────────────────────────────────────────────

def test_remediation_quality_and_actionability(orchestrator):
    result = orchestrator.run_parallel_analysis(
        PYTHON_HIGH_COMPLEXITY_VULNERABLE, language="python", filename="vulnerable_service.py"
    )
    findings = result["findings"]
    assert len(findings) > 0

    for f in findings:
        assert "remediation" in f
        rem = f["remediation"]
        assert isinstance(rem, dict)
        assert len(rem.get("recommendation", "")) > 10
        assert len(rem.get("corrected_code", "")) > 5
        assert isinstance(rem.get("best_practices", []), list)
        assert len(rem.get("best_practices", [])) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 4. TEST CHROMADB RAG RETRIEVAL RELEVANCE
# ─────────────────────────────────────────────────────────────────────────────

def test_chromadb_rag_retrieval_relevance():
    retriever = OWASPRetriever()
    status = retriever.get_status()
    assert status.get("status") == "ready"
    assert status.get("chunks_count", 0) > 0

    # 1. SQL Injection query
    sqli_results = retriever.search("prevent SQL injection parameterized query", top_k=3)
    assert len(sqli_results) > 0
    top_sqli = " ".join([r.get("content", "").lower() + " " + r.get("title", "").lower() for r in sqli_results])
    assert "sql" in top_sqli or "injection" in top_sqli or "parameter" in top_sqli

    # 2. Command Injection query
    cmd_results = retriever.search("command injection subprocess runtime exec", top_k=3)
    assert len(cmd_results) > 0
    top_cmd = " ".join([r.get("content", "").lower() + " " + r.get("title", "").lower() for r in cmd_results])
    assert "command" in top_cmd or "injection" in top_cmd or "cwe-78" in top_cmd or "execution" in top_cmd

    # 3. Deserialization query
    deser_results = retriever.search("insecure deserialization pickle objectinputstream", top_k=3)
    assert len(deser_results) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. TEST PDF REPORT COMPLETENESS & BINARY INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────

def test_pdf_report_completeness_and_binary_integrity(orchestrator):
    # Test generation for both clean, moderate, and vulnerable analysis outputs
    for sample, lang, name in [
        (PYTHON_LOW_COMPLEXITY_CLEAN, "python", "clean.py"),
        (PYTHON_MODERATE_COMPLEXITY_SMELLS, "python", "pipeline.py"),
        (JAVA_HIGH_COMPLEXITY_VULNERABLE, "java", "LegacyPortal.java"),
    ]:
        analysis_data = orchestrator.run_parallel_analysis(sample, language=lang, filename=name)
        pdf_stream = generate_pdf_report(analysis_data)

        assert isinstance(pdf_stream, io.BytesIO)
        pdf_bytes = pdf_stream.getvalue()
        assert len(pdf_bytes) > 2500  # Even clean reports with assessment header > 2.5KB
        assert pdf_bytes.startswith(b"%PDF-")  # Authentic PDF header


# ─────────────────────────────────────────────────────────────────────────────
# 6. TEST API PDF ENDPOINT INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def test_api_pdf_report_endpoint(client, orchestrator):
    # Pass complete multi-agent analysis_data payload to ensure full 4-pillar generation
    analysis = orchestrator.run_parallel_analysis(
        PYTHON_HIGH_COMPLEXITY_VULNERABLE, language="python", filename="vulnerable.py"
    )
    payload = {
        "analysis_data": analysis,
        "filename": "vulnerable.py"
    }
    res = client.post("/api/reports/pdf", json=payload)
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    assert res.data.startswith(b"%PDF-")
    assert len(res.data) > 10000  # Rich 4-pillar report with tables and roadmap > 10KB
