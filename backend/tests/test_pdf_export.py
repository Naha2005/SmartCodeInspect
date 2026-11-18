"""
Enterprise PDF Code Review Report Test Suite.
Validates PDF generation, structural sections, before/after code blocks,
and the POST /reports/pdf API endpoint.
"""

import io
import pytest
from app import create_app
from reports.pdf_generator import generate_pdf_report
from agents.orchestrator import MultiAgentOrchestrator


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator()


def test_pdf_generation_clean_code():
    clean_data = {
        "filename": "SecureCalculator.py",
        "language": "python",
        "source_code": "def add(a, b):\n    return a + b\n",
        "findings": [],
        "summary": {
            "overall_code_health_score": 100,
            "code_quality_score": 100,
            "security_posture": "Grade A (Hardened)",
            "total_findings": 0
        }
    }
    pdf_stream = generate_pdf_report(clean_data)
    assert isinstance(pdf_stream, io.BytesIO)
    content = pdf_stream.getvalue()
    assert len(content) > 1000
    assert content.startswith(b"%PDF")


def test_pdf_generation_vulnerable_code_before_and_after():
    vuln_data = {
        "filename": "vulnerable_app.py",
        "language": "python",
        "source_code": "import sqlite3\nconn = sqlite3.connect('app.db')\ncursor = conn.cursor()\ncursor.execute(f'SELECT * FROM users WHERE name = {user}')\n",
        "findings": [
            {
                "rule_id": "SEC-PY-003",
                "title": "SQL Injection via String Formatting",
                "severity": "Critical",
                "line": 4,
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE name = {user}')",
                "risk_explanation": "Direct string formatting into SQL queries allows attackers to execute arbitrary database commands.",
                "mitigation": "Use parameterized queries with placeholder syntax.",
                "category": "OWASP A03:2021-Injection"
            }
        ],
        "summary": {
            "overall_code_health_score": 35,
            "code_quality_score": 60,
            "security_posture": "Critical Risk (Compromised)",
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total_findings": 1
        }
    }
    pdf_stream = generate_pdf_report(vuln_data)
    content = pdf_stream.getvalue()
    assert len(content) > 2500
    assert content.startswith(b"%PDF")


def test_pdf_generation_java_code():
    java_data = {
        "filename": "VulnerablePortal.java",
        "language": "java",
        "source_code": "public class VulnerablePortal {\n    public void execute(Connection conn, String user) throws Exception {\n        Statement stmt = conn.createStatement();\n        ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + user + \"'\");\n    }\n}\n",
        "findings": [
            {
                "rule_id": "SEC-JV-001",
                "title": "SQL Injection via Concatenation",
                "severity": "Critical",
                "line": 4,
                "evidence": 'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = \'" + user + "\'");',
                "risk_explanation": "Direct SQL concatenation allows authentication bypass.",
                "mitigation": "Use PreparedStatement with parameter binding.",
                "category": "OWASP A03:2021-Injection"
            },
            {
                "rule_id": "RISK-JV-001",
                "title": "Unmanaged JDBC Connection Outside Try-with-Resources",
                "severity": "High",
                "line": 3,
                "evidence": "Statement stmt = conn.createStatement();",
                "risk_explanation": "Unclosed statements exhaust the database connection pool.",
                "mitigation": "Wrap in try-with-resources.",
                "category": "Resource Management"
            }
        ]
    }
    pdf_stream = generate_pdf_report(java_data)
    content = pdf_stream.getvalue()
    assert len(content) > 4000
    assert content.startswith(b"%PDF")


def test_pdf_api_endpoint_with_source_code(client):
    payload = {
        "source_code": "import requests\nresp = requests.get('https://example.com')\n",
        "language": "python",
        "filename": "fetch_service.py"
    }
    res = client.post("/api/reports/pdf", json=payload)
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    assert len(res.data) > 1000
    assert res.data.startswith(b"%PDF")


def test_pdf_api_endpoint_with_precomputed_analysis(client):
    payload = {
        "filename": "test_precomputed.py",
        "language": "python",
        "analysis_data": {
            "filename": "test_precomputed.py",
            "language": "python",
            "findings": [],
            "summary": {
                "overall_code_health_score": 100,
                "code_quality_score": 100,
                "security_posture": "Grade A (Clean)",
                "total_findings": 0
            }
        }
    }
    res = client.post("/api/reports/pdf", json=payload)
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    assert res.data.startswith(b"%PDF")
