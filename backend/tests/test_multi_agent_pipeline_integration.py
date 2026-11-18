import pytest
from agents.orchestrator import MultiAgentOrchestrator
from app import create_app


@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator()


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


SAMPLE_CODE = """import os
import subprocess

API_KEY = "AKIA-SECRET-PRODUCTION-KEY-999"

def process_data(a, b, c, d, e, f):
    print("Processing started")
    try:
        val = eval(a)
        subprocess.Popen("cat " + str(b), shell=True)
    except Exception:
        pass
    return val
"""


def test_multi_agent_pipeline_complete_flow(orchestrator):
    result = orchestrator.run_parallel_analysis(SAMPLE_CODE, language="python", filename="data_processor.py")

    # 1. Base pipeline assertions
    assert "findings" in result
    assert "summary" in result
    assert "pr_summary" in result
    assert "orchestration" in result

    # 2. Four agents present in orchestration telemetry
    agents = result["orchestration"]["agents"]
    assert "code_analysis_agent" in agents
    assert "security_vulnerability_agent" in agents
    assert "remediation_agent" in agents
    assert "pr_summary_agent" in agents

    assert agents["remediation_agent"]["status"] == "completed"
    assert agents["pr_summary_agent"]["status"] == "completed"

    # 3. Findings enriched with remediation
    findings = result["findings"]
    assert len(findings) > 0
    for f in findings:
        assert "remediation" in f
        rem = f["remediation"]
        assert "recommendation" in rem
        assert "corrected_code" in rem
        assert "best_practices" in rem

    # 4. Summary metrics include overall_code_health_score
    summary = result["summary"]
    assert "overall_code_health_score" in summary
    assert 0 <= summary["overall_code_health_score"] <= 100
    assert "code_quality_score" in summary
    assert "security_posture" in summary

    # 5. PR Summary agent output structure
    pr = result["pr_summary"]
    assert pr["agent"] == "PR Summary Agent"
    assert pr["verdict"]["decision"] == "CHANGES_REQUESTED"  # Because eval + shell=True are critical
    assert len(pr["prioritized_fix_list"]["p0_blockers"]) >= 2
    assert "## 📋 Pull Request Code Review & Security Audit Summary" in pr["markdown"]


def test_chat_endpoint_api(client):
    res = client.post("/api/chat", json={
        "query": "What is SQL injection?",
        "context": {"language": "python"}
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "response" in data
    assert len(data["response"]) > 0


def test_remediate_endpoint_api(client):
    res = client.post("/api/remediate", json={
        "finding": {
            "rule_id": "SEC-PY-003",
            "title": "SQL Injection",
            "severity": "High",
            "line": 10
        },
        "language": "python"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "remediation" in data
    assert "parameterized" in data["remediation"]["recommendation"].lower() or "placeholder" in data["remediation"]["recommendation"].lower()


def test_pr_summary_endpoint_api(client):
    res = client.post("/api/pr-summary", json={
        "findings": [
            {"rule_id": "SEC-PY-001", "severity": "Critical", "title": "eval() usage", "line": 4}
        ],
        "summary": {
            "total_findings": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "code_quality_score": 80,
            "security_posture": "F"
        },
        "metadata": {"filename": "test.py", "language": "python"}
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "verdict" in data
    assert "markdown" in data

