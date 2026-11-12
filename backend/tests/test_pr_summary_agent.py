import pytest
from agents.pr_summary_agent import PRSummaryAgent, get_pr_summary_agent


@pytest.fixture
def agent():
    return PRSummaryAgent()


def test_pr_summary_agent_singleton():
    a1 = get_pr_summary_agent()
    a2 = get_pr_summary_agent()
    assert a1 is a2
    assert a1.name == "PR Summary Agent"


def test_verdict_blocked_on_critical(agent):
    findings = [
        {
            "rule_id": "SEC-PY-001",
            "title": "eval() execution",
            "severity": "Critical",
            "severity_score": 9.5,
            "line": 10,
            "remediation": {"recommendation": "Use ast.literal_eval()"}
        }
    ]
    summary = {
        "total_findings": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "code_quality_score": 85,
        "security_posture": "F (Critical Security Findings Detected)"
    }
    result = agent.generate_pr_summary(findings, summary, {"filename": "app.py", "language": "python"})

    assert result["verdict"]["decision"] == "CHANGES_REQUESTED"
    assert "🔴 Changes Requested" in result["verdict"]["label"]
    assert result["overall_health_score"] < 70
    assert len(result["prioritized_fix_list"]["p0_blockers"]) == 1
    assert "eval()" in result["markdown"]


def test_verdict_approved_on_clean_code(agent):
    findings = []
    summary = {
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "code_quality_score": 100,
        "security_posture": "A (No Configured Security Findings Detected)"
    }
    result = agent.generate_pr_summary(findings, summary, {"filename": "Clean.java", "language": "java"})

    assert result["verdict"]["decision"] == "APPROVED"
    assert "🟢 Approved" in result["verdict"]["label"]
    assert result["overall_health_score"] >= 95
    assert len(result["prioritized_fix_list"]["p0_blockers"]) == 0
    assert "No P0 Blockers" in result["markdown"]


def test_prioritized_fix_list_partitioning(agent):
    findings = [
        {"rule_id": "SEC-PY-001", "severity": "Critical", "line": 5},
        {"rule_id": "SEC-PY-004", "severity": "High", "line": 8},
        {"rule_id": "COMPLEX-PY-001", "severity": "Medium", "line": 20},
        {"rule_id": "PRACTICE-PY-001", "severity": "Low", "line": 35}
    ]
    summary = {"critical": 1, "high": 1, "medium": 1, "low": 1, "code_quality_score": 75}
    result = agent.generate_pr_summary(findings, summary)

    prioritized = result["prioritized_fix_list"]
    assert prioritized["total_p0"] == 2
    assert prioritized["total_p1"] == 1
    assert prioritized["total_p2"] == 1
    assert len(result["merge_checklist"]) >= 2
    assert "# 📋 Pull Request Code Review & Security Audit Summary" in result["markdown"]

