import pytest
from agents.remediation_agent import RemediationAgent, REMEDIATION_CATALOG, get_remediation_agent


@pytest.fixture
def agent():
    return RemediationAgent()


def test_remediation_agent_singleton():
    a1 = get_remediation_agent()
    a2 = get_remediation_agent()
    assert a1 is a2
    assert a1.name == "Remediation Agent"


def test_python_sql_injection_remediation(agent):
    finding = {
        "rule_id": "SEC-PY-003",
        "title": "SQL Injection via String Formatting",
        "severity": "High",
        "line": 15,
        "evidence": "cursor.execute(f'SELECT * FROM users WHERE name = {user_name}')",
        "language": "python"
    }
    remediation = agent.generate_remediation(finding)

    assert remediation["rule_id"] == "SEC-PY-003"
    assert "parameterized" in remediation["recommendation"].lower() or "prepared" in remediation["recommendation"].lower()
    assert "cursor.execute" in remediation["corrected_code"]
    assert "?" in remediation["corrected_code"] or "%s" in remediation["corrected_code"]
    assert len(remediation["best_practices"]) >= 3
    assert len(remediation["references"]) > 0


def test_java_sql_injection_remediation(agent):
    finding = {
        "rule_id": "SEC-JV-001",
        "title": "SQL Injection Concatenation",
        "severity": "High",
        "line": 42,
        "evidence": "stmt.executeQuery(\"SELECT * FROM accounts WHERE id = \" + accountId)",
        "language": "java"
    }
    remediation = agent.generate_remediation(finding)

    assert remediation["rule_id"] == "SEC-JV-001"
    assert "PreparedStatement" in remediation["corrected_code"]
    assert "setString" in remediation["corrected_code"]
    assert len(remediation["best_practices"]) >= 3


def test_python_secrets_remediation(agent):
    finding = {
        "rule_id": "SEC-PY-004",
        "title": "Hardcoded Production Secret",
        "severity": "High",
        "line": 5,
        "evidence": "SECRET_KEY = 'AKIA-12345'",
        "language": "python"
    }
    remediation = agent.generate_remediation(finding)
    assert "os.environ" in remediation["corrected_code"] or "environ.get" in remediation["corrected_code"]
    assert "Secrets Management" in str(remediation["best_practices"])


def test_code_quality_remediation(agent):
    finding = {
        "rule_id": "SMELL-PY-002",
        "title": "Long Parameter List",
        "severity": "Medium",
        "line": 12,
        "evidence": "def create(a, b, c, d, e, f):",
        "language": "python"
    }
    remediation = agent.generate_remediation(finding)
    assert "dataclass" in remediation["corrected_code"] or "Parameter Object" in remediation["title"]
    assert len(remediation["best_practices"]) >= 2


def test_enrich_finding(agent):
    original = {
        "rule_id": "SEC-PY-001",
        "title": "eval() usage",
        "severity": "Critical",
        "line": 10,
        "evidence": "eval(raw)"
    }
    enriched = agent.enrich_finding(original)

    assert "remediation" in enriched
    assert enriched["remediation"]["rule_id"] == "SEC-PY-001"
    assert "ast.literal_eval" in enriched["remediation"]["corrected_code"]
    assert enriched["mitigation"] != ""


def test_fallback_remediation_for_unknown_rule(agent):
    unknown_finding = {
        "rule_id": "CUSTOM-999",
        "title": "Custom Violation",
        "severity": "Low",
        "category": "Maintainability",
        "line": 25,
        "evidence": "custom_call()",
        "language": "python"
    }
    remediation = agent.generate_remediation(unknown_finding)
    assert remediation["rule_id"] == "CUSTOM-999"
    assert "remediate" in remediation["title"].lower()
    assert len(remediation["best_practices"]) > 0

