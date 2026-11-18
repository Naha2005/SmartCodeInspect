import pytest
from agents.conversational_agent import ConversationalCodeAssistant, get_conversational_assistant


@pytest.fixture
def assistant():
    return ConversationalCodeAssistant()


def test_conversational_assistant_singleton():
    a1 = get_conversational_assistant()
    a2 = get_conversational_assistant()
    assert a1 is a2
    assert a1.name == "Conversational Code Assistant"


def test_ask_sql_injection_guidance(assistant):
    res = assistant.ask(
        query="How do I prevent SQL injection in my Python application?",
        context={"language": "python", "filename": "database.py"}
    )

    assert res["success"] is True
    assert "response" in res
    assert "SQL" in res["response"]
    assert "Parameterized" in res["response"] or "placeholder" in res["response"]
    assert len(res["citations"]) > 0


def test_ask_specific_rule_guidance(assistant):
    res = assistant.ask(
        query="Explain SEC-PY-001 and how to fix it",
        context={"language": "python"}
    )

    assert res["success"] is True
    assert "SEC-PY-001" in res["response"]
    assert "eval" in res["response"].lower()
    assert "ast.literal_eval" in res["response"]


def test_ask_with_active_findings(assistant):
    res = assistant.ask(
        query="Can you summarize the findings in this file?",
        context={
            "language": "python",
            "filename": "vuln.py",
            "findings": [
                {"rule_id": "SEC-PY-001", "title": "eval() usage", "severity": "Critical", "line": 4},
                {"rule_id": "SEC-PY-003", "title": "SQL Injection", "severity": "High", "line": 12}
            ]
        }
    )

    assert res["success"] is True
    assert "Critical" in res["response"] or "Flagged" in res["response"]


def test_ask_radar_chart_dimensions(assistant):
    res = assistant.ask(
        query="What are the six dimensions of the radar chart?",
        context={"language": "python"}
    )
    assert res["success"] is True
    assert "Six-Dimensional" in res["response"]
    assert "Security" in res["response"]
    assert "Complexity" in res["response"]
    assert "Maintainability" in res["response"]
    assert "Best Practices" in res["response"]
    assert "Input Validation" in res["response"]


def test_ask_scoring_formula_consistency(assistant):
    res = assistant.ask(
        query="Explain the severity scoring formula and deductions",
        context={"language": "python"}
    )
    assert res["success"] is True
    assert "Critical" in res["response"]
    assert "-35" in res["response"]
    assert "-20" in res["response"]
    assert "100" in res["response"]
    assert "0.70" in res["response"] or "70%" in res["response"] or "Security" in res["response"]


def test_ask_line_specific_fix(assistant):
    res = assistant.ask(
        query="How do I fix line 10?",
        context={
            "language": "python",
            "findings": [
                {
                    "rule_id": "SEC-PY-003",
                    "title": "SQL Injection",
                    "severity": "High",
                    "line": 10,
                    "evidence": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                    "mitigation": "Use parameterized queries."
                }
            ]
        }
    )
    assert res["success"] is True
    assert "Line 10" in res["response"]
    assert "SEC-PY-003" in res["response"]
    assert "parameterized" in res["response"].lower() or "placeholder" in res["response"].lower()


def test_ask_risky_call_timeout_rule(assistant):
    res = assistant.ask(
        query="Explain RISK-PY-001 and how to remediate missing timeout",
        context={"language": "python"}
    )
    assert res["success"] is True
    assert "RISK-PY-001" in res["response"]
    assert "timeout" in res["response"].lower()


def test_ask_fix_all_workflow(assistant):
    res = assistant.ask(
        query="How does the Fix All button work?",
        context={"language": "java"}
    )
    assert res["success"] is True
    assert "Fix All" in res["response"]
    assert "Syntax" in res["response"] or "syntax" in res["response"]
    assert "Radar" in res["response"] or "100" in res["response"]

