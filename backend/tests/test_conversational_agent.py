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

