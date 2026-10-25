import pytest
import io
from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "java_compiler" in data
    assert "knowledge_base" in data
    assert "ai_integration" in data


def test_validate_endpoint_valid_python(client):
    payload = {
        "language": "python",
        "source_code": "def hello():\n    return 'world'\n",
        "filename": "hello.py"
    }
    res = client.post("/api/validate", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["valid_syntax"] is True
    assert data["language"] == "python"


def test_validate_endpoint_invalid_python(client):
    payload = {
        "language": "python",
        "source_code": "def broken(\n",
        "filename": "broken.py"
    }
    res = client.post("/api/validate", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["valid_syntax"] is False
    assert len(data["diagnostics"]) > 0


def test_validate_endpoint_invalid_language(client):
    payload = {
        "language": "ruby",
        "source_code": "puts 'hello'"
    }
    res = client.post("/api/validate", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_analyze_endpoint_python_vulnerabilities(client):
    payload = {
        "language": "python",
        "source_code": "user_input = 'evil'\neval(user_input)\n",
        "filename": "eval_test.py"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["valid_syntax"] is True
    assert data["summary"]["total_findings"] >= 1
    assert any(f["rule_id"] == "SEC-PY-001" for f in data["findings"])


def test_knowledge_search_endpoint(client):
    payload = {
        "query": "SQL injection prepared statements",
        "top_k": 2
    }
    res = client.post("/api/knowledge/search", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "results" in data
    assert len(data["results"]) > 0


def test_ai_explain_endpoint_offline_mode(client):
    finding = {
        "rule_id": "SEC-PY-001",
        "title": "Unsafe Dynamic Code Execution via eval()",
        "severity": "Critical",
        "language": "python",
        "line": 2,
        "evidence": "eval(user_input)",
        "risk_explanation": "Arbitrary code execution risk.",
        "mitigation": "Avoid eval() and use ast.literal_eval()."
    }
    res = client.post("/api/ai/explain", json={"finding": finding})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "explanation" in data


def test_reports_pdf_endpoint(client):
    payload = {
        "language": "python",
        "filename": "report_test.py",
        "source_code": "eval('2 + 2')\n"
    }
    res = client.post("/api/reports/pdf", json=payload)
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    # PDF magic header is %PDF-
    assert res.data.startswith(b"%PDF-")


def test_orchestrate_endpoint(client):
    payload = {
        "language": "python",
        "source_code": "eval('secret')\nAPI_KEY = 'AKIA1234567890123456'\n"
    }
    res = client.post("/api/orchestrate", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "findings" in data
    assert "summary" in data
    assert "orchestration" in data
    assert data["orchestration"]["parallel_execution"] is True
    assert len(data["findings"]) > 0

