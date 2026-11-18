"""
Test Suite for OASIS SARIF v2.1.0 Export Generator.
"""

import pytest
from agents.orchestrator import MultiAgentOrchestrator
from reports.sarif_generator import generate_sarif_report
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


def test_sarif_generation_schema_compliance(orchestrator):
    code = "import os\ndef run(x):\n    eval(x)\n"
    analysis = orchestrator.run_parallel_analysis(code, language="python", filename="eval_test.py")
    
    sarif = generate_sarif_report(analysis, filename="eval_test.py")
    
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "sarif-schema-2.1.0" in sarif["$schema"]
    assert len(sarif["runs"]) == 1
    
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SmartCodeInspect"
    assert len(driver["rules"]) >= 1
    
    results = sarif["runs"][0]["results"]
    assert len(results) >= 1
    
    # Check first result structure
    res0 = results[0]
    assert "ruleId" in res0
    assert "message" in res0
    assert "level" in res0
    assert res0["level"] in ("error", "warning", "note")
    assert "locations" in res0
    assert res0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "eval_test.py"


def test_sarif_api_endpoint(client, orchestrator):
    code = "eval('1+1')\n"
    analysis = orchestrator.run_parallel_analysis(code, language="python", filename="test.py")
    
    payload = {
        "analysis_data": analysis,
        "filename": "test.py"
    }
    res = client.post("/api/reports/sarif", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) >= 1
