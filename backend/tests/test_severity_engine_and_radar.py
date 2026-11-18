"""
Comprehensive Unit & Integration Test Suite for Centralized Severity Engine,
Risky-Call AST Analysis, Finding Deduplication, and 6-Dimensional Radar Scoring.
"""

import pytest
from utils.severity_engine import (
    SeverityEngine,
    get_severity_engine,
    sort_findings,
    get_severity_breakdown,
    calculate_health_score,
    calculate_security_score,
    calculate_quality_score,
    calculate_composite_score,
    get_score_explanation,
    calculate_six_dimensional_radar,
    deduplicate_findings,
    RADAR_DIMENSIONS,
)
from agents.code_analysis_agent import CodeAnalysisAgent
from agents.orchestrator import MultiAgentOrchestrator


@pytest.fixture
def engine():
    return get_severity_engine()


@pytest.fixture
def code_agent():
    return CodeAnalysisAgent()


@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator()


# =============================================================================
# 1. Centralized Severity Engine Tests
# =============================================================================

def test_severity_sorting(engine):
    findings = [
        {"rule_id": "LOW-1", "severity": "Low", "line": 10},
        {"rule_id": "CRIT-1", "severity": "Critical", "line": 5},
        {"rule_id": "MED-1", "severity": "Medium", "line": 20},
        {"rule_id": "HIGH-1", "severity": "High", "line": 2},
        {"rule_id": "INFO-1", "severity": "Informational", "line": 1},
    ]
    sorted_findings = engine.sort_findings(findings)
    severities = [f["severity"] for f in sorted_findings]
    assert severities == ["Critical", "High", "Medium", "Low", "Informational"]


def test_severity_breakdown(engine):
    findings = [
        {"severity": "Critical"},
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Info"},
    ]
    breakdown = engine.get_severity_breakdown(findings)
    assert breakdown["critical"] == 1
    assert breakdown["high"] == 2
    assert breakdown["medium"] == 1
    assert breakdown["low"] == 1
    assert breakdown["informational"] == 1
    assert breakdown["total"] == 6


def test_confidence_normalization(engine):
    assert engine.normalize_confidence("High") == 1.0
    assert engine.normalize_confidence("Medium") == 0.75
    assert engine.normalize_confidence("Low") == 0.5
    assert engine.normalize_confidence(0.9) == 0.9
    assert engine.normalize_confidence(None) == 1.0


def test_composite_score_capping(engine):
    # Perfect score with 0 critical/high
    assert engine.calculate_composite_score(100.0, 100, critical_count=0, high_count=0) == 100

    # With critical findings, score must not exceed 60
    capped_crit = engine.calculate_composite_score(90.0, 95, critical_count=1, high_count=0)
    assert capped_crit <= 60

    # With high findings (no critical), score must not exceed 75
    capped_high = engine.calculate_composite_score(90.0, 95, critical_count=0, high_count=1)
    assert capped_high <= 75


# =============================================================================
# 2. Six-Dimensional Radar Scoring Tests
# =============================================================================

def test_radar_exact_six_dimensions(engine):
    assert len(RADAR_DIMENSIONS) == 6
    expected_dims = {
        "Code Quality",
        "Security",
        "Complexity",
        "Maintainability",
        "Best Practices",
        "Input Validation",
    }
    assert set(RADAR_DIMENSIONS) == expected_dims


def test_radar_clean_baseline_scores(engine):
    radar = engine.calculate_six_dimensional_radar([])
    assert radar["scoring_status"] == "complete"
    assert len(radar["radar_scores"]) == 6
    for dim in RADAR_DIMENSIONS:
        assert radar["radar_scores"][dim] == 100
        assert radar["dimension_details"][dim]["findings_count"] == 0
        assert radar["dimension_details"][dim]["status"] == "Excellent"


def test_radar_finding_driven_deductions(engine):
    findings = [
        {"rule_id": "SEC-PY-001", "severity": "Critical", "message": "SQL Injection vulnerability in query", "confidence": "High", "line": 15},
        {"rule_id": "SMELL-PY-001", "severity": "Low", "message": "Long function smell", "confidence": "High", "line": 40},
        {"rule_id": "COMPLEX-PY-002", "severity": "Medium", "message": "Deep control flow nesting", "confidence": "High", "line": 50},
        {"rule_id": "PRACTICE-PY-002", "severity": "Medium", "message": "Resource leak unmanaged open", "confidence": "High", "line": 60},
    ]
    radar = engine.calculate_six_dimensional_radar(findings)
    scores = radar["radar_scores"]

    # Security & Input Validation must be penalized by the SQLi finding
    assert scores["Security"] < 100
    assert scores["Input Validation"] < 100
    # Complexity penalized by COMPLEX-PY-002
    assert scores["Complexity"] < 100
    # Best practices penalized by PRACTICE-PY-002
    assert scores["Best Practices"] < 100
    # Code Quality penalized by SMELL-PY-001
    assert scores["Code Quality"] < 100


# =============================================================================
# 3. Context-Aware Risky-Call AST Analysis Tests
# =============================================================================

def test_python_missing_timeout_detection(code_agent):
    code = """import requests

def fetch_data(url):
    response = requests.get(url)
    return response.text
"""
    findings = code_agent.analyze(code, "python")
    rule_ids = [f.rule_id for f in findings]
    assert "RISK-PY-001" in rule_ids, "Should detect missing timeout in requests.get()"
    assert "RISK-PY-002" in rule_ids, "Should detect unhandled network call exception"


def test_python_handled_risky_call_suppression(code_agent):
    code = """import requests

def safe_fetch(url):
    try:
        response = requests.get(url, timeout=5.0)
        return response.text
    except requests.RequestException:
        return None
"""
    findings = code_agent.analyze(code, "python")
    rule_ids = [f.rule_id for f in findings]
    # Handled within try/except with timeout -> RISK-PY-001 and RISK-PY-002 must NOT trigger
    assert "RISK-PY-001" not in rule_ids, "Timeout is configured, should not flag RISK-PY-001"
    assert "RISK-PY-002" not in rule_ids, "Call is wrapped in try/except, should not flag RISK-PY-002"


def test_java_unmanaged_db_resource_detection(code_agent):
    code = """import java.sql.*;

public class DbTest {
    public void queryUser() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:test.db");
        Statement stmt = conn.createStatement();
    }
}
"""
    findings = code_agent.analyze(code, "java")
    rule_ids = [f.rule_id for f in findings]
    assert "RISK-JV-001" in rule_ids, "Should flag unmanaged database resource outside try-with-resources"


# =============================================================================
# 4. Orchestration Integration & Deduplication Tests
# =============================================================================

def test_orchestration_returns_radar_and_breakdown(orchestrator):
    code = """import os
import sqlite3

def run_query(q):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
"""
    res = orchestrator.run_parallel_analysis(code, "python", filename="test_app.py")
    summary = res["summary"]

    assert "radar_scores" in summary, "Summary must include radar_scores"
    assert "dimension_details" in summary, "Summary must include dimension_details"
    assert "score_breakdown" in summary, "Summary must include score_breakdown"
    assert summary["scoring_status"] == "complete"

    radar = summary["radar_scores"]
    for dim in RADAR_DIMENSIONS:
        assert dim in radar
        assert 0 <= radar[dim] <= 100

    breakdown = summary["score_breakdown"]
    assert breakdown["starting_score"] == 100
    assert "narrative_explanation" in breakdown
    assert "itemized_deductions" in breakdown
