import pytest
from agents.orchestrator import MultiAgentOrchestrator


@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator()


SAMPLE_PYTHON_DUAL_FLAWS = """import os
import subprocess
import pickle

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

SAMPLE_JAVA_DUAL_FLAWS = """import java.util.*;
import java.io.*;

public class PortalManager {
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    public void executeAdmin(String input, int p1, int p2, int p3, int p4, int p5) throws Exception {
        System.out.println("Executing admin task: " + input);
        Runtime.getRuntime().exec("sh " + input);
    }
}
"""


def test_parallel_execution_orchestration(orchestrator):
    result = orchestrator.run_parallel_analysis(SAMPLE_PYTHON_DUAL_FLAWS, language="python")

    assert "findings" in result
    assert "summary" in result
    assert "orchestration" in result

    orch = result["orchestration"]
    assert orch["parallel_execution"] is True
    assert "code_analysis_agent" in orch["agents"]
    assert "security_vulnerability_agent" in orch["agents"]
    assert orch["agents"]["code_analysis_agent"]["status"] == "completed"
    assert orch["agents"]["security_vulnerability_agent"]["status"] == "completed"
    assert orch["total_duration_ms"] > 0.0


def test_unified_findings_merging(orchestrator):
    result = orchestrator.run_parallel_analysis(SAMPLE_PYTHON_DUAL_FLAWS, language="python")
    findings = result["findings"]

    # Must contain both security findings and code quality findings
    agent_names = {f.get("agent") for f in findings}
    assert "Security Vulnerability Agent" in agent_names, "Unified list must contain findings from Security Agent"
    assert "Code Analysis Agent" in agent_names, "Unified list must contain findings from Code Analysis Agent"

    # Must be sorted by severity_score descending
    scores = [float(f.get("severity_score", 0.0)) for f in findings]
    for i in range(len(scores) - 1):
        assert scores[i] >= scores[i + 1], f"Findings must be sorted descending by severity_score: {scores}"


def test_summary_metrics_accuracy(orchestrator):
    result = orchestrator.run_parallel_analysis(SAMPLE_PYTHON_DUAL_FLAWS, language="python")
    summary = result["summary"]

    total = summary["total_findings"]
    sec_count = summary["security_findings_count"]
    code_count = summary["code_quality_findings_count"]

    assert total == sec_count + code_count, "Total findings must equal sum of security and quality counts"
    assert sec_count > 0, "Security findings count should be > 0"
    assert code_count > 0, "Code quality findings count should be > 0"
    assert 0 <= summary["code_quality_score"] <= 100, "Quality score must be between 0 and 100"
    assert "security_posture" in summary, "Summary must include security posture rating"


def test_java_multi_agent_orchestration(orchestrator):
    result = orchestrator.run_parallel_analysis(SAMPLE_JAVA_DUAL_FLAWS, language="java")
    findings = result["findings"]
    summary = result["summary"]

    assert summary["total_findings"] > 0
    assert summary["security_findings_count"] >= 2  # Hardcoded secret + Runtime.exec
    assert summary["code_quality_findings_count"] >= 2  # System.out + long parameter list
    assert any(f["agent"] == "Security Vulnerability Agent" for f in findings)
    assert any(f["agent"] == "Code Analysis Agent" for f in findings)


def test_agent_exception_resilience(orchestrator, monkeypatch):
    """Case 2: One agent raises an exception; other agent's findings still returned."""
    def _exploding_code_agent(*args, **kwargs):
        raise RuntimeError("Simulated internal parser crash")

    monkeypatch.setattr(orchestrator.code_analysis_agent, "analyze", _exploding_code_agent)

    result = orchestrator.run_parallel_analysis(SAMPLE_PYTHON_DUAL_FLAWS, language="python")
    orch = result["orchestration"]
    assert orch["agents"]["code_analysis_agent"]["status"] == "failed"
    assert orch["agents"]["security_vulnerability_agent"]["status"] == "completed"
    assert len(result["findings"]) > 0
    assert any(f["agent"] == "Security Vulnerability Agent" for f in result["findings"])
    assert any("Code Analysis Agent failed" in err for err in orch["errors"])
    # Sensitive internal trace should NOT be exposed in errors
    assert not any("Traceback" in err for err in orch["errors"])


def test_agent_timeout_handling(monkeypatch):
    """Case 3: One agent times out; report identifies the incomplete agent."""
    import time
    fast_orchestrator = MultiAgentOrchestrator(timeout_seconds=0.2)

    def _slow_security_agent(*args, **kwargs):
        time.sleep(1.0)
        return []

    monkeypatch.setattr(fast_orchestrator.security_agent, "analyze", _slow_security_agent)

    result = fast_orchestrator.run_parallel_analysis(SAMPLE_PYTHON_DUAL_FLAWS, language="python")
    orch = result["orchestration"]
    assert orch["agents"]["security_vulnerability_agent"]["status"] == "timeout"
    assert any("exceeded the shared" in err for err in orch["errors"])
    assert result["summary"]["security_posture"] == "Unknown (Security Agent Incomplete)"


def test_security_grade_isolation():
    """Case 4: Security findings affect security grade, while code-quality findings do not."""
    orch = MultiAgentOrchestrator()

    # Code with ONLY code quality defects (no security vulnerabilities)
    code_quality_only = """def verbose_task(a, b, c, d, e, f, g):
    print("Log statement 1")
    print("Log statement 2")
    try:
        x = 10 / 2
    except:
        pass
    return x
"""
    result = orch.run_parallel_analysis(code_quality_only, language="python")
    summary = result["summary"]

    assert summary["security_findings_count"] == 0
    assert summary["code_quality_findings_count"] > 0
    assert summary["code_quality_score"] < 100  # Penalized by quality findings
    assert summary["security_posture"].startswith("A ("), (
        f"Security posture must be grade A when 0 security flaws exist, got: {summary['security_posture']}"
    )

