import logging
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    wait,
    ALL_COMPLETED,
)
from typing import Any, Dict, List, Optional, Tuple

try:
    from analyzers.rules.base_rule import Finding
    from agents.code_analysis_agent import CodeAnalysisAgent
    from agents.security_agent import SecurityVulnerabilityAgent
except ImportError:
    try:
        from backend.analyzers.rules.base_rule import Finding
        from backend.agents.code_analysis_agent import CodeAnalysisAgent
        from backend.agents.security_agent import SecurityVulnerabilityAgent
    except ImportError:
        from ..analyzers.rules.base_rule import Finding
        from .code_analysis_agent import CodeAnalysisAgent
        from .security_agent import SecurityVulnerabilityAgent


logger = logging.getLogger(__name__)


class MultiAgentOrchestrator:
    """
    Runs the Code Analysis Agent and Security Vulnerability Agent
    concurrently, combines their findings, and calculates summary metrics.

    This is static analysis. A clean report does not guarantee that
    submitted code is free from defects or security vulnerabilities.
    """

    def __init__(self, timeout_seconds: float = 15.0):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        self.code_analysis_agent = CodeAnalysisAgent()
        self.security_agent = SecurityVulnerabilityAgent()
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _finding_to_dict(finding: Any) -> Optional[Dict[str, Any]]:
        """Convert an agent finding into a dictionary safely."""
        try:
            if isinstance(finding, dict):
                result = dict(finding)
            elif hasattr(finding, "to_dict"):
                result = finding.to_dict()
            else:
                logger.warning(
                    "Ignoring unsupported finding type: %s",
                    type(finding).__name__,
                )
                return None

            if not isinstance(result, dict):
                logger.warning("Ignoring finding with invalid to_dict() output.")
                return None

            return result

        except Exception:
            logger.exception("Could not serialize an agent finding.")
            return None

    @staticmethod
    def _normalize_findings(result: Any) -> List[Dict[str, Any]]:
        """Normalize a list of Finding objects or dictionaries."""
        if result is None:
            return []

        if not isinstance(result, (list, tuple)):
            raise TypeError(
                "An analysis agent must return a list or tuple of findings."
            )

        findings = []

        for item in result:
            finding_dict = MultiAgentOrchestrator._finding_to_dict(item)

            if finding_dict is not None:
                findings.append(finding_dict)

        return findings

    @staticmethod
    def _safe_severity_score(finding: Dict[str, Any]) -> float:
        """Return a valid numeric score for sorting and aggregation."""
        try:
            score = float(finding.get("severity_score", 0.0))

            if score != score or score in (float("inf"), float("-inf")):
                return 0.0

            return max(0.0, min(10.0, score))

        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _safe_line_number(finding: Dict[str, Any]) -> int:
        try:
            return max(0, int(finding.get("line", 0)))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _severity(finding: Dict[str, Any]) -> str:
        value = str(finding.get("severity", "Informational")).strip().lower()

        allowed = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Informational",
            "info": "Informational",
        }

        return allowed.get(value, "Informational")

    @staticmethod
    def _agent_name(
        finding: Dict[str, Any],
        default: str,
    ) -> str:
        agent = finding.get("agent")

        if isinstance(agent, str) and agent.strip():
            return agent.strip()

        return default

    def _run_agent(
        self,
        agent: Any,
        source_code: str,
        language: str,
        filename: Optional[str],
        default_agent_name: str,
    ) -> Tuple[List[Dict[str, Any]], float]:
        """Run one agent and validate its result."""
        start = time.perf_counter()

        result = agent.analyze(
            source_code,
            language=language,
            filename=filename,
        )

        findings = self._normalize_findings(result)

        # Ensure every finding identifies its source agent.
        for finding in findings:
            if not finding.get("agent"):
                finding["agent"] = default_agent_name

        duration_ms = (time.perf_counter() - start) * 1000.0

        return findings, duration_ms

    def run_parallel_analysis(
        self,
        source_code: str,
        language: str,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute both agents concurrently and return a unified report.

        The timeout is a shared deadline for both agent futures, rather
        than a separate timeout for each agent.
        """
        start = time.perf_counter()

        code_findings: List[Dict[str, Any]] = []
        security_findings: List[Dict[str, Any]] = []

        code_duration_ms = 0.0
        security_duration_ms = 0.0

        code_status = "pending"
        security_status = "pending"
        errors: List[str] = []

        code_name = "Code Analysis Agent"
        security_name = "Security Vulnerability Agent"

        executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="sci_agent",
        )

        future_code = executor.submit(
            self._run_agent,
            self.code_analysis_agent,
            source_code,
            language,
            filename,
            code_name,
        )

        future_security = executor.submit(
            self._run_agent,
            self.security_agent,
            source_code,
            language,
            filename,
            security_name,
        )

        futures = {
            future_code: ("code", code_name),
            future_security: ("security", security_name),
        }

        try:
            completed, pending = wait(
                futures.keys(),
                timeout=self.timeout_seconds,
                return_when=ALL_COMPLETED,
            )

            for future in completed:
                agent_type, agent_label = futures[future]

                try:
                    findings, duration_ms = future.result()

                    if agent_type == "code":
                        code_findings = findings
                        code_duration_ms = duration_ms
                        code_status = "completed"
                    else:
                        security_findings = findings
                        security_duration_ms = duration_ms
                        security_status = "completed"

                except Exception as exc:
                    logger.exception("%s failed.", agent_label)

                    errors.append(
                        f"{agent_label} failed. "
                        f"Error type: {type(exc).__name__}."
                    )

                    if agent_type == "code":
                        code_status = "failed"
                    else:
                        security_status = "failed"

            for future in pending:
                agent_type, agent_label = futures[future]

                future.cancel()

                errors.append(
                    f"{agent_label} exceeded the shared "
                    f"{self.timeout_seconds:g}-second analysis deadline."
                )

                if agent_type == "code":
                    code_status = "timeout"
                else:
                    security_status = "timeout"

            # Do not wait for a still-running agent before returning.
            # Running Python threads cannot be forcibly stopped.
            executor.shutdown(wait=False, cancel_futures=True)
            executor = None

        finally:
            if executor is not None:
                executor.shutdown(wait=False, cancel_futures=True)

        total_duration_ms = (time.perf_counter() - start) * 1000.0

        findings = self._merge_findings(
            code_findings,
            security_findings,
        )

        summary = self._compute_summary(
            unified_findings=findings,
            code_findings=code_findings,
            security_findings=security_findings,
            security_status=security_status,
        )

        return {
            "findings": findings,
            "summary": summary,
            "orchestration": {
                "parallel_execution": True,
                "timeout_seconds": self.timeout_seconds,
                "total_duration_ms": round(total_duration_ms, 2),
                "agents": {
                    "code_analysis_agent": {
                        "name": code_name,
                        "status": code_status,
                        "duration_ms": round(code_duration_ms, 2),
                        "findings_count": len(code_findings),
                    },
                    "security_vulnerability_agent": {
                        "name": security_name,
                        "status": security_status,
                        "duration_ms": round(security_duration_ms, 2),
                        "findings_count": len(security_findings),
                    },
                },
                "errors": errors,
            },
        }

    def _merge_findings(
        self,
        code_findings: List[Dict[str, Any]],
        security_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Merge and deduplicate findings.

        Findings from different agents are retained independently.
        """
        unified: List[Dict[str, Any]] = []
        seen_keys = set()

        for default_agent, findings in (
            ("Security Vulnerability Agent", security_findings),
            ("Code Analysis Agent", code_findings),
        ):
            for original in findings:
                finding = dict(original)

                agent = self._agent_name(finding, default_agent)
                rule_id = str(finding.get("rule_id", "UNKNOWN"))
                line = self._safe_line_number(finding)
                evidence = str(finding.get("evidence", "")).strip()
                category = str(finding.get("category", "")).strip()
                title = str(finding.get("title", "")).strip()

                # Include agent and category to avoid suppressing
                # distinct findings from different analysis agents.
                dedup_key = (
                    agent,
                    rule_id,
                    line,
                    category,
                    title,
                    evidence,
                )

                if dedup_key in seen_keys:
                    continue

                seen_keys.add(dedup_key)
                finding["agent"] = agent
                finding["severity"] = self._severity(finding)
                finding["severity_score"] = self._safe_severity_score(
                    finding
                )

                unified.append(finding)

        unified.sort(
            key=lambda item: (
                -self._safe_severity_score(item),
                self._safe_line_number(item),
            )
        )

        return unified

    def _compute_summary(
        self,
        unified_findings: List[Dict[str, Any]],
        code_findings: List[Dict[str, Any]],
        security_findings: List[Dict[str, Any]],
        security_status: str,
    ) -> Dict[str, Any]:
        """Calculate finding counts, code-quality score and security grade."""
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }

        for finding in unified_findings:
            severity = self._severity(finding)
            counts[severity] += 1

        scores = [
            self._safe_severity_score(finding)
            for finding in unified_findings
        ]

        average_score = (
            round(sum(scores) / len(scores), 2)
            if scores
            else 0.0
        )

        # Score only findings originating from the Code Analysis Agent.
        quality_deduction = 0.0

        for finding in code_findings:
            severity = self._severity(finding)

            if severity == "Critical":
                quality_deduction += 15.0
            elif severity == "High":
                quality_deduction += 10.0
            elif severity == "Medium":
                quality_deduction += 5.0
            elif severity == "Low":
                quality_deduction += 2.0
            else:
                quality_deduction += 0.5

        code_quality_score = max(
            0,
            min(100, round(100.0 - quality_deduction)),
        )

        # The security grade must use security findings only.
        # A failed or timed-out security agent cannot receive a clean grade.
        if security_status != "completed":
            security_posture = "Unknown (Security Agent Incomplete)"
        else:
            security_severities = [
                self._severity(finding)
                for finding in security_findings
            ]

            critical_count = security_severities.count("Critical")
            high_count = security_severities.count("High")
            medium_count = security_severities.count("Medium")

            if critical_count > 0:
                security_posture = (
                    "F (Critical Security Findings Detected)"
                )
            elif high_count > 2:
                security_posture = (
                    "D (Multiple High-Severity Security Findings)"
                )
            elif high_count > 0:
                security_posture = (
                    "C (High-Severity Security Findings Detected)"
                )
            elif medium_count > 0:
                security_posture = (
                    "B (Medium-Severity Security Findings Detected)"
                )
            else:
                security_posture = (
                    "A (No Configured Security Findings Detected)"
                )

        # Consistent counts reflecting deduplicated unified report if pruning occurred
        if len(unified_findings) < (len(security_findings) + len(code_findings)):
            sec_count = sum(
                1 for f in unified_findings
                if self._agent_name(f, "") == "Security Vulnerability Agent"
            )
            code_count = len(unified_findings) - sec_count
        else:
            sec_count = len(security_findings)
            code_count = len(code_findings)

        return {
            "total_findings": len(unified_findings),
            "critical": counts["Critical"],
            "high": counts["High"],
            "medium": counts["Medium"],
            "low": counts["Low"],
            "informational": counts["Informational"],
            "security_findings_count": sec_count,
            "code_quality_findings_count": code_count,
            "average_severity_score": average_score,
            "code_quality_score": code_quality_score,
            "security_posture": security_posture,
        }


# Reusable orchestrator instance.
_global_orchestrator = MultiAgentOrchestrator()


def get_orchestrator() -> MultiAgentOrchestrator:
    """Return the reusable orchestrator instance."""
    return _global_orchestrator
