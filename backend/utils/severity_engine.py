"""
Centralized Severity Engine for SmartCodeInspect.
Provides a single source of truth for:
- Severity hierarchy, weights, and confidence normalization
- Finding sorting and breakdown calculations
- Security, Quality, Composite Health, and Deduction Breakdown scoring
- Cross-agent finding deduplication and correlation
- Six-Dimensional Code Quality Radar Chart calculations (0-100 finding-driven)
"""

from typing import Any, Dict, List, Optional, Tuple, Union


# Severity ranks (higher number = more severe)
SEVERITY_RANKS: Dict[str, int] = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 30,
    "LOW": 20,
    "INFORMATIONAL": 10,
    "INFO": 10,
}

# Standard penalty weights for scores
QUALITY_DEDUCTION_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 15.0,
    "HIGH": 10.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFORMATIONAL": 0.5,
    "INFO": 0.5,
}

SECURITY_PENALTY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 50.0,
    "HIGH": 25.0,
    "MEDIUM": 10.0,
    "LOW": 2.0,
    "INFORMATIONAL": 2.0,
    "INFO": 2.0,
}

# Radar dimension penalty weights per severity
RADAR_PENALTY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 4.0,
    "INFORMATIONAL": 1.0,
    "INFO": 1.0,
}

# The 6 Radar Dimensions
RADAR_DIMENSIONS = [
    "Code Quality",
    "Security",
    "Complexity",
    "Maintainability",
    "Best Practices",
    "Input Validation",
]


class SeverityEngine:
    """
    Centralized, thread-safe engine for all severity, scoring, correlation,
    and radar calculations across SmartCodeInspect.
    """

    def __init__(
        self,
        security_weights: Optional[Dict[str, float]] = None,
        quality_weights: Optional[Dict[str, float]] = None,
        radar_weights: Optional[Dict[str, float]] = None,
    ):
        self.security_weights = dict(security_weights or SECURITY_PENALTY_WEIGHTS)
        self.quality_weights = dict(quality_weights or QUALITY_DEDUCTION_WEIGHTS)
        self.radar_weights = dict(radar_weights or RADAR_PENALTY_WEIGHTS)

    # -------------------------------------------------------------------------
    # Normalization Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def normalize_severity(severity: Any) -> str:
        """Standardize severity into title-case (Critical, High, Medium, Low, Informational)."""
        s = str(severity or "").strip().upper()
        if s == "INFO":
            return "Informational"
        if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            return s.capitalize()
        return "Informational"

    @staticmethod
    def normalize_confidence(confidence: Any) -> float:
        """
        Normalize confidence value to a float between 0.0 and 1.0.
        Supports both string labels ('High', 'Medium', 'Low') and numeric values.
        """
        if confidence is None:
            return 1.0
        if isinstance(confidence, (int, float)):
            return max(0.0, min(1.0, float(confidence)))
        
        c = str(confidence).strip().upper()
        if c == "HIGH":
            return 1.0
        elif c in ("MEDIUM", "MED"):
            return 0.75
        elif c == "LOW":
            return 0.5
        
        try:
            val = float(confidence)
            return max(0.0, min(1.0, val))
        except (ValueError, TypeError):
            return 1.0

    @staticmethod
    def get_severity_rank(severity: Any) -> int:
        """Get integer rank for ordering (50=Critical down to 10=Info)."""
        s = str(severity or "").strip().upper()
        return SEVERITY_RANKS.get(s, 10)

    # -------------------------------------------------------------------------
    # Sorting & Severity Breakdown
    # -------------------------------------------------------------------------

    def sort_findings(
        self, findings: List[Dict[str, Any]], sort_by: str = "severity"
    ) -> List[Dict[str, Any]]:
        """
        Sort findings by severity descending (Critical first) then by line number ascending.
        """
        def _sort_key(item: Dict[str, Any]) -> Tuple[int, int]:
            sev = item.get("severity") or item.get("level") or "Informational"
            rank = self.get_severity_rank(sev)
            line = item.get("line") or item.get("line_number") or 0
            try:
                line_num = int(line)
            except (ValueError, TypeError):
                line_num = 0
            return (-rank, line_num)

        return sorted(findings, key=_sort_key)

    def get_severity_breakdown(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Produce a breakdown dictionary mapping each severity category to count,
        including lowercase and titlecase keys for seamless UI and report compatibility.
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "total": len(findings),
            # Titlecase keys for PR Summary compatibility
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
            "total_findings": len(findings),
        }

        for finding in findings:
            sev = self.normalize_severity(
                finding.get("severity") or finding.get("level")
            )
            lower_sev = sev.lower()
            if lower_sev in counts:
                counts[lower_sev] += 1
            if sev in counts:
                counts[sev] += 1

        return counts

    # -------------------------------------------------------------------------
    # Quality & Security Scoring
    # -------------------------------------------------------------------------

    def calculate_quality_score(
        self, code_findings: List[Dict[str, Any]]
    ) -> int:
        """
        Calculate Code Quality score (0 - 100) based strictly on code-analysis findings.
        Applies confidence-weighted deductions.
        """
        deduction = 0.0
        for f in code_findings:
            sev = str(f.get("severity") or f.get("level") or "INFO").strip().upper()
            weight = self.quality_weights.get(sev, 0.5)
            conf = self.normalize_confidence(f.get("confidence"))
            deduction += weight * conf

        return max(0, min(100, round(100.0 - deduction)))

    def calculate_security_score(
        self, security_findings: List[Dict[str, Any]]
    ) -> Tuple[float, str]:
        """
        Calculate raw security score (0.0 - 100.0) and letter posture grade (A - F).
        """
        sec_penalty = 0.0
        crit_count = 0
        high_count = 0
        med_count = 0

        for f in security_findings:
            sev = str(f.get("severity") or f.get("level") or "INFO").strip().upper()
            weight = self.security_weights.get(sev, 2.0)
            conf = self.normalize_confidence(f.get("confidence"))
            sec_penalty += weight * conf

            if sev == "CRITICAL":
                crit_count += 1
            elif sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                med_count += 1

        sec_score = max(0.0, 100.0 - sec_penalty)

        if crit_count > 0:
            posture = "F (Critical Security Findings Detected)"
        elif high_count > 2:
            posture = "D (Multiple High-Severity Security Findings)"
        elif high_count > 0:
            posture = "C (High-Severity Security Findings Detected)"
        elif med_count > 0:
            posture = "B (Medium-Severity Security Findings Detected)"
        else:
            posture = "A (No Configured Security Findings Detected)"

        return sec_score, posture

    # -------------------------------------------------------------------------
    # Composite Health Score
    # -------------------------------------------------------------------------

    def calculate_composite_score(
        self,
        security_score: float,
        quality_score: Union[int, float],
        critical_count: int = 0,
        high_count: int = 0,
    ) -> int:
        """
        Calculate unified Composite Health Score (0 - 100).
        Weights security (65%) and quality (35%), capping score when critical/high issues exist.
        """
        composite = (security_score * 0.65) + (float(quality_score) * 0.35)
        if critical_count > 0:
            composite = min(composite, 60.0)
        elif high_count > 0:
            composite = min(composite, 75.0)

        return max(0, min(100, round(composite)))

    def calculate_health_score(
        self,
        findings: List[Dict[str, Any]],
        code_findings: Optional[List[Dict[str, Any]]] = None,
        security_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """Convenience method to calculate composite health score from lists of findings."""
        if code_findings is None:
            code_findings = [f for f in findings if f.get("agent") != "Security Vulnerability Agent"]
        if security_findings is None:
            security_findings = [f for f in findings if f.get("agent") == "Security Vulnerability Agent"]

        quality_score = self.calculate_quality_score(code_findings)
        sec_score, _ = self.calculate_security_score(security_findings)

        crit_count = sum(
            1 for f in findings
            if str(f.get("severity", "")).upper() == "CRITICAL"
        )
        high_count = sum(
            1 for f in findings
            if str(f.get("severity", "")).upper() == "HIGH"
        )

        return self.calculate_composite_score(sec_score, quality_score, crit_count, high_count)

    # -------------------------------------------------------------------------
    # Finding Deduplication & Cross-Agent Correlation
    # -------------------------------------------------------------------------

    def deduplicate_and_correlate(
        self,
        code_findings: List[Dict[str, Any]],
        security_findings: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Deduplicates and correlates findings between Code Analysis and Security agents.
        Findings referring to the same line with overlapping rules/evidence are merged into
        a correlated finding with tracking field `merged_from_agents` without dropping context.
        Returns: (unified_findings, count_of_duplicates_excluded)
        """
        unified: List[Dict[str, Any]] = []
        duplicates_excluded = 0
        
        # Track seen (normalized_line, evidence_snippet_or_rule_key)
        seen_keys: Dict[Tuple[int, str], Dict[str, Any]] = {}

        all_findings = []
        for f in security_findings:
            f_copy = dict(f)
            if "agent" not in f_copy:
                f_copy["agent"] = "Security Vulnerability Agent"
            all_findings.append(f_copy)

        for f in code_findings:
            f_copy = dict(f)
            if "agent" not in f_copy:
                f_copy["agent"] = "Code Analysis Agent"
            all_findings.append(f_copy)

        for item in all_findings:
            line = item.get("line") or item.get("line_number") or 0
            try:
                line_num = int(line)
            except (ValueError, TypeError):
                line_num = 0

            rule_id = str(item.get("rule_id") or item.get("rule") or "").strip().upper()
            evidence = str(item.get("evidence") or item.get("code") or "").strip()
            
            # Key for correlation: same line and identical rule or identical evidence
            evidence_key = evidence[:60].lower() if evidence else rule_id
            corr_key = (line_num, evidence_key)

            if line_num > 0 and corr_key in seen_keys:
                # Merge into existing finding
                duplicates_excluded += 1
                existing = seen_keys[corr_key]
                
                # Maintain correlated agent history
                merged_agents = existing.setdefault("merged_from_agents", [existing.get("agent", "Unknown")])
                curr_agent = item.get("agent", "Unknown")
                if curr_agent not in merged_agents:
                    merged_agents.append(curr_agent)
                
                # Retain higher severity
                curr_rank = self.get_severity_rank(item.get("severity"))
                existing_rank = self.get_severity_rank(existing.get("severity"))
                if curr_rank > existing_rank:
                    existing["severity"] = item.get("severity")
                    existing["severity_score"] = item.get("severity_score", curr_rank)
                    existing["rule_id"] = item.get("rule_id", existing.get("rule_id"))
                    existing["message"] = item.get("message", existing.get("message"))
                
                # Correlate remediation if one has it and other doesn't
                if not existing.get("remediation") and item.get("remediation"):
                    existing["remediation"] = item["remediation"]
            else:
                item_copy = dict(item)
                item_copy["merged_from_agents"] = [item_copy.get("agent", "Unknown")]
                if line_num > 0:
                    seen_keys[corr_key] = item_copy
                unified.append(item_copy)

        return self.sort_findings(unified), duplicates_excluded

    # -------------------------------------------------------------------------
    # Explainable Score & Deduction Breakdown
    # -------------------------------------------------------------------------

    def get_score_explanation(
        self,
        findings: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]] = None,
        duplicates_excluded: int = 0,
    ) -> Dict[str, Any]:
        """
        Generate transparent, explainable deduction accounting:
        - Starting score (100)
        - Deductions per finding with rule, line, weight, and confidence
        - Duplicates excluded count
        - Final scores (Quality, Security, Composite Health)
        - Clear human-readable summary narrative
        """
        starting_score = 100
        itemized_deductions = []

        code_findings = [f for f in findings if f.get("agent") != "Security Vulnerability Agent"]
        sec_findings = [f for f in findings if f.get("agent") == "Security Vulnerability Agent"]

        total_quality_deduction = 0.0
        for f in code_findings:
            sev = str(f.get("severity") or f.get("level") or "INFO").strip().upper()
            w = self.quality_weights.get(sev, 0.5)
            c = self.normalize_confidence(f.get("confidence"))
            ded = round(w * c, 2)
            total_quality_deduction += ded
            itemized_deductions.append({
                "type": "Code Quality",
                "rule_id": f.get("rule_id") or f.get("rule") or "GENERAL-SMELL",
                "severity": self.normalize_severity(sev),
                "line": f.get("line") or f.get("line_number"),
                "confidence": c,
                "deduction": ded,
                "message": f.get("message", "")
            })

        total_security_penalty = 0.0
        for f in sec_findings:
            sev = str(f.get("severity") or f.get("level") or "INFO").strip().upper()
            w = self.security_weights.get(sev, 2.0)
            c = self.normalize_confidence(f.get("confidence"))
            ded = round(w * c, 2)
            total_security_penalty += ded
            itemized_deductions.append({
                "type": "Security",
                "rule_id": f.get("rule_id") or f.get("rule") or "SEC-VULN",
                "severity": self.normalize_severity(sev),
                "line": f.get("line") or f.get("line_number"),
                "confidence": c,
                "deduction": ded,
                "message": f.get("message", "")
            })

        quality_score = max(0, min(100, round(100.0 - total_quality_deduction)))
        sec_score = max(0.0, 100.0 - total_security_penalty)
        crit_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
        final_health = self.calculate_composite_score(sec_score, quality_score, crit_count, high_count)

        narrative = (
            f"Inspection started with a baseline score of {starting_score}. "
            f"{len(itemized_deductions)} findings contributed to deductions "
            f"({total_quality_deduction:.1f} pts code quality, {total_security_penalty:.1f} pts security). "
            f"{duplicates_excluded} overlapping/duplicate finding(s) were merged to prevent double penalty. "
            f"Resulting overall composite health score is {final_health}/100."
        )

        return {
            "starting_score": starting_score,
            "final_health_score": final_health,
            "quality_score": quality_score,
            "security_score": round(sec_score, 1),
            "total_quality_deduction": round(total_quality_deduction, 2),
            "total_security_penalty": round(total_security_penalty, 2),
            "duplicates_excluded": duplicates_excluded,
            "itemized_deductions": itemized_deductions,
            "narrative_explanation": narrative,
        }

    # -------------------------------------------------------------------------
    # Phase 3: Six-Dimensional Code Quality Radar Chart
    # -------------------------------------------------------------------------

    def calculate_six_dimensional_radar(
        self,
        findings: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate the exact 6-Dimensional Radar Chart scores (0 - 100):
        1. Code Quality: General smells, naming, long functions, prints
        2. Security: Injection, hardcoded secrets, OWASP Top 10
        3. Complexity: Cyclomatic complexity, deep nesting
        4. Maintainability: Design anti-patterns, god functions, tight coupling
        5. Best Practices: Risky calls without error handling, bare excepts, resource leaks
        6. Input Validation: Injection vectors, path traversal, untrusted input

        All scores are finding-driven and explainable (starting at 100).
        """
        # Bucket findings into the 6 dimensions
        dimension_penalties: Dict[str, float] = {d: 0.0 for d in RADAR_DIMENSIONS}
        dimension_counts: Dict[str, int] = {d: 0 for d in RADAR_DIMENSIONS}
        dimension_findings: Dict[str, List[Dict[str, Any]]] = {d: [] for d in RADAR_DIMENSIONS}

        for f in findings:
            rule_id = str(f.get("rule_id") or f.get("rule") or "").upper()
            msg = str(f.get("message") or "").lower()
            sev = str(f.get("severity") or f.get("level") or "INFO").strip().upper()
            weight = self.radar_weights.get(sev, 1.0)
            conf = self.normalize_confidence(f.get("confidence"))
            deduction = weight * conf

            assigned_dimensions = []

            # 1. Input Validation: SQLi, Command Injection, SSRF, Path Traversal, Untrusted Input
            if (
                any(k in rule_id for k in ("001", "002", "004", "005", "INPUT", "INJECT", "TRAVERSAL"))
                or any(w in msg for w in ("sql", "command injection", "path traversal", "xss", "ssrf", "input", "sanitize"))
            ):
                assigned_dimensions.append("Input Validation")

            # 2. Security: Any OWASP / SEC- rule or Security Agent finding
            if (
                rule_id.startswith("SEC-")
                or f.get("agent") == "Security Vulnerability Agent"
                or any(w in msg for w in ("security", "secret", "hardcoded", "token", "password", "crypto", "cipher", "injection", "deserialization", "cwe", "owasp"))
            ):
                assigned_dimensions.append("Security")

            # 3. Complexity: Deep nesting, complex logic, long functions
            if (
                rule_id.startswith("COMPLEX-")
                or "COMPLEX" in rule_id
                or any(w in msg for w in ("nesting", "cyclomatic", "complex", "too many branches"))
            ):
                assigned_dimensions.append("Complexity")

            # 4. Maintainability: Design anti-patterns, god functions, tight coupling, magic numbers
            if (
                rule_id.startswith("DESIGN-")
                or "DESIGN" in rule_id
                or any(w in msg for w in ("god function", "parameter list", "coupling", "maintainability", "magic number"))
            ):
                assigned_dimensions.append("Maintainability")

            # 5. Best Practices: Risky calls without error handling, bare excepts, resource leaks
            if (
                rule_id.startswith("PRACTICE-")
                or rule_id.startswith("RISK-")
                or any(w in msg for w in ("resource leak", "bare except", "unhandled", "timeout", "open(", "try-with-resources", "exception handling"))
            ):
                assigned_dimensions.append("Best Practices")

            # 6. Code Quality: Long functions, prints, naming, dead code, general smells
            if (
                rule_id.startswith("SMELL-")
                or not assigned_dimensions  # fallback to Code Quality if no other matched
                or any(w in msg for w in ("print statement", "naming", "dead code", "mutable default", "code smell"))
            ):
                assigned_dimensions.append("Code Quality")

            # Deduplicate dimension assignments per finding
            for dim in set(assigned_dimensions):
                dimension_penalties[dim] += deduction
                dimension_counts[dim] += 1
                dimension_findings[dim].append({
                    "rule_id": rule_id,
                    "severity": self.normalize_severity(sev),
                    "deduction": round(deduction, 1),
                    "line": f.get("line") or f.get("line_number"),
                    "message": f.get("message", "")
                })

        # Calculate final 0 - 100 scores
        radar_scores: Dict[str, int] = {}
        dimension_details: Dict[str, Dict[str, Any]] = {}

        for dim in RADAR_DIMENSIONS:
            score = max(0, min(100, round(100.0 - dimension_penalties[dim])))
            radar_scores[dim] = score
            dimension_details[dim] = {
                "score": score,
                "findings_count": dimension_counts[dim],
                "total_deduction": round(dimension_penalties[dim], 1),
                "status": (
                    "Excellent" if score >= 90
                    else "Good" if score >= 75
                    else "Needs Improvement" if score >= 50
                    else "Critical Attention Required"
                ),
                "contributing_findings": dimension_findings[dim][:5],  # top 5
            }

        return {
            "radar_scores": radar_scores,
            "dimension_details": dimension_details,
            "dimensions_order": RADAR_DIMENSIONS,
            "scoring_status": "complete",
            "average_radar_score": round(sum(radar_scores.values()) / len(radar_scores), 1)
        }


# Global singleton instance
_severity_engine = SeverityEngine()


def get_severity_engine() -> SeverityEngine:
    """Retrieve singleton SeverityEngine instance."""
    return _severity_engine


# Functional interface matching specification
def sort_findings(findings: List[Dict[str, Any]], sort_by: str = "severity") -> List[Dict[str, Any]]:
    return _severity_engine.sort_findings(findings, sort_by=sort_by)


def get_severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return _severity_engine.get_severity_breakdown(findings)


def calculate_health_score(
    findings: List[Dict[str, Any]],
    code_findings: Optional[List[Dict[str, Any]]] = None,
    security_findings: Optional[List[Dict[str, Any]]] = None,
) -> int:
    return _severity_engine.calculate_health_score(findings, code_findings, security_findings)


def calculate_security_score(security_findings: List[Dict[str, Any]]) -> Tuple[float, str]:
    return _severity_engine.calculate_security_score(security_findings)


def calculate_quality_score(code_findings: List[Dict[str, Any]]) -> int:
    return _severity_engine.calculate_quality_score(code_findings)


def calculate_composite_score(
    security_score: float,
    quality_score: Union[int, float],
    critical_count: int = 0,
    high_count: int = 0,
) -> int:
    return _severity_engine.calculate_composite_score(
        security_score, quality_score, critical_count, high_count
    )


def get_score_explanation(
    findings: List[Dict[str, Any]],
    summary: Optional[Dict[str, Any]] = None,
    duplicates_excluded: int = 0,
) -> Dict[str, Any]:
    return _severity_engine.get_score_explanation(
        findings, summary, duplicates_excluded=duplicates_excluded
    )


def calculate_six_dimensional_radar(
    findings: List[Dict[str, Any]],
    summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return _severity_engine.calculate_six_dimensional_radar(findings, summary)


def deduplicate_findings(
    code_findings: List[Dict[str, Any]],
    security_findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    return _severity_engine.deduplicate_and_correlate(code_findings, security_findings)
