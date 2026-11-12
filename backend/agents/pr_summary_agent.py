"""
PR Summary Agent for Smart Code Inspection Platform.

Compiles multi-agent inspection findings (Code Analysis Agent, Security Vulnerability Agent,
and Remediation Agent) into a structured pull request (PR) style review summary.
Produces executive overviews, severity breakdowns, prioritized fix lists (P0/P1/P2),
merge checklists, and exportable GitHub/GitLab markdown comments.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

AGENT_NAME = "PR Summary Agent"


class PRSummaryAgent:
    """
    PR Summary Agent:
    Compiles all multi-agent outputs into an actionable, professional Pull Request review summary.
    """

    def __init__(self):
        self.name = AGENT_NAME

    def _determine_verdict(
        self,
        critical_count: int,
        high_count: int,
        medium_count: int,
        quality_score: int,
        security_posture: str
    ) -> Dict[str, str]:
        """Determine PR merge decision status, badge, and reasoning."""
        if critical_count > 0:
            return {
                "decision": "CHANGES_REQUESTED",
                "label": "🔴 Changes Requested",
                "badge": "CHANGES_REQUESTED",
                "reason": (
                    f"Blocked: {critical_count} Critical vulnerability finding(s) detected. "
                    "All Critical findings must be remediated before this pull request can be merged."
                )
            }
        elif high_count > 0:
            return {
                "decision": "CHANGES_REQUESTED",
                "label": "🔴 Changes Requested",
                "badge": "CHANGES_REQUESTED",
                "reason": (
                    f"Blocked: {high_count} High-severity finding(s) detected. "
                    "High-severity security risks must be remediated prior to merge."
                )
            }
        elif medium_count > 0 or quality_score < 75:
            return {
                "decision": "COMMENT",
                "label": "🟡 Review Comments & Hardening Needed",
                "badge": "NEEDS_WORK",
                "reason": (
                    f"Review Comments: {medium_count} Medium-severity finding(s) and/or code quality score of "
                    f"{quality_score}/100. Resolution of recommendations is advised before production deployment."
                )
            }
        elif quality_score < 90:
            return {
                "decision": "APPROVED_WITH_COMMENTS",
                "label": "🟡 Approved with Minor Improvements",
                "badge": "APPROVED_WITH_COMMENTS",
                "reason": (
                    "Approved with suggestions: Code is secure with no critical or high vulnerabilities. "
                    "Consider addressing minor code smells and style recommendations."
                )
            }
        else:
            return {
                "decision": "APPROVED",
                "label": "🟢 Approved",
                "badge": "APPROVED",
                "reason": (
                    "Approved: Code passes all security standards and adheres to high engineering quality guidelines."
                )
            }

    def _calculate_health_score(
        self,
        quality_score: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int
    ) -> int:
        """
        Calculates an overall Composite Code Health Score (0 - 100).
        Weights security posture (65%) and code maintainability (35%).
        Caps health score when active critical/high vulnerabilities are present.
        """
        security_penalty = (critical_count * 50.0) + (high_count * 25.0) + (medium_count * 10.0) + (low_count * 2.0)
        security_score = max(0.0, 100.0 - security_penalty)

        health = (security_score * 0.65) + (float(quality_score) * 0.35)
        if critical_count > 0:
            health = min(health, 60.0)
        elif high_count > 0:
            health = min(health, 75.0)
        return max(0, min(100, round(health)))

    def _build_prioritized_fix_list(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Partitions and prioritizes findings into actionable engineering tiers:
        - P0 (Blockers): Critical and High findings (must fix before merge)
        - P1 (Important): Medium findings, resource leaks, complexity issues
        - P2 (Hygiene): Low findings, code smells, style, naming, docstrings
        """
        p0_list = []
        p1_list = []
        p2_list = []

        for finding in findings:
            sev = str(finding.get("severity", "Informational")).lower()
            rule_id = str(finding.get("rule_id", ""))
            agent = str(finding.get("agent", ""))

            item = {
                "rule_id": rule_id,
                "title": finding.get("title", "Issue"),
                "severity": finding.get("severity", "Medium"),
                "severity_score": finding.get("severity_score", 5.0),
                "line": finding.get("line", 0),
                "agent": agent,
                "evidence": finding.get("evidence", ""),
                "recommendation": finding.get("mitigation") or (
                    finding.get("remediation", {}).get("recommendation", "")
                ),
                "corrected_code": finding.get("remediation", {}).get("corrected_code", ""),
                "diff_example": finding.get("remediation", {}).get("diff_example", "")
            }

            if sev in ("critical", "high"):
                item["priority"] = "P0 - Blocker"
                p0_list.append(item)
            elif sev == "medium":
                item["priority"] = "P1 - Important"
                p1_list.append(item)
            else:
                item["priority"] = "P2 - Maintainability"
                p2_list.append(item)

        # Sort within each priority by line number
        p0_list.sort(key=lambda x: x.get("line", 0))
        p1_list.sort(key=lambda x: x.get("line", 0))
        p2_list.sort(key=lambda x: x.get("line", 0))

        return {
            "p0_blockers": p0_list,
            "p1_important": p1_list,
            "p2_maintainability": p2_list,
            "total_p0": len(p0_list),
            "total_p1": len(p1_list),
            "total_p2": len(p2_list)
        }

    def _build_merge_checklist(self, prioritized_fixes: Dict[str, Any]) -> List[str]:
        """Generate an actionable markdown checklist for code authors and reviewers."""
        checklist = []

        for item in prioritized_fixes.get("p0_blockers", []):
            line_str = f"line {item['line']}" if item['line'] else "scope"
            checklist.append(f"Resolve blocker: {item['title']} ({item['rule_id']}) at {line_str}")

        for item in prioritized_fixes.get("p1_important", []):
            line_str = f"line {item['line']}" if item['line'] else "scope"
            checklist.append(f"Address: {item['title']} ({item['rule_id']}) at {line_str}")

        if not checklist:
            checklist.append("Verify automated test suite passes with zero regressions")
            checklist.append("Peer review completed by domain maintainer")

        return checklist

    def _generate_markdown_report(
        self,
        filename: str,
        language: str,
        verdict: Dict[str, str],
        health_score: int,
        quality_score: int,
        security_posture: str,
        summary: Dict[str, Any],
        prioritized_fixes: Dict[str, Any],
        checklist: List[str],
        findings: List[Dict[str, Any]]
    ) -> str:
        """Render a clean, GitHub/GitLab-ready Pull Request review markdown comment."""
        md = []
        md.append(f"## 📋 Pull Request Code Review & Security Audit Summary")
        md.append("")
        md.append(f"**Target File:** `{filename}` &nbsp;|&nbsp; **Language:** `{language.title()}` &nbsp;|&nbsp; **Review Verdict:** **{verdict['label']}**")
        md.append("")
        md.append(f"> {verdict['reason']}")
        md.append("")

        # Metrics Table
        md.append("### 📊 Code Health & Security Posture")
        md.append("")
        md.append("| Metric | Score / Grade | Status |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Overall Code Health** | **{health_score}/100** | {'🟢 Excellent' if health_score >= 85 else '🟡 Needs Improvement' if health_score >= 60 else '🔴 Critical Risk'} |")
        md.append(f"| **Code Quality Score** | **{quality_score}/100** | {'🟢 High Maintainability' if quality_score >= 80 else '🟡 Moderate Debt'} |")
        md.append(f"| **Security Posture** | **{security_posture}** | {'🟢 Compliant' if 'A' in security_posture else '🔴 Non-Compliant'} |")
        md.append(f"| **Total Findings** | **{summary.get('total_findings', 0)}** | {summary.get('security_findings_count', 0)} Security &bull; {summary.get('code_quality_findings_count', 0)} Quality |")
        md.append("")

        # Severity Breakdown Table
        md.append("### 🛡️ Severity Breakdown")
        md.append("")
        md.append("| Severity Tier | Count | Merge Blocking? |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| 🚨 **Critical** | {summary.get('critical', 0)} | **Yes (Required)** |")
        md.append(f"| ⚠️ **High** | {summary.get('high', 0)} | **Yes (Required)** |")
        md.append(f"| ⚡ **Medium** | {summary.get('medium', 0)} | Strongly Recommended |")
        md.append(f"| ℹ️ **Low / Info** | {summary.get('low', 0) + summary.get('informational', 0)} | Optional / Cleanup |")
        md.append("")

        # Prioritized Action Items
        md.append("### 🎯 Prioritized Action Items")
        md.append("")

        if prioritized_fixes["p0_blockers"]:
            md.append("#### 🔴 P0 - Merge Blockers (Immediate Remediation Required)")
            for b in prioritized_fixes["p0_blockers"]:
                md.append(f"- **[Line {b['line']}] `{b['rule_id']}`**: **{b['title']}**")
                md.append(f"  - *Remediation:* {b['recommendation']}")
                if b["corrected_code"]:
                    md.append("  ```" + language.lower())
                    md.append("  " + b["corrected_code"].replace("\n", "\n  "))
                    md.append("  ```")
            md.append("")
        else:
            md.append("✅ **No P0 Blockers detected.**")
            md.append("")

        if prioritized_fixes["p1_important"]:
            md.append("#### 🟡 P1 - Important Refactoring & Security Hardening")
            for imp in prioritized_fixes["p1_important"][:5]:  # limit to top 5 in summary
                md.append(f"- **[Line {imp['line']}] `{imp['rule_id']}`**: {imp['title']}")
                md.append(f"  - *Guidance:* {imp['recommendation']}")
            if len(prioritized_fixes["p1_important"]) > 5:
                md.append(f"  *(and {len(prioritized_fixes['p1_important']) - 5} more P1 items...)*")
            md.append("")

        if prioritized_fixes["p2_maintainability"]:
            md.append(f"#### ℹ️ P2 - Hygiene & Style ({len(prioritized_fixes['p2_maintainability'])} items)")
            for hyg in prioritized_fixes["p2_maintainability"][:4]:
                md.append(f"- **[Line {hyg['line']}] `{hyg['rule_id']}`**: {hyg['title']}")
            if len(prioritized_fixes["p2_maintainability"]) > 4:
                md.append(f"  *(and {len(prioritized_fixes['p2_maintainability']) - 4} more P2 items...)*")
            md.append("")

        # Merge Checklist
        md.append("### 📝 Merge Readiness Checklist")
        md.append("")
        for task in checklist:
            md.append(f"- [ ] {task}")
        md.append("")

        md.append("---")
        md.append("*Generated automatically by AI Code Review & Security Analysis Multi-Agent Platform.*")

        return "\n".join(md)

    def generate_pr_summary(
        self,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Compile all agent outputs into a complete Pull Request review summary.
        Returns both structured JSON components and fully-formatted Markdown.
        """
        meta = metadata or {}
        filename = meta.get("filename", "inspected_source")
        language = meta.get("language", "python")

        crit = summary.get("critical", 0)
        high = summary.get("high", 0)
        med = summary.get("medium", 0)
        low = summary.get("low", 0)
        info = summary.get("informational", 0)
        quality_score = summary.get("code_quality_score", 100)
        security_posture = summary.get("security_posture", "A (Clean)")

        # 1. Determine PR verdict
        verdict = self._determine_verdict(
            critical_count=crit,
            high_count=high,
            medium_count=med,
            quality_score=quality_score,
            security_posture=security_posture
        )

        # 2. Composite health score
        health_score = self._calculate_health_score(
            quality_score=quality_score,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low + info
        )

        # 3. Prioritized fix list
        prioritized = self._build_prioritized_fix_list(findings)

        # 4. Merge checklist
        checklist = self._build_merge_checklist(prioritized)

        # 5. Extract top remediation highlights
        remediation_highlights = []
        for finding in findings:
            remediation = finding.get("remediation")
            if remediation and (finding.get("severity") in ("Critical", "High") or len(remediation_highlights) < 3):
                remediation_highlights.append({
                    "rule_id": finding.get("rule_id"),
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "line": finding.get("line"),
                    "recommendation": remediation.get("recommendation"),
                    "corrected_code": remediation.get("corrected_code"),
                    "diff_example": remediation.get("diff_example")
                })
                if len(remediation_highlights) >= 5:
                    break

        # 6. Generate formatted Markdown document
        markdown_text = self._generate_markdown_report(
            filename=filename,
            language=language,
            verdict=verdict,
            health_score=health_score,
            quality_score=quality_score,
            security_posture=security_posture,
            summary=summary,
            prioritized_fixes=prioritized,
            checklist=checklist,
            findings=findings
        )

        return {
            "agent": AGENT_NAME,
            "filename": filename,
            "language": language,
            "overall_health_score": health_score,
            "code_quality_score": quality_score,
            "security_posture": security_posture,
            "verdict": verdict,
            "severity_breakdown": {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "informational": info,
                "total": summary.get("total_findings", len(findings))
            },
            "prioritized_fix_list": prioritized,
            "remediation_highlights": remediation_highlights,
            "merge_checklist": checklist,
            "markdown": markdown_text
        }


# Singleton instance
_pr_summary_agent = PRSummaryAgent()


def get_pr_summary_agent() -> PRSummaryAgent:
    return _pr_summary_agent
