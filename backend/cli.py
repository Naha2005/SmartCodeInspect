#!/usr/bin/env python3
"""
SmartCodeInspect Command-Line Interface (CLI).
Provides developer-first terminal execution and CI/CD automated pipeline auditing
with configurable quality thresholds, JSON/SARIF export, and zero-execution safety.

Usage:
    python backend/cli.py path/to/source.py
    python backend/cli.py path/to/Service.java --format sarif --output audit.sarif
    python backend/cli.py src/ --fail-on critical
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
_CURRENT_DIR = Path(__file__).resolve().parent
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))

try:
    from agents.orchestrator import MultiAgentOrchestrator
    from reports.sarif_generator import generate_sarif_report
except ImportError:
    from backend.agents.orchestrator import MultiAgentOrchestrator
    from backend.reports.sarif_generator import generate_sarif_report


def detect_language(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    if ext in (".py", ".pyw"):
        return "python"
    elif ext in (".java", ".jav"):
        return "java"
    return "python"


def main():
    parser = argparse.ArgumentParser(
        description="SmartCodeInspect: AI Code Review & OWASP Security Analysis CLI"
    )
    parser.add_argument("file", help="Path to Python or Java source file to inspect")
    parser.add_argument("--language", choices=["python", "java"], help="Source language (default: auto-detect)")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format")
    parser.add_argument("--output", help="Optional output file path")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "any"],
        default="critical",
        help="Exit with non-zero code if findings meet or exceed severity (default: critical)"
    )

    args = parser.parse_args()

    target_path = Path(args.file)
    if not target_path.exists() or not target_path.is_file():
        print(f"Error: Target file '{args.file}' not found or is not a regular file.", file=sys.stderr)
        sys.exit(2)

    language = args.language or detect_language(target_path)
    source_code = target_path.read_text(encoding="utf-8", errors="replace")

    orchestrator = MultiAgentOrchestrator()
    analysis = orchestrator.run_parallel_analysis(
        source_code=source_code,
        language=language,
        filename=target_path.name
    )

    summary = analysis.get("summary", {})
    findings = analysis.get("findings", [])
    pr_review = analysis.get("pr_summary", {})

    output_content = ""

    if args.format == "sarif":
        sarif_doc = generate_sarif_report(analysis, filename=target_path.name)
        output_content = json.dumps(sarif_doc, indent=2)
    elif args.format == "json":
        output_content = json.dumps(analysis, indent=2)
    else:
        # Formatted Terminal text
        verdict = pr_review.get("verdict", {}).get("label", "REVIEW")
        health = summary.get("overall_code_health_score", 100)
        lines = [
            "==================================================================",
            f"  SmartCodeInspect Audit: {target_path.name} ({language.upper()})",
            "==================================================================",
            f"  Review Verdict:    {verdict}",
            f"  Code Health Score: {health}/100",
            f"  Quality Score:     {summary.get('code_quality_score', 100)}/100",
            f"  Security Posture:  {summary.get('security_posture', 'A')}",
            f"  Total Findings:    {summary.get('total_findings', 0)} (Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)})",
            "------------------------------------------------------------------"
        ]
        if findings:
            lines.append("  Detected Findings:")
            for f in findings:
                sev = f.get("severity", "Medium")
                rule = f.get("rule_id", "UNKNOWN")
                line_no = f.get("line", 1)
                title = f.get("title", "")
                lines.append(f"   [{sev.upper()}] Line {line_no:3d} | {rule:12s} | {title}")
        else:
            lines.append("  🎉 0 Defects Detected. Code safe for production merge.")
        lines.append("==================================================================")
        output_content = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(output_content, encoding="utf-8")
        print(f"Results written to {args.output}")
    else:
        print(output_content)

    # Determine exit code based on --fail-on
    critical_count = summary.get("critical", 0)
    high_count = summary.get("high", 0)
    medium_count = summary.get("medium", 0)
    total_count = summary.get("total_findings", 0)

    if args.fail_on == "critical" and critical_count > 0:
        sys.exit(1)
    elif args.fail_on == "high" and (critical_count > 0 or high_count > 0):
        sys.exit(1)
    elif args.fail_on == "medium" and (critical_count > 0 or high_count > 0 or medium_count > 0):
        sys.exit(1)
    elif args.fail_on == "any" and total_count > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
