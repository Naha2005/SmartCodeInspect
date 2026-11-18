"""
SARIF v2.1.0 Static Analysis Results Interchange Format Generator.
Converts SmartCodeInspect multi-agent inspection findings into OASIS SARIF v2.1.0 JSON format,
compatible with GitHub Code Scanning, GitLab SAST, SonarQube, and VS Code SARIF viewers.
"""

from typing import Any, Dict, List, Optional


def _severity_to_sarif_level(severity: str) -> str:
    """Map internal severity to SARIF v2.1.0 result level."""
    s = (severity or "low").strip().lower()
    if s in ("critical", "high"):
        return "error"
    elif s == "medium":
        return "warning"
    else:
        return "note"


def generate_sarif_report(analysis_data: Dict[str, Any], filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate an authentic OASIS SARIF v2.1.0 JSON payload from multi-agent analysis data.
    """
    findings = analysis_data.get("findings", [])
    target_filename = filename or analysis_data.get("filename", "inspected_source")
    language = analysis_data.get("language", "python")

    rules_dict = {}
    results = []

    for f in findings:
        rule_id = str(f.get("rule_id", "GENERIC-RULE"))
        title = str(f.get("title", "Detected Code Issue"))
        description = str(f.get("description", title))
        severity = f.get("severity", "Medium")
        sarif_level = _severity_to_sarif_level(severity)
        line = max(1, int(f.get("line", 1) or 1))
        col = max(1, int(f.get("column", 1) or 1))
        cwe_id = f.get("cwe_id") or "CWE-General"
        references = f.get("owasp_references") or []
        help_uri = references[0] if references else "https://owasp.org/www-project-top-ten/"

        # Register unique rule metadata in the tool driver
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": title.replace(" ", "_"),
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "helpUri": help_uri,
                "properties": {
                    "tags": ["security" if f.get("category") == "Security Vulnerability" else "quality", language],
                    "cwe": [cwe_id] if cwe_id else [],
                    "precision": "high",
                    "problem.severity": sarif_level,
                },
                "defaultConfiguration": {
                    "level": sarif_level
                }
            }

        # Build SARIF result object
        result_entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "message": {
                "text": f"{title}: {description}"
            },
            "level": sarif_level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_filename,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": col,
                            "endLine": line,
                            "snippet": {
                                "text": str(f.get("evidence", "")).strip()
                            }
                        }
                    }
                }
            ]
        }

        # Attach Remediation fix if available
        remediation = f.get("remediation")
        if remediation and isinstance(remediation, dict) and remediation.get("corrected_code"):
            result_entry["fixes"] = [
                {
                    "description": {
                        "text": remediation.get("recommendation", "Apply secure remediation")
                    },
                    "replacement": {
                        "deletedRegion": {
                            "startLine": line,
                            "endLine": line
                        },
                        "insertedContent": {
                            "text": remediation.get("corrected_code", "")
                        }
                    }
                }
            ]

        results.append(result_entry)

    sarif_document = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SmartCodeInspect",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/Naha2005/SmartCodeInspect",
                        "rules": list(rules_dict.values())
                    }
                },
                "artifacts": [
                    {
                        "location": {
                            "uri": target_filename,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "sourceLanguage": language
                    }
                ],
                "results": results
            }
        ]
    }

    return sarif_document
