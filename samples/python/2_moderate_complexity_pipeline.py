"""
Sample 2: Moderate Complexity (Code Smells & Resource Flaws)
Language: Python
Purpose: Demonstrates maintainability debt, resource leaks, and cyclomatic complexity issues.
Flagged Rules:
- DESIGN-PY-001 (Mutable default argument anti-pattern)
- PRACTICE-PY-001 (Print statement in production code)
- PRACTICE-PY-002 (Resource leak / open without with-context)
- COMPLEX-PY-002 (Deeply nested conditionals > 3 levels)
- SMELL-PY-004 (Empty exception handler / swallowed error)
"""

import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


# Smell 1: Mutable default argument anti-pattern
def process_pipeline_batch(records: List[Dict[str, Any]], error_log=[]):
    """Processes batch ETL records with maintainability smells."""
    # Smell 2: Print statement in production
    print(f"Starting batch of {len(records)} items")

    # Smell 3: Resource leak / unmanaged file descriptor without with-context
    metrics_file = open("pipeline.log", "a")
    metrics_file.write(f"Processed: {len(records)}\n")

    results = []
    # Smell 4: High cyclomatic complexity & deeply nested branches (>3 levels)
    for item in records:
        if item.get("status") == "ACTIVE":
            if item.get("tier") == "ENTERPRISE":
                if item.get("score", 0) > 80:
                    results.append({"id": item.get("id"), "action": "EXPEDITE"})
                else:
                    results.append({"id": item.get("id"), "action": "STANDARD"})
            elif item.get("tier") == "PREMIUM":
                results.append({"id": item.get("id"), "action": "STANDARD"})
            else:
                results.append({"id": item.get("id"), "action": "BATCH"})
        else:
            # Smell 5: Silenced error / overly broad empty exception handler
            try:
                error_log.append(f"Skipping {item.get('id')}")
            except Exception:
                pass

    metrics_file.close()
    return results
