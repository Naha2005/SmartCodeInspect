"""
SmartCodeInspect Utilities Package.
Provides centralized severity calculations, radar scoring, and deduplication.
"""

from .severity_engine import (
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
)

__all__ = [
    "SeverityEngine",
    "get_severity_engine",
    "sort_findings",
    "get_severity_breakdown",
    "calculate_health_score",
    "calculate_security_score",
    "calculate_quality_score",
    "calculate_composite_score",
    "get_score_explanation",
    "calculate_six_dimensional_radar",
    "deduplicate_findings",
]
