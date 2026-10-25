from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any


DEFAULT_SEVERITY_SCORES = {
    "Critical": 9.5,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Informational": 1.0,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Informational
    language: str  # python, java
    line: int
    column: int
    evidence: str
    risk_explanation: str
    mitigation: str
    owasp_references: List[str]
    confidence: str  # High, Medium, Low
    owasp_category: str = ""  # Human-readable OWASP Top 10 category label
    severity_score: float = 0.0
    category: str = "Security Vulnerability"  # Code Smell, Complexity, Design Anti-Pattern, Poor Coding Practice, Security Vulnerability
    agent: str = "Security Vulnerability Agent"
    cwe_id: str = ""

    def __post_init__(self):
        if self.severity_score <= 0.0:
            self.severity_score = DEFAULT_SEVERITY_SCORES.get(self.severity, 2.5)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

