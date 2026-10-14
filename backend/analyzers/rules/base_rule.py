from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
