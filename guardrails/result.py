from dataclasses import dataclass, field
from typing import Any, Dict, List

@dataclass
class GuardrailResult:
    allowed: bool = True
    text: str = ""
    action: str = "allow"
    reasons: List[str] = field(default_factory=list)
    detections: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def merge(self, other: "GuardrailResult") -> "GuardrailResult":
        self.allowed = self.allowed and other.allowed
        self.text = other.text
        if other.action != "allow":
            self.action = other.action
        self.reasons.extend(other.reasons)
        self.detections.extend(other.detections)
        self.risk_score = max(self.risk_score, other.risk_score)
        self.metadata.update(other.metadata)
        return self
