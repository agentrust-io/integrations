from typing import Optional
from sentinel.models import SentinelInput, DetectionResult, Action, RiskLevel
from sentinel.detectors.base import BaseDetector


class DelegationEscalationDetector(BaseDetector):
    def __init__(self, max_depth: int = 2, risk_threshold: float = 0.8):
        self.max_depth = max_depth
        self.risk_threshold = risk_threshold

    def name(self) -> str:
        return "delegation_escalation"

    def detect(self, input_data: SentinelInput) -> DetectionResult:
        depth = len(input_data.delegation_chain)
        risk = 0.0
        reason = "Delegation chain within limits"

        if depth > self.max_depth:
            risk = min(1.0, 0.5 + 0.2 * (depth - self.max_depth))
            reason = f"Delegation depth {depth} exceeds threshold {self.max_depth}"
        elif depth == 2 and set(input_data.delegation_chain) == {"root", "admin"}:
            risk = 0.7
            reason = "Moderate risk delegation pattern (root + admin)"
        elif depth == 1 and "root" in input_data.delegation_chain:
            risk = 0.3
            reason = "Low risk delegation (root only)"
        elif depth == 0:
            risk = 0.0
            reason = "No delegation chain"

        detected = risk >= self.risk_threshold

        action = Action.QUARANTINE if risk > 0.7 else Action.ESCALATE if risk > 0.4 else Action.MONITOR
        risk_level = self._risk_level_from_score(risk)

        return self._create_result(
            detection_type="delegation_escalation",
            risk_score=risk,
            reason=reason,
            action=action,
            risk_level=risk_level,
            evidence={"delegation_chain": input_data.delegation_chain},
            detected=detected,
        )
