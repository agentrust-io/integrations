from typing import List, Optional
from sentinel.schemas import SentinelInput, DetectionResult   # absolute import


class DelegationEscalationDetector:
    def __init__(self, max_depth: int = 2, risk_threshold: float = 0.8):
        self.max_depth = max_depth
        self.risk_threshold = risk_threshold

    def detect(self, input_data: SentinelInput) -> DetectionResult:
        depth = len(input_data.delegation_chain)
        risk = 0.0
        if depth > self.max_depth:
            risk = min(1.0, 0.5 + 0.2 * (depth - self.max_depth))
        elif depth == 2 and set(input_data.delegation_chain) == {"root", "admin"}:
            risk = 0.7
        elif depth == 1 and "root" in input_data.delegation_chain:
            risk = 0.3

        detected = risk >= self.risk_threshold
        reason = None
        if detected:
            reason = f"Delegation depth {depth} exceeds threshold {self.max_depth}" if depth > self.max_depth else "Suspicious delegation pattern"
        return DetectionResult(detected=detected, risk_score=risk, reason=reason)