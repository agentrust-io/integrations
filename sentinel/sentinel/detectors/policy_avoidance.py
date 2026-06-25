from src.models import SentinelInput, DetectionResult, DetectionType, RiskLevel
from src.detectors.base import BaseDetector

class PolicyAvoidanceDetector(BaseDetector):
    """
    Detects repeated near-boundary requests that attempt to avoid policy enforcement.
    """

    def name(self) -> str:
        return "policy_avoidance"

    def detect(self, input_data: SentinelInput) -> DetectionResult:
        # Simulate: count how many tool calls are near policy boundaries
        boundary_actions = [t for t in input_data.tool_calls if "write" in t.get("name", "").lower()]
        risk_score = min(len(boundary_actions) * 0.2, 1.0)
        reason = f"{len(boundary_actions)} boundary-adjacent actions detected"

        return DetectionResult(
            detection_type=DetectionType.POLICY_AVOIDANCE,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            reason=reason,
            evidence={
                "boundary_actions": len(boundary_actions),
                "total_actions": len(input_data.tool_calls)
            }
        )

    def _risk_level(self, score: float) -> RiskLevel:
        if score < 0.3: return RiskLevel.LOW
        if score < 0.6: return RiskLevel.MEDIUM
        if score < 0.8: return RiskLevel.HIGH
        return RiskLevel.CRITICAL