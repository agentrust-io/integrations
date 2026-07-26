from sentinel.models import SentinelInput, DetectionResult, DetectionType, RiskLevel
from sentinel.detectors.base import BaseDetector

class ToolDriftDetector(BaseDetector):
    """
    Detects when an agent starts calling tools it has never used before.
    """

    def name(self) -> str:
        return "tool_drift"

    def detect(self, input_data: SentinelInput) -> DetectionResult:
        # This is a simplified version. In production, you would maintain a baseline
        # of tool usage per agent over time.
        tool_names = [t.get("name", "") for t in input_data.tool_calls]
        unique_tools = set(tool_names)

        # Simulate: if more than 3 unique tools, flag as drift
        risk_score = min(len(unique_tools) * 0.15, 1.0)
        reason = f"Agent called {len(unique_tools)} unique tools"

        return DetectionResult(
            detection_type=DetectionType.TOOL_DRIFT,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            reason=reason,
            evidence={
                "tools_called": list(unique_tools),
                "count": len(unique_tools)
            }
        )

    def _risk_level(self, score: float) -> RiskLevel:
        if score < 0.3: return RiskLevel.LOW
        if score < 0.6: return RiskLevel.MEDIUM
        if score < 0.8: return RiskLevel.HIGH
        return RiskLevel.CRITICAL