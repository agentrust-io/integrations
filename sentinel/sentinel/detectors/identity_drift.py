from src.models import SentinelInput, DetectionResult, DetectionType, RiskLevel
from src.detectors.base import BaseDetector

class IdentityDriftDetector(BaseDetector):
    """
    Detects when the runtime identity deviates from the baseline.
    """

    def name(self) -> str:
        return "identity_drift"

    def detect(self, input_data: SentinelInput) -> DetectionResult:
        # Simplified: check if observer_identity_hash has changed
        # In production, you would maintain a baseline per agent.
        # For now, we assume any change is suspicious.
        risk_score = 0.0
        reason = "Identity matches baseline"

        # In a real implementation, you would compare against a stored baseline.
        # This is a placeholder that always returns low risk.
        return DetectionResult(
            detection_type=DetectionType.IDENTITY_DRIFT,
            risk_score=0.1,
            risk_level=RiskLevel.LOW,
            reason="Identity stable",
            evidence={"observer_identity_hash": input_data.observer_identity_hash}
        )