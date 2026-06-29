from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any
from sentinel.models import SentinelInput, DetectionResult, RiskLevel, Action


class BaseDetector(ABC):
    @abstractmethod
    def detect(self, input_data: SentinelInput) -> DetectionResult:
        pass

    @abstractmethod
    def name(self) -> str:
        pass

    def _create_result(
        self,
        detection_type: str,
        risk_score: float,
        reason: str,
        action: Action = Action.MONITOR,
        risk_level: RiskLevel = None,
        evidence: Optional[Dict[str, Any]] = None,
        detected: bool = False,
    ) -> DetectionResult:
        if risk_level is None:
            risk_level = self._risk_level_from_score(risk_score)

        return DetectionResult(
            detection_type=detection_type,
            risk_score=risk_score,
            risk_level=risk_level,
            reason=reason,
            action=action,
            timestamp=datetime.now().isoformat(),
            evidence=evidence or {},
            detected=detected,
        )

    def _risk_level_from_score(self, score: float) -> RiskLevel:
        if score < 0.3:
            return RiskLevel.LOW
        if score < 0.6:
            return RiskLevel.MEDIUM
        if score < 0.8:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL
