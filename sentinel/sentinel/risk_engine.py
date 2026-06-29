from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from sentinel.models import (
    SentinelInput,
    SentinelOutput,
    DetectionResult,
    RiskLevel,
    Action,
    TimelineEvent,
    CollusionPattern,
    QuarantineRecord,
)
from sentinel.detectors import DelegationEscalationDetector
from sentinel.quarantine import generate_quarantine


class RiskEngine:
    def __init__(self):
        self.detectors = [DelegationEscalationDetector()]

    def evaluate(self, input_data: SentinelInput) -> SentinelOutput:
        detections: List[DetectionResult] = []
        total_risk = 0.0
        timeline: List[TimelineEvent] = []
        quarantine_recommended = False
        decision = "ADMIT"
        reason = None

        for detector in self.detectors:
            result = detector.detect(input_data)

            if result.risk_score > 0.7:
                result.action = Action.QUARANTINE
                quarantine_recommended = True
            elif result.risk_score > 0.4:
                result.action = Action.ESCALATE
            else:
                result.action = Action.MONITOR

            detections.append(result)
            total_risk += result.risk_score

            timeline.append(TimelineEvent(
                timestamp=datetime.now().isoformat(),
                agent_id=input_data.agent_id,
                event_type=result.detection_type or "detection",
                description=result.reason or "Detection triggered",
                severity=result.risk_level.value if result.risk_level else str(result.risk_score)
            ))

        avg_risk = total_risk / len(self.detectors) if self.detectors else 0.0

        if avg_risk > 0.7:
            decision = "DENY"
            reason = f"Risk score {avg_risk:.2f} exceeds threshold"
        elif any(d.risk_score > 0.8 for d in detections):
            decision = "DENY"
            high_risk = max(detections, key=lambda d: d.risk_score)
            reason = f"Critical detection: {high_risk.reason or 'high risk detected'}"
        elif avg_risk > 0.4:
            decision = "REVIEW"
            reason = f"Moderate risk score {avg_risk:.2f} requires review"

        output = SentinelOutput(
            trace_id=input_data.trace_id,
            risk_score=avg_risk,
            risk_level=self._risk_level(avg_risk),
            detections=detections,
            quarantine_recommended=quarantine_recommended,
            timeline=timeline,
            decision=decision,
            reason=reason
        )

        if quarantine_recommended:
            output = generate_quarantine(output, input_data.agent_id)

        return output

    def _risk_level(self, score: float) -> RiskLevel:
        if score < 0.3:
            return RiskLevel.LOW
        if score < 0.6:
            return RiskLevel.MEDIUM
        if score < 0.8:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL
