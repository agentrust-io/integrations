import pytest
from src.detectors import DelegationEscalationDetector
from src.models import DetectionResult, DetectionType, RiskLevel

def test_delegation_escalation_detector():
    detector = DelegationEscalationDetector()
    # Simulate a trace with delegation chain length > 2
    trace = {
        "agent_id": "test-agent",
        "delegation_chain": ["root", "admin", "superadmin"],  # length 3 > threshold 2
        "policy_version": "v1"
    }
    result = detector.detect(trace)
    assert result is not None
    assert result.detection_type == DetectionType.DELEGATION_ESCALATION
    assert result.risk_score > 0.5
    assert result.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

def test_delegation_escalation_detector_clean():
    detector = DelegationEscalationDetector()
    trace = {
        "agent_id": "test-agent",
        "delegation_chain": ["root", "admin"],  # length 2 allowed
        "policy_version": "v1"
    }
    result = detector.detect(trace)
    assert result is None or result.risk_score < 0.5