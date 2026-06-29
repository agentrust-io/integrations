import pytest
from sentinel.detectors.delegation_escalation import DelegationEscalationDetector
from sentinel.models import SentinelInput   # use models, not schemas

@pytest.fixture
def detector():
    return DelegationEscalationDetector()

def test_clean_delegation(detector):
    input_data = SentinelInput(
        trace_id="test-001",
        delegation_chain=["root", "admin"],
        policy_version="v1",
        agent_id="alice",
        action="read"
    )
    result = detector.detect(input_data)
    assert result.risk_score == 0.7
    assert result.detected is False

def test_risky_delegation(detector):
    input_data = SentinelInput(
        trace_id="test-002",
        delegation_chain=["root", "admin", "finance", "ops"],
        policy_version="v1",
        agent_id="bob",
        action="write"
    )
    result = detector.detect(input_data)
    assert result.risk_score > 0.8
    assert result.detected is True