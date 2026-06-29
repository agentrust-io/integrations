from .delegation_escalation import DelegationEscalationDetector
from .base import BaseDetector

# Only expose the working detector
__all__ = [
    "DelegationEscalationDetector",
    "BaseDetector",
]