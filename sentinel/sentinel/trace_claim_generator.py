import json
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class TraceClaim:
    claim_id: str
    timestamp: float
    issuer: str
    subject: str
    event_type: str
    payload: Dict[str, Any]
    signature: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps({
            "claim_id": self.claim_id,
            "timestamp": self.timestamp,
            "issuer": self.issuer,
            "subject": self.subject,
            "event_type": self.event_type,
            "payload": self.payload,
            "signature": self.signature
        }, separators=(",", ":"))


class TraceClaimGenerator:
    def __init__(self, issuer_id: str = "sentinel"):
        self.issuer_id = issuer_id

    def generate_claim(self, enforcement_event: Dict[str, Any], subject: str = "agent-fleet") -> TraceClaim:
        return TraceClaim(
            claim_id=f"sentinel-{int(time.time())}-{enforcement_event.get('event_id', 'unknown')}",
            timestamp=time.time(),
            issuer=self.issuer_id,
            subject=subject,
            event_type=enforcement_event.get("event_type", "enforcement"),
            payload=enforcement_event
        )


# Convenience function for backward compatibility
def generate_trace_claim(event: Dict[str, Any]) -> str:
    gen = TraceClaimGenerator()
    claim = gen.generate_claim(event)
    return claim.to_json()