import json
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, date


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime and date objects."""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


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
        # Use the custom encoder to handle datetime objects in payload
        return json.dumps({
            "claim_id": self.claim_id,
            "timestamp": self.timestamp,
            "issuer": self.issuer,
            "subject": self.subject,
            "event_type": self.event_type,
            "payload": self._serialize_payload(self.payload),
            "signature": self.signature
        }, separators=(",", ":"), cls=DateTimeEncoder)

    def _serialize_payload(self, payload: Any) -> Any:
        """Recursively convert datetime objects in payload to ISO strings."""
        if isinstance(payload, dict):
            return {k: self._serialize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self._serialize_payload(v) for v in payload]
        elif isinstance(payload, (datetime, date)):
            return payload.isoformat()
        else:
            return payload


class TraceClaimGenerator:
    def __init__(self, issuer_id: str = "sentinel"):
        self.issuer_id = issuer_id

    def generate_claim(self, enforcement_event: Dict[str, Any], subject: str = "agent-fleet") -> TraceClaim:
        # Ensure timestamp is a float, not datetime
        timestamp = enforcement_event.get('timestamp')
        if isinstance(timestamp, (datetime, date)):
            timestamp = timestamp.timestamp()
        elif timestamp is None:
            timestamp = time.time()

        return TraceClaim(
            claim_id=f"sentinel-{int(time.time())}-{enforcement_event.get('event_id', 'unknown')}",
            timestamp=timestamp,
            issuer=self.issuer_id,
            subject=subject,
            event_type=enforcement_event.get("event_type", "enforcement"),
            payload=self._serialize_payload(enforcement_event)
        )

    def _serialize_payload(self, payload: Any) -> Any:
        """Recursively convert datetime objects in payload to ISO strings."""
        if isinstance(payload, dict):
            return {k: self._serialize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self._serialize_payload(v) for v in payload]
        elif isinstance(payload, (datetime, date)):
            return payload.isoformat()
        else:
            return payload


# Convenience function for backward compatibility
def generate_trace_claim(event: Dict[str, Any]) -> str:
    """Generate a JSON string from a TraceClaim."""
    gen = TraceClaimGenerator()
    # Convert any datetime objects in the event to ISO strings
    serialized_event = gen._serialize_payload(event)
    claim = gen.generate_claim(serialized_event)
    return claim.to_json()