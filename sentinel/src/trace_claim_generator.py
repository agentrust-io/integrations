import json
import time
import hashlib
import base64
from datetime import datetime
from typing import Dict, Any

from src.models import DetectionResult, TraceClaim, DetectionType

def generate_trace_claim(agent_id: str, detection: DetectionResult, decision: str = "ADMIT") -> TraceClaim:
    claim_id = f"sentinel-{int(time.time())}-{hashlib.md5(f'{agent_id}{detection.detection_type}'.encode()).hexdigest()[:8]}"
    claim_payload = {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": int(time.time()),
        "subject": f"spiffe://sentinel.io/agent/{agent_id}",
        "claim_type": "anomaly_detection",
        "detection": {
            "type": detection.detection_type.value,
            "risk_score": detection.risk_score,
            "risk_level": detection.risk_level.value,
            "reason": detection.reason,
            "evidence": detection.evidence
        },
        "timestamp": detection.timestamp.isoformat(),
        "decision": decision
    }
    return TraceClaim(
        claim_id=claim_id,
        agent_id=agent_id,
        detection_type=detection.detection_type,
        risk_score=detection.risk_score,
        evidence=detection.evidence,
        timestamp=detection.timestamp,
        jwt=None,
        json_export=claim_payload,
        decision=decision
    )

def export_trace_claim(claim: TraceClaim, format: str = "json") -> str:
    """Export the trace claim as JSON or JWT format."""
    if format == "json":
        return json.dumps(claim.json_export, indent=2)
    elif format == "jwt":
        return claim.jwt or "JWT not generated (set TRACE_PRIVATE_KEY_PEM)"
    else:
        raise ValueError(f"Unsupported export format: {format}")