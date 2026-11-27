"""Write a demo Auditant evidence bundle (format 1.0.0) signed with a throwaway key.

The events are synthetic. The format, the hash chain and the checkpoint signature
follow the bundle that Auditant's ``GET /v1/export`` returns, so the adapter can be
exercised without an Auditant account. The signing key is generated here and thrown
away: this bundle proves nothing about any real deployment.

    python make_demo_bundle.py demo-bundle.json
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

LOG_ID = "demo_org/dev"
GENESIS = "sha256:" + "0" * 64


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _event(n: int, action_type: str, action: str, **extra: object) -> dict:
    event = {
        "schemaVersion": "1.0.0",
        "eventId": f"evt_{n:06d}",
        "ts": f"2026-11-27T10:00:{n:02d}.000Z",
        "logId": LOG_ID,
        "actor": {"kind": "agent", "id": "refund-agent", "version": "0.1.0", "mode": "autonomous"},
        "sessionId": "sess_demo",
        "actionType": action_type,
        "action": action,
        "surface": {"plane": "action", "adapter": "sdk", "modality": "text"},
        "outcome": "ok",
    }
    event.update(extra)
    return event


def build(
    path: Path, models: tuple[tuple[str, str], ...] = (("demo-provider", "demo-model"),)
) -> Path:
    specs: list[tuple[str, str, dict]] = [("lifecycle", "session_start", {})]
    for provider, model in models:
        specs.append(
            (
                "model_call",
                model,
                {
                    "inputHash": _sha(b"prompt"),
                    "outputHash": _sha(b"completion"),
                    "cost": {"currency": "USD", "total": 0.0042, "model": model, "provider": provider},
                },
            )
        )
    specs += [
        ("tool_call", "lookup_order", {"inputHash": _sha(b"order 1042")}),
        (
            "policy_decision",
            "issue_refund",
            {
                "policy": {
                    "decision": "allow",
                    "policyId": "refund-limit",
                    "policyVersion": "1",
                    "engine": "demo",
                    "reasons": ["amount 40 is under the limit 100"],
                }
            },
        ),
        ("tool_call", "issue_refund", {"inputHash": _sha(b"refund 40")}),
        ("lifecycle", "session_end", {}),
    ]
    inputs = [_event(n, t, a, **x) for n, (t, a, x) in enumerate(specs, start=1)]

    events, prev = [], GENESIS
    for seq, item in enumerate(inputs):
        sealed = {**item, "seq": seq, "prevHash": prev}
        sealed["eventHash"] = _sha(rfc8785.dumps(sealed))
        events.append(sealed)
        prev = sealed["eventHash"]

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    key_id = "demo-" + hashlib.sha256(pem.encode()).hexdigest()[:12]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    checkpoint = {
        "origin": f"auditant.dev/{LOG_ID}",
        "treeSize": len(events),
        "headHash": prev,
        "timestamp": now,
    }
    body = "\n".join(
        [checkpoint["origin"], str(len(events)), base64.b64encode(bytes.fromhex(prev[7:])).decode(), ""]
    )
    signature = base64.b64encode(key.sign(body.encode(), ec.ECDSA(hashes.SHA256()))).decode()

    bundle = {
        "bundleVersion": "1.0.0",
        "logId": LOG_ID,
        "from": "2026-11-27T00:00:00.000Z",
        "to": "2026-11-27T23:59:59.999Z",
        "exportedAt": now,
        "events": events,
        "checkpoints": [{"checkpoint": checkpoint, "body": body, "keyId": key_id, "signature": signature}],
        "publicKeys": [{"keyId": key_id, "pem": pem}],
        "readme": "Demo bundle: synthetic events, throwaway signing key.",
    }
    path.write_text(json.dumps(bundle, indent=2) + "\n")
    return path


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "demo-bundle.json")))
