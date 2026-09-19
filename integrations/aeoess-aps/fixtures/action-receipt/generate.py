"""Regenerate the committed action receipt fixture, byte for byte.

Keys are Ed25519 seeds derived from published labels, so the fixture is
deterministic and carries no secret material: anyone can regenerate the
private keys from this file. The receipt is test evidence for the verifier
in ``aps_action_receipt.py``. It proves nothing about any real agent.

Run from the integration directory:

    python fixtures/action-receipt/generate.py

Then ``git diff`` should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import compute_action_ref
from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import create_receipt_v1

HERE = Path(__file__).resolve().parent

ISSUER = "did:aps:example:gateway-01"
ISSUER_KEY_ID = "gateway-01-key-2026-09"
SUBJECT_AGENT = "did:aps:example:agent-01"
DELEGATION_REF = hashlib.sha256(b"aeoess-aps-integration:action-receipt-fixture:delegation:v1").hexdigest()
ISSUED_AT = "2026-09-18T12:00:00.000Z"

#: Canonical action preimage per draft-pidlisnyi-aps section 4.1, as the
#: verifier expects it (``agent_id``, ``action_type``, ``scope_required``,
#: ``timestamp``). The receipt's ``action_ref`` is computed over exactly this.
ACTION = {
    "agent_id": SUBJECT_AGENT,
    "action_type": "calendar.event.create",
    "scope_required": ["calendar:write"],
    "timestamp": "2026-09-18T11:59:58Z",
}


def _seed(label: str) -> str:
    return hashlib.sha256(f"aeoess-aps-integration:action-receipt-fixture:{label}".encode()).hexdigest()


def main() -> None:
    issuer_private = _seed("issuer:v1")
    issuer_public = public_key_from_private(issuer_private)
    other_public = public_key_from_private(_seed("unrelated:v1"))

    action_ref = compute_action_ref(**ACTION)
    fields = {
        "profile": "aps-receipt-v1",
        "receipt_type": "aps:action-intent:v1",
        "issuer": ISSUER,
        "subject_agent": SUBJECT_AGENT,
        "action_ref": action_ref,
        "delegation_ref": DELEGATION_REF,
        "issued_at": ISSUED_AT,
        "evidence_refs": [],
        "result": {"intent_id": "itn-fixture-0001", "description": "create one calendar event"},
    }
    receipt = create_receipt_v1(fields, [{"signer": ISSUER, "key_id": ISSUER_KEY_ID, "private_key": issuer_private}])

    keys = {
        "note": "Public keys only. Seeds are sha256 over the labels in generate.py, so the material is public by construction.",
        "pinned": {ISSUER: {ISSUER_KEY_ID: issuer_public}},
        "unrelated_public_key": other_public,
    }
    meta = {
        "reference_time": "2026-09-18T12:05:00Z",
        "max_age_seconds": 600,
        "expected_subject_agent": SUBJECT_AGENT,
        "expected_delegation_ref": DELEGATION_REF,
        "generated_by": "fixtures/action-receipt/generate.py",
        "sdk": "agent-passport-system 3.0.1",
    }
    for name, value in (("receipt.json", receipt), ("action.json", ACTION), ("keys.json", keys), ("meta.json", meta)):
        (HERE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
