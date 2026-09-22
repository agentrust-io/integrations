"""Regenerate the committed action receipt fixture, byte for byte.

Keys are Ed25519 seeds derived from published labels, so the fixture is
deterministic and carries no secret material: anyone can regenerate the
private keys from this file. The receipt is test evidence for the verifier
in ``aps_action_receipt.py``. It proves nothing about any real agent.

What this mints, and why each piece is what it is. The receipt is an
``aps:action-intent:v1``, which draft-pidlisnyi-aps-03 section 5.3.1
constrains beyond the ReceiptV1 envelope: the issuer is the acting agent
itself, there is no ``prev`` and no ``decision_ref``, and ``result`` is
exactly ``{profile: aps-action-intent-result-v1, status: declared}``. The
receipt is signed by the agent key, not a gateway key.

``delegation_ref`` names a real root ``AuthorityDelegationV1`` minted below
and carries its ``delegation_id`` verbatim, including the ``sha256:``
prefix that identifier already has. ``action_ref`` is the draft-native
section 4.1 reference computed with ``compute_action_ref_v2`` over the
exact eight member input object, and is bare lowercase hex with no prefix.
The pre-draft ``compute_action_ref`` is a different primitive over a
different preimage and is deliberately not used here.

The delegation nonce is supplied rather than generated. The Python SDK
documents that a caller-supplied nonce is kept unchanged, which is what
keeps this fixture byte reproducible.

Run from the integration directory:

    python fixtures/action-receipt/generate.py

Then ``git diff`` should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import (
    compute_action_ref_v2,
    compute_payload_ref_v1,
    create_action_reference_input_v2,
    issue_authority_delegation,
)
from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import create_receipt_v1

HERE = Path(__file__).resolve().parent

PRINCIPAL = "did:aps:example:principal-01"
PRINCIPAL_VERIFICATION_METHOD = PRINCIPAL + "#key-1"
AGENT = "did:aps:example:agent-01"
AGENT_KEY_ID = "agent-01-key-2026-09"

DELEGATION_ISSUED_AT = "2026-09-18T11:00:00.000Z"
ACTION_ISSUED_AT = "2026-09-18T11:59:58.000Z"
RECEIPT_ISSUED_AT = "2026-09-18T12:00:00.000Z"

SCOPE = "calendar:write"
ACTION_TYPE = "calendar.event.create"
TARGET = "https://calendar.example.com/calendars/primary"

#: The application payload the action commits to. Its digest enters the
#: action reference through compute_payload_ref_v1, which is domain
#: separated, so a bare sha256 over these bytes is not the same value.
PAYLOAD = {
    "title": "Weekly sync",
    "start": "2026-09-18T13:00:00.000Z",
    "end": "2026-09-18T13:30:00.000Z",
}


def _seed(label: str) -> str:
    return hashlib.sha256(f"aeoess-aps-integration:action-receipt-fixture:{label}".encode()).hexdigest()


def _delegation_body(nonce: str) -> dict:
    return {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "parent_delegation_id": None,
        "issuer": PRINCIPAL,
        "subject": AGENT,
        "verification_method": PRINCIPAL_VERIFICATION_METHOD,
        "issued_at": DELEGATION_ISSUED_AT,
        "nonce": nonce,
        "authority": {
            "scope": {"profile": "aps-hierarchical-v1", "grants": [SCOPE]},
            "spend": {"mode": "unbounded"},
            "depth": {"remaining": 1},
            "time": {
                "not_before": "2026-09-18T00:00:00.000Z",
                "not_after": "2026-09-19T00:00:00.000Z",
            },
            "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
            "values": {"profile": "aps-values-identifiers-v1", "required": []},
            "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
        },
    }


def main() -> None:
    principal_private = _seed("principal:v1")
    principal_public = public_key_from_private(principal_private)
    agent_private = _seed("agent:v1")
    agent_public = public_key_from_private(agent_private)
    other_public = public_key_from_private(_seed("unrelated:v1"))

    delegation = issue_authority_delegation(
        _delegation_body(_seed("delegation-nonce:v1")[:32]), principal_private
    )

    action = create_action_reference_input_v2(
        agent_id=AGENT,
        action_type=ACTION_TYPE,
        target=TARGET,
        payload_ref=compute_payload_ref_v1(PAYLOAD),
        scope_required=[SCOPE],
        issued_at=ACTION_ISSUED_AT,
        nonce=_seed("action-nonce:v1")[:32],
    )

    fields = {
        "profile": "aps-receipt-v1",
        "receipt_type": "aps:action-intent:v1",
        "issuer": AGENT,
        "subject_agent": AGENT,
        "action_ref": compute_action_ref_v2(action),
        "delegation_ref": delegation["delegation_id"],
        "issued_at": RECEIPT_ISSUED_AT,
        "evidence_refs": [],
        "result": {"profile": "aps-action-intent-result-v1", "status": "declared"},
    }
    receipt = create_receipt_v1(
        fields, [{"signer": AGENT, "key_id": AGENT_KEY_ID, "private_key": agent_private}]
    )

    keys = {
        "note": "Public keys only. Seeds are sha256 over the labels in generate.py, so the material is public by construction.",
        "pinned": {AGENT: {AGENT_KEY_ID: agent_public}},
        "delegation_verification_key": {PRINCIPAL_VERIFICATION_METHOD: principal_public},
        "unrelated_public_key": other_public,
    }
    meta = {
        "reference_time": "2026-09-18T12:05:00Z",
        "max_age_seconds": 600,
        "expected_subject_agent": AGENT,
        "expected_delegation_ref": delegation["delegation_id"],
        "generated_by": "fixtures/action-receipt/generate.py",
        "sdk": "agent-passport-system 4.0.0",
    }
    for name, value in (
        ("receipt.json", receipt),
        ("delegation.json", delegation),
        ("action.json", action),
        ("payload.json", PAYLOAD),
        ("keys.json", keys),
        ("meta.json", meta),
    ):
        (HERE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
