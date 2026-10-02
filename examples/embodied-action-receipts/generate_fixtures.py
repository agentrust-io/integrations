"""Generate deterministic embodied-action receipt fixtures."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verify_receipts import action_preimage, canonical_bytes, receipt_hash, sha256_ref


ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"

SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
KEY_ID = "robot-cell-7-controller"
ISSUER = "spiffe://factory.example/controller/robot-cell-7"
TRACE_ID = "trace-session-embodied-001"
CALL_ID = "call-material-move-001"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


PUBLIC_KEY_B64URL = b64url(KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
))


def sign(receipt: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(receipt)
    signature = KEY.sign(canonical_bytes(signed))
    signed["signature"] = "ed25519:" + b64url(signature)
    return signed


def base_trace() -> dict[str, Any]:
    return {
        "trace_id": TRACE_ID,
        "cmcp_call_id": CALL_ID,
        "policy_decision": "allow",
        "verification": {"action_receipts": "required"},
    }


def base_action() -> dict[str, Any]:
    action = {
        "agent_id": "spiffe://factory.example/agent/material-movement/dev",
        "action_type": "move_material",
        "action_scope": "robot-cell-7/material-bin-a",
        "action_timestamp": "2026-06-25T16:30:00Z",
    }
    action["action_ref"] = sha256_ref(action_preimage(action))
    return action


def receipt(sequence: int, action: dict[str, Any], terminal_state: str, verdict: str,
            previous_hash: str | None, observed_at: str) -> dict[str, Any]:
    return {
        "type": "embodied.action_receipt.v0",
        "receipt_id": f"receipt-{sequence:03d}",
        "issuer": ISSUER,
        "issuer_key_id": KEY_ID,
        "trace_id": TRACE_ID,
        "call_id": CALL_ID,
        "action_ref": action["action_ref"],
        "sequence": sequence,
        "prev_receipt_hash": previous_hash,
        "verdict": verdict,
        "terminal_state": terminal_state,
        "observed_at": observed_at,
    }


def valid_chain() -> dict[str, Any]:
    action = base_action()
    first = sign(receipt(
        1, action, "handoff_accepted", "accepted", None, "2026-06-25T16:30:01Z",
    ))
    second = sign(receipt(
        2, action, "controller_completed", "accepted", receipt_hash(first),
        "2026-06-25T16:30:05Z",
    ))
    return {
        "case": "valid-chain",
        "trace": base_trace(),
        "action": action,
        "receipts": [first, second],
        "expected": {"result": "valid", "receipt_state": "accepted"},
    }


def missing_receipt() -> dict[str, Any]:
    return {
        "case": "missing-receipt",
        "trace": base_trace(),
        "action": base_action(),
        "receipts": [],
        "expected": {"result": "invalid", "receipt_state": "missing"},
    }


def signature_mismatch() -> dict[str, Any]:
    fixture = valid_chain()
    fixture["case"] = "signature-mismatch"
    fixture["receipts"][0]["signature"] = fixture["receipts"][0]["signature"][:-1] + "A"
    fixture["expected"] = {"result": "invalid", "receipt_state": "invalid_signature"}
    return fixture


def controller_rejected() -> dict[str, Any]:
    action = base_action()
    rejection = sign(receipt(
        1, action, "controller_rejected", "rejected", None, "2026-06-25T16:30:02Z",
    ))
    rejection["reason"] = "human_detected_in_safeguarded_area"
    # The reason is part of the signed receipt, so sign again after adding it.
    rejection.pop("signature")
    rejection = sign(rejection)
    return {
        "case": "controller-rejected",
        "trace": base_trace(),
        "action": action,
        "receipts": [rejection],
        "expected": {"result": "valid", "receipt_state": "rejected"},
        "note": "A valid rejected receipt is evidence of controller rejection, not physical completion.",
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    FIXTURES.mkdir(exist_ok=True)
    write_json(ROOT / "trusted-keys.json", {
        "controller_signers": {
            KEY_ID: {
                "alg": "Ed25519",
                "issuer": ISSUER,
                "public_key_b64url": PUBLIC_KEY_B64URL,
            },
        },
        "note": "Public test verifier key for deterministic fixtures. Never use the signing seed in production.",
    })
    write_json(FIXTURES / "valid-chain.json", valid_chain())
    write_json(FIXTURES / "missing-receipt.json", missing_receipt())
    write_json(FIXTURES / "signature-mismatch.json", signature_mismatch())
    write_json(FIXTURES / "controller-rejected.json", controller_rejected())
    print(f"Wrote fixtures to {FIXTURES}")


if __name__ == "__main__":
    main()

