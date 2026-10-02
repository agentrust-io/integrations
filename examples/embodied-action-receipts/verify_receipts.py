"""Offline verifier for embodied-action receipt fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).parent
MALFORMED = {"result": "invalid", "receipt_state": "malformed"}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


@dataclass(frozen=True)
class TrustedSigner:
    issuer: str
    public_key: Ed25519PublicKey


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64url_decode(value: str) -> bytes:
    """Strict unpadded base64url: one accepted spelling per byte string."""
    if not isinstance(value, str) or _B64URL.fullmatch(value) is None:
        raise ValueError("not unpadded base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("non-canonical base64url")
    return decoded


def sha256_ref(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def action_preimage(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": action["agent_id"],
        "action_type": action["action_type"],
        "action_scope": action["action_scope"],
        "action_timestamp": action["action_timestamp"],
    }


def receipt_preimage(receipt: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in receipt.items() if k != "signature"}


def receipt_hash(receipt: dict[str, Any]) -> str:
    return sha256_ref(receipt)


def load_trusted_keys(path: Path = ROOT / "trusted-keys.json") -> dict[str, TrustedSigner]:
    data = json.loads(path.read_text())
    keys = {}
    for key_id, key in data["controller_signers"].items():
        keys[key_id] = TrustedSigner(
            issuer=key["issuer"],
            public_key=Ed25519PublicKey.from_public_bytes(
                b64url_decode(key["public_key_b64url"])
            ),
        )
    return keys


def verify_fixture(
    path: Path, trusted_keys: dict[str, TrustedSigner] | None = None
) -> dict[str, Any]:
    if trusted_keys is None:
        trusted_keys = load_trusted_keys()
    return verify_text(path.read_text(), trusted_keys)


def verify_text(text: str, trusted_keys: dict[str, TrustedSigner]) -> dict[str, Any]:
    """Verify fixture JSON. Always returns a verdict; never raises on bad input."""
    try:
        return verify_document(json.loads(text), trusted_keys)
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError):
        # The fixture is untrusted input: a wrong shape is a verdict, not a crash.
        return dict(MALFORMED)


def verify_document(
    fixture: dict[str, Any], trusted_keys: dict[str, TrustedSigner]
) -> dict[str, Any]:
    trace = fixture["trace"]
    action = fixture["action"]
    receipts = fixture.get("receipts", [])
    expected_required = trace.get("verification", {}).get("action_receipts") == "required"

    recomputed_action_ref = sha256_ref(action_preimage(action))
    if recomputed_action_ref != action.get("action_ref"):
        return {"result": "invalid", "receipt_state": "action_ref_mismatch"}

    if expected_required and not receipts:
        return {"result": "invalid", "receipt_state": "missing"}

    previous_hash = None
    final_state = "absent"
    final_verdict = None

    for expected_sequence, receipt in enumerate(
        sorted(receipts, key=lambda r: r["sequence"]), start=1
    ):
        if receipt["sequence"] != expected_sequence:
            return {"result": "invalid", "receipt_state": "sequence_mismatch"}
        if receipt["call_id"] != trace["cmcp_call_id"]:
            return {"result": "invalid", "receipt_state": "call_id_mismatch"}
        if receipt["trace_id"] != trace["trace_id"]:
            return {"result": "invalid", "receipt_state": "trace_id_mismatch"}
        if receipt["action_ref"] != action["action_ref"]:
            return {"result": "invalid", "receipt_state": "action_ref_mismatch"}
        if receipt.get("prev_receipt_hash") != previous_hash:
            return {"result": "invalid", "receipt_state": "chain_mismatch"}

        signer = trusted_keys.get(receipt["issuer_key_id"])
        if signer is None:
            return {"result": "invalid", "receipt_state": "untrusted"}
        if receipt.get("issuer") != signer.issuer:
            return {"result": "invalid", "receipt_state": "issuer_mismatch"}

        signature = receipt["signature"]
        if not signature.startswith("ed25519:"):
            return {"result": "invalid", "receipt_state": "signature_format"}

        try:
            signature_bytes = b64url_decode(signature.removeprefix("ed25519:"))
        except ValueError:
            return {"result": "invalid", "receipt_state": "signature_format"}
        try:
            signer.public_key.verify(
                signature_bytes,
                canonical_bytes(receipt_preimage(receipt)),
            )
        except InvalidSignature:
            return {"result": "invalid", "receipt_state": "invalid_signature"}

        previous_hash = receipt_hash(receipt)
        final_verdict = receipt["verdict"]
        final_state = receipt["terminal_state"]

    if final_verdict == "rejected" or final_state.endswith("rejected"):
        return {"result": "valid", "receipt_state": "rejected"}
    if final_verdict == "accepted":
        return {"result": "valid", "receipt_state": "accepted"}
    return {"result": "valid", "receipt_state": final_state}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python verify_receipts.py <fixture.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    result = verify_fixture(path)
    print(json.dumps(result, indent=2, sort_keys=True))

    expected = json.loads(path.read_text()).get("expected")
    if expected and result != expected:
        print(f"expected {expected}, got {result}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

