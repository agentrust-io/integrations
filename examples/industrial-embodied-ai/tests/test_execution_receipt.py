from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

from controller import IndependentSafetyController  # noqa: E402
from server import mock_robot_controller  # noqa: E402


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_like_cmcp(
    receipt: dict,
    external_evidence_keys: dict[str, bytes],
    call_id: str,
) -> None:
    """Reproduce cmcp_verify's external_execution_evidence check: the
    trusted key-id map, linked_call_id binding, and Ed25519 signature over the
    canonical receipt with the signature field absent. Raises on verification
    failure.
    """
    if receipt["linked_call_id"] != call_id:
        raise AssertionError("linked_call_id does not match the entry call_id")
    key_id = receipt["issuer_key_id"]
    public_key = external_evidence_keys[key_id]
    if hashlib.sha256(public_key).hexdigest() != key_id:
        raise AssertionError("issuer_key_id does not match trusted public key")
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    signing_input = json.dumps(
        {k: v for k, v in receipt.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    pub.verify(_b64url_decode(receipt["signature"]), signing_input)


class ExecutionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = IndependentSafetyController(
            token_key=b"unit-test-only-controller-key"
        )

    def test_receipt_has_required_fields(self) -> None:
        receipt = self.controller.sign_execution_receipt(
            call_id="c1",
            decision={"controller_decision": "rejected", "reason": "human_detected"},
        )
        for field in (
            "issuer",
            "issuer_key_id",
            "signature",
            "evidence_hash",
            "evidence_type",
            "linked_call_id",
        ):
            self.assertIn(field, receipt)
        self.assertTrue(receipt["evidence_hash"].startswith("sha256:"))
        self.assertEqual(receipt["evidence_type"], "controller-execution-receipt/v1")
        self.assertEqual(
            receipt["issuer_key_id"],
            hashlib.sha256(self.controller.receipt_public_key_bytes).hexdigest(),
        )

    def test_receipt_verifies_like_cmcp(self) -> None:
        receipt = self.controller.sign_execution_receipt(
            call_id="c1",
            decision={"controller_decision": "rejected", "reason": "human_detected"},
        )
        # Should not raise.
        _verify_like_cmcp(
            receipt,
            {self.controller.receipt_key_id: self.controller.receipt_public_key_bytes},
            "c1",
        )

    def test_tampered_receipt_fails(self) -> None:
        receipt = self.controller.sign_execution_receipt(
            call_id="c1", decision={"controller_decision": "rejected"}
        )
        receipt["evidence_hash"] = "sha256:" + "cd" * 32  # tamper after signing
        with self.assertRaises(InvalidSignature):
            _verify_like_cmcp(
                receipt,
                {
                    self.controller.receipt_key_id: (
                        self.controller.receipt_public_key_bytes
                    )
                },
                "c1",
            )

    def test_linked_call_id_is_bound(self) -> None:
        receipt = self.controller.sign_execution_receipt(
            call_id="c1", decision={"controller_decision": "rejected"}
        )
        with self.assertRaises(AssertionError):
            _verify_like_cmcp(
                receipt,
                {
                    self.controller.receipt_key_id: (
                        self.controller.receipt_public_key_bytes
                    )
                },
                "other",
            )

    def test_receipt_key_is_deterministic(self) -> None:
        # Fixed dev seed: the receipt key id is reproducible across instances,
        # so committed evidence stays stable.
        other = IndependentSafetyController(token_key=b"different-token-key")
        self.assertEqual(self.controller.receipt_key_id, other.receipt_key_id)
        self.assertEqual(
            self.controller.receipt_public_key_b64,
            "eOBimyX_-wLLvWhQ3Jl2KnRULU8ZU-vK0z7eAn2gNoo",
        )

    def test_mock_server_attaches_receipt_to_motion_decision(self) -> None:
        result = mock_robot_controller._with_execution_receipt(
            {"controller_decision": "rejected", "reason": "human_detected"},
            "call-42",
        )
        receipt = result["external_execution_evidence"]
        self.assertEqual(receipt["linked_call_id"], "call-42")
        _verify_like_cmcp(
            receipt,
            {
                mock_robot_controller.controller.receipt_key_id: (
                    mock_robot_controller.controller.receipt_public_key_bytes
                )
            },
            "call-42",
        )


if __name__ == "__main__":
    unittest.main()
