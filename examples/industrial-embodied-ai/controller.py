"""Independent mock safety controller for the industrial example.

This module models a controller boundary. It does not implement a safety
function, control physical hardware, or claim compliance with robot standards.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


CONTROLLER_ID = "spiffe://factory.example/controller/robot-cell-7"
MAX_STATE_AGE_MS = 5_000
MAX_SPEED_MPS = 0.5
ALLOWED_TARGETS = frozenset({"buffer-zone-1", "transfer-station-b"})


class SafetyRejected(RuntimeError):
    """The independent controller rejected physical execution."""


def canonical_bytes(value: Any) -> bytes:
    """Return stable JSON bytes for hashing and signing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def sha256_b64url(value: Any) -> str:
    """Return a base64url-encoded SHA-256 digest."""
    return _b64url_encode(hashlib.sha256(canonical_bytes(value)).digest())


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class IndependentSafetyController:
    """Mock controller that remains authoritative for simulated motion."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        token_key: bytes | None = None,
    ) -> None:
        self._clock = clock
        self._token_key = token_key or secrets.token_bytes(32)
        self._sequence = 0
        self._consumed_sequences: set[int] = set()
        # #301: deterministic development-only Ed25519 key the controller uses to
        # sign execution receipts (external_execution_evidence). Fixed seed so the
        # public key and any committed evidence are reproducible. Not for production.
        self._receipt_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"development-only-mock-controller-receipt-key").digest()
        )
        self._receipt_pub = self._receipt_key.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        self._state = {
            "operating_mode": "automatic",
            "emergency_stop_active": False,
            "protective_stop_active": False,
            "human_detected": False,
        }

    def set_state(self, **changes: Any) -> None:
        unknown = set(changes) - set(self._state)
        if unknown:
            raise ValueError(f"Unknown controller state fields: {sorted(unknown)}")
        self._state.update(changes)

    def read_safety_state(self) -> dict[str, Any]:
        self._sequence += 1
        snapshot = {
            "controller_id": CONTROLLER_ID,
            "sequence": self._sequence,
            "observed_at_ms": int(self._clock() * 1000),
            **self._state,
        }
        payload = canonical_bytes(snapshot)
        signature = hmac.new(self._token_key, payload, hashlib.sha256).digest()
        return {
            **snapshot,
            "state_token": f"{_b64url_encode(payload)}.{_b64url_encode(signature)}",
        }

    def _verify_state_token(self, token: str) -> dict[str, Any]:
        try:
            payload_b64, signature_b64 = token.split(".", maxsplit=1)
            payload = _b64url_decode(payload_b64)
            signature = _b64url_decode(signature_b64)
            expected = hmac.new(self._token_key, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise SafetyRejected("invalid_safety_state_token")
            snapshot = json.loads(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            raise SafetyRejected("malformed_safety_state_token") from exc

        try:
            age_ms = int(self._clock() * 1000) - int(snapshot["observed_at_ms"])
            sequence = int(snapshot["sequence"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SafetyRejected("malformed_safety_state_token") from exc

        if age_ms < 0 or age_ms > MAX_STATE_AGE_MS:
            raise SafetyRejected("stale_safety_state")
        if snapshot.get("controller_id") != CONTROLLER_ID:
            raise SafetyRejected("unexpected_controller_identity")
        if sequence in self._consumed_sequences:
            raise SafetyRejected("replayed_safety_state")

        self._consumed_sequences.add(sequence)
        return snapshot

    def request_motion(self, request: dict[str, Any]) -> dict[str, Any]:
        self._verify_state_token(str(request.get("safety_state_token", "")))

        # The request token is evidence of a recent observation, not permission
        # to move. The controller rechecks its authoritative current state.
        if self._state["emergency_stop_active"]:
            raise SafetyRejected("emergency_stop_active")
        if self._state["protective_stop_active"]:
            raise SafetyRejected("protective_stop_active")
        if self._state["human_detected"]:
            raise SafetyRejected("human_detected")
        if self._state["operating_mode"] != "automatic":
            raise SafetyRejected("controller_not_in_automatic_mode")

        motion_id = request.get("motion_id")
        target = request.get("target")
        try:
            speed = float(request["max_speed_mps"])
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise SafetyRejected("invalid_motion_request") from exc

        if not isinstance(motion_id, str) or not motion_id:
            raise SafetyRejected("invalid_motion_request")
        if not isinstance(target, str) or target not in ALLOWED_TARGETS:
            raise SafetyRejected("target_outside_approved_zone")
        # NaN fails both comparisons, so it must be refused explicitly.
        if not math.isfinite(speed) or speed < 0 or speed > MAX_SPEED_MPS:
            raise SafetyRejected("speed_exceeds_controller_limit")

        request_for_hash = {
            key: value
            for key, value in request.items()
            if key != "safety_state_token"
        }
        return {
            "controller_id": CONTROLLER_ID,
            "motion_id": motion_id,
            "request_digest": sha256_b64url(request_for_hash),
            "controller_decision": "accepted",
            "execution_status": "completed",
        }

    @property
    def receipt_key_id(self) -> str:
        """Stable id for the receipt-signing public key (sha256 hex of the key)."""
        return hashlib.sha256(self._receipt_pub).hexdigest()

    @property
    def receipt_public_key_b64(self) -> str:
        """base64url of the raw Ed25519 receipt-signing public key."""
        return _b64url_encode(self._receipt_pub)

    @property
    def receipt_public_key_bytes(self) -> bytes:
        """Raw Ed25519 receipt-signing public key bytes for cMCP verification."""
        return self._receipt_pub

    def sign_execution_receipt(
        self, *, call_id: str, decision: dict[str, Any]
    ) -> dict[str, str]:
        """Return a controller-signed execution receipt for a decision.

        Matches the cMCP external_execution_evidence format (issue #301): the
        signature is Ed25519 over the canonical receipt with the signature field
        absent, and a verifier checks linked_call_id against the audit entry
        call_id. This attests what the independent controller decided. It is not
        a claim that a physical action was safe, accepted, or certified.
        """
        receipt = {
            "issuer": CONTROLLER_ID,
            "issuer_key_id": self.receipt_key_id,
            "evidence_hash": (
                "sha256:"
                + hashlib.sha256(canonical_bytes(decision)).hexdigest()
            ),
            "evidence_type": "controller-execution-receipt/v1",
            "linked_call_id": call_id,
        }
        receipt["signature"] = _b64url_encode(
            self._receipt_key.sign(canonical_bytes(receipt))
        )
        return receipt
