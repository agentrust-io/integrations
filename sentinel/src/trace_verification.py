"""Verification gate for incoming TRACE claims.

Sentinel must not score or enforce on trace data it has not authenticated.
This module verifies the Ed25519 signature on a trace against a *configured
trusted key* (never the key embedded in the record itself) before the trace is
allowed downstream.

Behaviour (fail closed):

* The trusted public key is taken from ``TRACE_TRUSTED_JWK`` (a JWK JSON object).
* If the ``agentrust_trace`` package is importable, its ``verify_record`` is
  used; otherwise a minimal Ed25519 check over the canonical JSON is performed.
  Both verify against the configured trusted key, not ``record["cnf"]["jwk"]``.
* Unsigned traces, traces that fail verification, or traces presented with no
  trusted key configured are REJECTED.
* The only way to bypass verification is to set ``SENTINEL_ALLOW_UNVERIFIED=1``,
  which logs a loud warning on every use.
"""

import base64
import json
import logging
import os
from typing import Any, Dict, Optional

TRUSTED_JWK_ENV = "TRACE_TRUSTED_JWK"
ALLOW_UNVERIFIED_ENV = "SENTINEL_ALLOW_UNVERIFIED"

logger = logging.getLogger("sentinel.trace_verification")


class TraceVerificationError(ValueError):
    """Raised when a trace cannot be verified and must be rejected."""


def _allow_unverified() -> bool:
    return os.environ.get(ALLOW_UNVERIFIED_ENV, "").strip() in ("1", "true", "True", "yes")


def _load_trusted_jwk() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(TRUSTED_JWK_ENV)
    if not raw:
        return None
    try:
        jwk = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise TraceVerificationError(
            f"{TRUSTED_JWK_ENV} is set but is not valid JSON: {exc}"
        )
    if not isinstance(jwk, dict) or not jwk.get("x"):
        raise TraceVerificationError(f"{TRUSTED_JWK_ENV} is not a valid OKP/Ed25519 JWK")
    return jwk


def _canonical_bytes(record: Dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _b64url_decode(value: str) -> bytes:
    pad = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + "=" * pad)


def _minimal_verify(record: Dict[str, Any], jwk: Dict[str, Any]) -> None:
    """Minimal Ed25519 verification against an explicit trusted JWK.

    Raises TraceVerificationError on any failure (no signature, bad key, bad sig).
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    sig_b64 = record.get("signature")
    if not sig_b64:
        raise TraceVerificationError("trace has no 'signature' field")
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
        sig = _b64url_decode(sig_b64)
    except Exception as exc:  # malformed key or signature encoding
        raise TraceVerificationError(f"could not decode trusted key or signature: {exc}")
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    try:
        pub.verify(sig, body)
    except InvalidSignature:
        raise TraceVerificationError("trace signature does not verify against trusted key")


def verify_trace(record: Dict[str, Any]) -> None:
    """Verify *record* against the configured trusted key, or raise.

    On success returns None. On any failure (no trusted key, unsigned trace,
    bad signature) raises ``TraceVerificationError`` -- unless the explicit
    ``SENTINEL_ALLOW_UNVERIFIED=1`` opt-out is set, in which case a loud warning
    is logged and verification is skipped.
    """
    if _allow_unverified():
        logger.warning(
            "%s is set: SKIPPING trace verification. Traces are being scored and "
            "enforced WITHOUT authentication. Do NOT use this in production.",
            ALLOW_UNVERIFIED_ENV,
        )
        return

    if not isinstance(record, dict):
        raise TraceVerificationError("trace must be a JSON object to be verified")

    trusted_jwk = _load_trusted_jwk()
    if trusted_jwk is None:
        raise TraceVerificationError(
            f"No trusted key configured. Set {TRUSTED_JWK_ENV} to the trusted "
            f"Ed25519 public JWK, or set {ALLOW_UNVERIFIED_ENV}=1 to bypass "
            "verification (not recommended)."
        )

    try:
        from agentrust_trace import verify_record as _verify_record
    except ImportError:
        _verify_record = None

    if _verify_record is not None:
        try:
            # Verify against the CONFIGURED trusted key, never record["cnf"]["jwk"].
            _verify_record(record, trusted_jwk)
            return
        except Exception as exc:
            raise TraceVerificationError(f"trace verification failed: {exc}")

    _minimal_verify(record, trusted_jwk)
