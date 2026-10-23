"""Standalone verifier for ramen-ai V5 Ed25519 receipts."""

from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PRODUCTION_PUBLIC_KEYS: dict[str, str] = {
    "ramen_pk_v1": "MCowBQYDK2VwAyEA8iTL9lJGYn2alGn1yMWVAIqLImTpADb9CqaLhisTuto=",
}
CONFORMANCE_PUBLIC_KEYS: dict[str, str] = {
    "ramen_pk_ephemeral_test": "MCowBQYDK2VwAyEACmDytPXlfjKUMgV5l4w31xHt/G5p30UsNm/AmOI9OaM=",
}
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON object key: {k!r}")
        out[k] = v
    return out


def _no_nonfinite_constant(token: str) -> object:
    raise ValueError(f"non-finite JSON constant is not allowed: {token}")


def verify_v5_receipt(
    receipt: dict,
    original_input: str,
    *,
    extra_keys: dict[str, str] | None = None,
) -> tuple[bool, str | None]:
    """Verify the Ed25519 signature and SHA-256 input binding of a V5 receipt.

    Only production keys are trusted by default. Tests and offline examples must
    explicitly supply their conformance-document public keys via ``extra_keys``.
    """
    try:
        return _verify(receipt, original_input, extra_keys or {})
    except Exception as exc:  # pragma: no cover - unexpected internal error
        return False, f"Unexpected verifier error: {exc}"


def _verify(
    receipt: dict,
    original_input: str,
    extra_keys: dict[str, str],
) -> tuple[bool, str | None]:
    if not isinstance(receipt, dict) or not isinstance(original_input, str):
        return False, "receipt must be a dict and original_input must be a string"
    kid = receipt.get("kid", "")
    signature_b64url = receipt.get("signature", "")
    canonical_payload = receipt.get("canonical_payload", "")
    if (
        not isinstance(kid, str)
        or not isinstance(signature_b64url, str)
        or not isinstance(canonical_payload, str)
    ):
        return False, "kid, signature, and canonical_payload must be strings"

    key_registry = {**PRODUCTION_PUBLIC_KEYS, **extra_keys}
    if kid not in key_registry:
        return False, f"Unknown kid: {kid!r}"

    pub_key = _load_spki_key(key_registry[kid])
    try:
        pub_key.verify(_b64url_decode(signature_b64url), canonical_payload.encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False, "Signature does not verify over canonical_payload"

    try:
        payload = json.loads(
            canonical_payload,
            object_pairs_hook=_unique_object,
            parse_constant=_no_nonfinite_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"canonical_payload is not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return False, "canonical_payload must decode to a JSON object"

    if payload.get("schema_version") != "5.0":
        return False, (
            f"Unexpected schema_version {payload.get('schema_version')!r}; expected '5.0'"
        )

    expected_hash = hashlib.sha256(original_input.encode("utf-8")).hexdigest()
    if payload.get("payload_hash") != expected_hash:
        return False, "payload_hash does not match SHA-256 of the provided input"

    return True, None


def _load_spki_key(spki_b64: str) -> Ed25519PublicKey:
    key = serialization.load_der_public_key(base64.b64decode(spki_b64))
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519PublicKey, got {type(key)}")
    return key


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("signature must be canonical unpadded base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("signature must be canonical 64-byte base64url")
    return raw
