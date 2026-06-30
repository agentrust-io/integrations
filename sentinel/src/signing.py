"""Keyed signing for Sentinel incident reports.

Incident reports are signed with HMAC-SHA256 using a secret loaded from the
``SENTINEL_SIGNING_KEY`` environment variable. Signing and verification both
FAIL CLOSED when the key is unset: ``sign_payload`` raises and ``verify_payload``
returns ``False`` rather than emitting or accepting a value that merely looks
signed.
"""

import hashlib
import hmac
import json
import os
from typing import Any, Dict

SIGNING_KEY_ENV = "SENTINEL_SIGNING_KEY"


class SigningKeyMissing(RuntimeError):
    """Raised when an incident must be signed but no signing key is configured."""


def _signing_key() -> bytes:
    key = os.environ.get(SIGNING_KEY_ENV)
    if not key:
        raise SigningKeyMissing(
            f"{SIGNING_KEY_ENV} is not set. Refusing to emit an incident "
            "signature without a secret key (fail closed). Set "
            f"{SIGNING_KEY_ENV} to a high-entropy secret to enable signing."
        )
    return key.encode("utf-8")


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def is_signing_configured() -> bool:
    """Return True if a signing key is configured."""
    return bool(os.environ.get(SIGNING_KEY_ENV))


def sign_payload(payload: Dict[str, Any]) -> str:
    """Return a hex HMAC-SHA256 signature over the canonical JSON of *payload*.

    Raises ``SigningKeyMissing`` if no signing key is configured.
    """
    return hmac.new(_signing_key(), _canonical_bytes(payload), hashlib.sha256).hexdigest()


def verify_payload(payload: Dict[str, Any], signature: str) -> bool:
    """Return True iff *signature* is a valid HMAC for *payload* under the key.

    Fails closed: returns False if no key is configured or *signature* is empty.
    Uses a constant-time comparison.
    """
    if not signature or not is_signing_configured():
        return False
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)
