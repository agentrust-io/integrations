"""Verify the proposed OpenShell bundle contract; no live producer is assumed."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "agentrust.openshell-evidence-candidate.v1"
_FILES = {"effective-policy.yaml", "events.ocsf.jsonl"}
_LIMIT = 2**53 - 1


class BundleError(ValueError):
    """Malformed, unauthenticated, substituted or corrupted bundle."""


@dataclass(frozen=True)
class BundleVerification:
    """Coverage is limited to the producer's signed sequence range."""

    coverage: Literal["verified_complete_over_range", "provable_gap", "not_established"]
    reason: str
    sandbox_id: str
    event_count: int
    signature_verified: bool = True
    file_integrity_verified: bool = True


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BundleError("duplicate JSON key")
        value[key] = item
    return value


def _json(raw: bytes) -> dict:
    def reject_constant(value):
        raise BundleError("non-finite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=reject_constant,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BundleError("invalid JSON object") from exc
    if not isinstance(value, dict):
        raise BundleError("JSON object required")
    return value


def _integer(value):
    if type(value) is not int or not 0 <= value <= _LIMIT:
        raise BundleError("nonnegative safe integer required")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise BundleError("nonempty text required")
    return value


def verify_bundle(
    manifest_bytes: bytes,
    signature_bytes: bytes,
    files: Mapping[str, bytes],
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    expected_sandbox_id: str,
    expected_capture_start: int,
    expected_capture_end: int,
) -> BundleVerification:
    """Check exact bytes using caller-pinned keys, sandbox and interval.

    No key, file path or network location supplied by the bundle is trusted.
    Invalid authentication/integrity raises BundleError, never a coverage pass.
    """
    if not isinstance(manifest_bytes, bytes) or not isinstance(signature_bytes, bytes):
        raise BundleError("immutable input bytes required")
    # Snapshot caller-owned mappings before hashing and parsing the same bytes.
    files = dict(files)
    signature = _json(signature_bytes)
    if set(signature) != {"algorithm", "key_id", "signature"}:
        raise BundleError("invalid detached signature fields")
    if signature["algorithm"] != "Ed25519":
        raise BundleError("unsupported signature algorithm")
    key_id = _text(signature["key_id"])
    key = trusted_keys.get(key_id)
    if not isinstance(key, Ed25519PublicKey):
        raise BundleError("untrusted gateway key")
    try:
        encoded = _text(signature["signature"])
        signed = base64.b64decode(encoded, validate=True)
        key.verify(signed, manifest_bytes)
    except (ValueError, InvalidSignature) as exc:
        raise BundleError("invalid gateway signature") from exc

    manifest = _json(manifest_bytes)
    fields = {
        "format",
        "sandbox_id",
        "openshell_version",
        "policy_revision",
        "capture_start",
        "capture_end",
        "complete",
        "incomplete_reason",
        "event_count",
        "sequence",
        "files",
    }
    if set(manifest) != fields or manifest["format"] != FORMAT:
        raise BundleError("unsupported candidate manifest")
    sandbox_id = _text(manifest["sandbox_id"])
    if sandbox_id != _text(expected_sandbox_id):
        raise BundleError("unexpected sandbox")
    version = _text(manifest["openshell_version"])
    _text(manifest["policy_revision"])
    start, end = _integer(manifest["capture_start"]), _integer(manifest["capture_end"])
    if start > end or (start, end) != (
        _integer(expected_capture_start),
        _integer(expected_capture_end),
    ):
        raise BundleError("unexpected capture interval")
    if type(manifest["complete"]) is not bool:
        raise BundleError("complete must be boolean")
    if manifest["complete"]:
        if manifest["incomplete_reason"] is not None:
            raise BundleError("complete export has an incomplete reason")
    else:
        _text(manifest["incomplete_reason"])
    expected_count = _integer(manifest["event_count"])
    digests = manifest["files"]
    if not isinstance(digests, dict) or set(digests) != _FILES or set(files) != _FILES:
        raise BundleError("exact candidate file set required")
    for name in _FILES:
        raw = files[name]
        if not isinstance(raw, bytes):
            raise BundleError("immutable file bytes required")
        if digests[name] != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise BundleError("file digest mismatch")
    if not files["effective-policy.yaml"]:
        raise BundleError("empty effective policy")

    bounds = manifest["sequence"]
    if bounds is not None:
        if not isinstance(bounds, dict) or set(bounds) != {"epoch", "first", "last"}:
            raise BundleError("invalid sequence bounds")
        _text(bounds["epoch"])
        first, last = _integer(bounds["first"]), _integer(bounds["last"])
        if first > last:
            raise BundleError("reversed sequence bounds")

    sequences = []
    missing_sequence = False
    for line in files["events.ocsf.jsonl"].splitlines():
        event = _json(line)
        metadata = event.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("uid") != sandbox_id:
            raise BundleError("event sandbox mismatch")
        product = metadata.get("product")
        if not isinstance(product, dict) or product.get("version") != version:
            raise BundleError("event product version mismatch")
        if not start <= _integer(event.get("time")) <= end:
            raise BundleError("event outside capture interval")
        seq = metadata.get("sequence")
        if seq is None:
            missing_sequence = True
        else:
            seq = _integer(seq)
            if bounds is not None and not first <= seq <= last:
                raise BundleError("event outside sequence bounds")
            sequences.append(seq)
    count = len(files["events.ocsf.jsonl"].splitlines())
    if count != expected_count:
        raise BundleError("event count mismatch")
    if len(sequences) != len(set(sequences)) or sequences != sorted(sequences):
        raise BundleError("duplicate or unordered sequence")
    if not count or bounds is None or missing_sequence:
        coverage, reason = "not_established", "empty_or_unbounded_or_unsequenced"
    elif len(sequences) != last - first + 1:
        coverage, reason = "provable_gap", "missing_sequence_in_signed_range"
    elif not manifest["complete"]:
        coverage, reason = "not_established", "producer_reported_incomplete"
    else:
        coverage, reason = "verified_complete_over_range", "signed_range_contiguous"
    return BundleVerification(coverage, reason, sandbox_id, count)
