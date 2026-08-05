"""Map verified ramen-ai V5 receipts to signed TRACE v0.2 Level 0 records.

The V5 receipt contract is authoritative for receipt identity, policy identifiers,
and the exact signed evaluation payload. TRACE claims not present in that contract
(model identity, data classification, policy artifact digest, build provenance,
and appraisal verifier) are required as explicit caller inputs.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

import agentrust_trace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _receipt_verify import verify_v5_receipt

EAT_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
SOFTWARE_MEASUREMENT = "sha256:" + "0" * 64
TRACE_PRIVATE_KEY_ENV = "TRACE_PRIVATE_KEY_PEM"

_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
_PAYLOAD_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MODEL_FIELDS = frozenset({"provider", "model_id", "version", "weights_digest", "aibom_uri"})
_BUILD_FIELDS = frozenset({"slsa_level", "builder", "digest", "provenance_uri"})


def build_trace_record(
    receipt: dict[str, Any],
    *,
    original_input: str,
    iat: int,
    model: dict[str, Any],
    data_class: str,
    policy_bundle_hash: str,
    build_provenance: dict[str, Any],
    appraisal_verifier: str,
    receipt_public_keys: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Verify a V5 receipt, then build and sign a software-only TRACE v0.2 record.

    Evidence that the V5 receipt does not carry must be supplied explicitly;
    this function never derives a policy artifact digest, model identity, or
    build claim from the evaluated input. The optional TRACE tool transcript is
    omitted because a V5 evaluation receipt is not an MCP/A2A transcript.

    The dedicated Ed25519 signing key is loaded from ``TRACE_PRIVATE_KEY_PEM``.
    There is deliberately no ephemeral-key fallback and no use of the ramen-ai
    receipt verification keys. ``receipt_public_keys`` allows explicit trust of
    additional receipt issuers; production verification keys remain the default.
    """
    _validate_receipt(receipt)
    valid, reason = verify_v5_receipt(
        receipt,
        original_input,
        extra_keys=receipt_public_keys,
    )
    if not valid:
        raise ValueError(f"V5 receipt verification failed: {reason}")

    _validate_trace_evidence(
        iat=iat,
        model=model,
        data_class=data_class,
        policy_bundle_hash=policy_bundle_hash,
        build_provenance=build_provenance,
        appraisal_verifier=appraisal_verifier,
    )

    unsigned_record: dict[str, Any] = {
        "eat_profile": EAT_PROFILE,
        "iat": iat,
        "subject": f"spiffe://ramenai.dev/evaluation/{receipt['id']}",
        "model": dict(model),
        "runtime": {
            "platform": "software-only",
            "measurement": SOFTWARE_MEASUREMENT,
        },
        "policy": {
            "bundle_hash": policy_bundle_hash,
            "enforcement_mode": "enforce",
        },
        "data_class": data_class,
        "build_provenance": dict(build_provenance),
        "appraisal": {
            "status": "none",
            "verifier": appraisal_verifier,
            "timestamp": iat,
        },
    }

    return agentrust_trace.sign_record(unsigned_record, _load_trace_signing_key())


def _load_trace_signing_key() -> Ed25519PrivateKey:
    pem = os.environ.get(TRACE_PRIVATE_KEY_ENV)
    if not pem:
        raise RuntimeError(
            f"{TRACE_PRIVATE_KEY_ENV} is required; refusing to generate an ephemeral "
            "TRACE key or reuse a ramen-ai receipt key"
        )

    try:
        key = agentrust_trace.load_key(pem)
    except Exception as exc:
        raise ValueError(f"{TRACE_PRIVATE_KEY_ENV} is not a valid private key: {exc}") from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{TRACE_PRIVATE_KEY_ENV} must contain an Ed25519 private key")
    return key


def _validate_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    required = {"id", "schema_version", "kid", "signature", "canonical_payload"}
    missing = required - receipt.keys()
    if missing:
        raise ValueError(f"Receipt missing required fields: {sorted(missing)}")
    if receipt["schema_version"] != "5.0":
        raise ValueError(
            f"Unsupported schema_version {receipt['schema_version']!r}; expected '5.0'"
        )

    try:
        payload = json.loads(receipt["canonical_payload"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"canonical_payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("canonical_payload must decode to a JSON object")

    payload_required = {
        "schema_version",
        "kid",
        "id",
        "timestamp",
        "policy_ids",
        "payload_hash",
        "verdict",
        "reasoning",
        "steering",
        "statutory_anchors",
    }
    payload_missing = payload_required - payload.keys()
    if payload_missing:
        raise ValueError(
            f"canonical_payload missing required fields: {sorted(payload_missing)}"
        )

    for field in ("schema_version", "kid", "id"):
        if payload[field] != receipt[field]:
            raise ValueError(f"Receipt {field} does not match canonical_payload {field}")
    if not _PAYLOAD_HASH_RE.fullmatch(str(payload["payload_hash"])):
        raise ValueError("canonical_payload.payload_hash must be 64 lowercase hex characters")
    if not isinstance(payload["policy_ids"], list) or not all(
        isinstance(value, str) and value for value in payload["policy_ids"]
    ):
        raise ValueError("canonical_payload.policy_ids must be a list of non-empty strings")
    if payload["verdict"] not in (0, 1):
        raise ValueError("canonical_payload.verdict must be 0 or 1")
    return payload


def _validate_trace_evidence(
    *,
    iat: int,
    model: dict[str, Any],
    data_class: str,
    policy_bundle_hash: str,
    build_provenance: dict[str, Any],
    appraisal_verifier: str,
) -> None:
    if isinstance(iat, bool) or not isinstance(iat, int) or iat < 1_700_000_000:
        raise ValueError("iat must be a Unix timestamp integer >= 1700000000")

    if not isinstance(model, dict):
        raise ValueError("model must be an object")
    unknown_model_fields = model.keys() - _MODEL_FIELDS
    if unknown_model_fields:
        raise ValueError(f"model contains unsupported fields: {sorted(unknown_model_fields)}")
    for field in ("provider", "model_id"):
        if not isinstance(model.get(field), str) or not model[field]:
            raise ValueError(f"model.{field} must be a non-empty string")
    if "weights_digest" in model:
        _validate_digest("model.weights_digest", model["weights_digest"])
    if "aibom_uri" in model:
        _validate_uri("model.aibom_uri", model["aibom_uri"])

    if not isinstance(data_class, str) or not data_class:
        raise ValueError("data_class must be a non-empty string")
    _validate_digest("policy_bundle_hash", policy_bundle_hash)

    if not isinstance(build_provenance, dict):
        raise ValueError("build_provenance must be an object")
    unknown_build_fields = build_provenance.keys() - _BUILD_FIELDS
    if unknown_build_fields:
        raise ValueError(
            f"build_provenance contains unsupported fields: {sorted(unknown_build_fields)}"
        )
    slsa_level = build_provenance.get("slsa_level")
    if isinstance(slsa_level, bool) or slsa_level not in {0, 1, 2, 3}:
        raise ValueError("build_provenance.slsa_level must be 0, 1, 2, or 3")
    _validate_digest("build_provenance.digest", build_provenance.get("digest"))
    for field in ("builder", "provenance_uri"):
        if field in build_provenance:
            _validate_uri(f"build_provenance.{field}", build_provenance[field])

    _validate_uri("appraisal_verifier", appraisal_verifier)


def _validate_digest(field: str, value: Any) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be sha256:<64hex> or sha384:<96hex>")


def _validate_uri(field: str, value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty URI")
    parsed = urlparse(value)
    if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
        raise ValueError(f"{field} must be an absolute URI")
