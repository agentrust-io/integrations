"""ramen_ai_trace — TRACE Trust Record mapper for ramen-ai V5 receipts.

Maps a ramen-ai V5 Ed25519 receipt onto a TRACE Trust Record dict
(EAT profile tag:agentrust.io,2026:trace-v0.1).

This is the self-contained copy for the agentrust-io/integrations submission.
The canonical implementation lives at:
  https://github.com/ramen-ai-dev/ramen-ai-integrations/tree/master/plugins/cmcp-python

Field mapping
─────────────
TRACE field                 ← ramen-ai V5 source
──────────────────────────────────────────────────────────────
eat_profile                 constant "tag:agentrust.io,2026:trace-v0.1"
iat                         caller-supplied (int, Unix seconds)
subject                     "spiffe://ramenai.dev/evaluation/<receipt.id>"
cnf.jwk                     caller-supplied (public JWK for signing)
policy.bundle_hash          "sha256:" + canonical_payload.payload_hash
policy.enforcement_mode     "enforce"
policy.version              canonical_payload.schema_version ("5.0")
runtime.measurement         receipt.id
runtime.platform            "software-only"
tool_transcript.call_count  1
tool_transcript.hash        "sha256:" + canonical_payload.payload_hash
tool_transcript.transcript_uri  "urn:ramen-ai:evaluation:<receipt.id>"
appraisal.policy_ref        comma-joined canonical_payload.policy_ids
appraisal.status            "affirming" if verdict==1 else "denying"
appraisal.timestamp         iat
appraisal.verifier          "ramen-ai-core"
appraisal.statutory_anchors canonical_payload.statutory_anchors (if non-empty)
appraisal.steering          canonical_payload.steering (omitted when empty)
transparency                "pending"
"""
from __future__ import annotations

import json
from typing import Any

EAT_PROFILE = "tag:agentrust.io,2026:trace-v0.1"
VERIFIER = "ramen-ai-core"


def build_trace_record(
    receipt: dict[str, Any],
    *,
    iat: int,
    jwk: dict[str, str],
) -> dict[str, Any]:
    """Map a ramen-ai V5 receipt dict onto an unsigned TRACE Trust Record dict.

    Args:
        receipt:    The ``data.receipt`` sub-object from a ramen-ai evaluate
                    response. Must contain ``id``, ``schema_version`` (``"5.0"``),
                    ``kid``, ``signature``, and ``canonical_payload``.
        iat:        Unix timestamp (int seconds) for the record issue time.
        jwk:        Public JWK dict embedded in ``cnf.jwk``; matches the private
                    key used to sign the record with ``agentrust_trace.sign_record``.

    Returns:
        Unsigned TRACE Trust Record dict.

    Raises:
        ValueError: if required fields are missing or schema_version != "5.0".
    """
    _validate_receipt(receipt)
    payload: dict[str, Any] = json.loads(receipt["canonical_payload"])

    receipt_id: str = receipt["id"]
    payload_hash: str = payload["payload_hash"]
    verdict: int = payload["verdict"]
    policy_ids: list[str] = payload.get("policy_ids", [])
    statutory_anchors: list[str] = payload.get("statutory_anchors", [])
    steering: str = payload.get("steering", "")

    prefixed_hash = f"sha256:{payload_hash}"

    appraisal: dict[str, Any] = {
        "policy_ref": ", ".join(policy_ids),
        "status": "affirming" if verdict == 1 else "denying",
        "timestamp": iat,
        "verifier": VERIFIER,
    }
    if statutory_anchors:
        appraisal["statutory_anchors"] = statutory_anchors
    if steering:
        appraisal["steering"] = steering

    return {
        "eat_profile": EAT_PROFILE,
        "iat": iat,
        "subject": f"spiffe://ramenai.dev/evaluation/{receipt_id}",
        "cnf": {"jwk": jwk},
        "policy": {
            "bundle_hash": prefixed_hash,
            "enforcement_mode": "enforce",
            "version": payload["schema_version"],
        },
        "runtime": {
            "measurement": receipt_id,
            "platform": "software-only",
        },
        "tool_transcript": {
            "call_count": 1,
            "hash": prefixed_hash,
            "transcript_uri": f"urn:ramen-ai:evaluation:{receipt_id}",
        },
        "appraisal": appraisal,
        "transparency": "pending",
    }


def _validate_receipt(receipt: dict[str, Any]) -> None:
    required = {"id", "schema_version", "kid", "signature", "canonical_payload"}
    missing = required - receipt.keys()
    if missing:
        raise ValueError(f"Receipt missing required fields: {missing}")
    if receipt["schema_version"] != "5.0":
        raise ValueError(
            f"Unsupported schema_version '{receipt['schema_version']}'; expected '5.0'"
        )
    try:
        json.loads(receipt["canonical_payload"])
    except json.JSONDecodeError as exc:
        raise ValueError(f"canonical_payload is not valid JSON: {exc}") from exc
