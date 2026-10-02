"""Local application authority, not a normative UCP or payment mandate.

The configured grant key is an external trust input. A valid grant signature
authenticates the exact fields below, not whether a user consented in a UI, a
merchant fulfilled an order, or a payment settled. The controller and auditor
must separately check expiry, request bindings, scope, amount, and one-spend
state. Neither a JWS ``kid`` nor a key supplied in a transcript establishes trust.
"""

from __future__ import annotations

import json
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import rfc8785
from agentrust_trace import (
    TRACE_PROFILE_V0_2,
    TrustRecord,
    sign_record,
    validate_json,
    verify_record,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from joserfc import jws
from joserfc.jwk import OKPKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

GRANT_ALGORITHM = "Ed25519"
GRANT_TYPE = "example-ucp-authority+jws"
DECISION_TYPE = "example-ucp-decision+jws"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_UNIX_TIME = 253_402_300_799  # 9999-12-31T23:59:59Z, not an unbounded expiry.
TRACE_SUBJECT = "did:example:released-ucp-local-controller"
TRACE_MAX_AGE_SECONDS = 300
TRACE_APPRAISAL_VERIFIER = "urn:example:appraisal-not-performed"


class EvidenceError(ValueError):
    """An evidence object failed local verification; no raw payload is returned."""


class AuthorityGrant(BaseModel):
    """Closed, non-coercing authority format scoped only to this local example."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    grant_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    merchant_origin: str = Field(min_length=1, max_length=2048)
    merchant_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    max_amount_minor: int = Field(gt=0, le=MAX_SAFE_INTEGER)
    operation: Literal["checkout.complete"]
    expires_at: int = Field(gt=0, le=MAX_UNIX_TIME)

    @field_validator("merchant_origin")
    @classmethod
    def origin_only(cls, value: str) -> str:
        """Require a literal HTTP(S) origin, without silently normalizing it."""
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or value != f"{parsed.scheme}://{parsed.netloc}"
            or any(character.isspace() for character in value)
        ):
            raise ValueError("merchant_origin must be an exact HTTP(S) origin")
        _ = parsed.port  # Reject malformed or out-of-range port syntax.
        return value


def _protected(kid: str) -> dict[str, str]:
    if not isinstance(kid, str) or not kid or len(kid) > 128:
        raise EvidenceError("invalid configured grant key identifier")
    return {"alg": GRANT_ALGORITHM, "kid": kid, "typ": GRANT_TYPE}


def sign_grant(grant: AuthorityGrant, key: Ed25519PrivateKey, kid: str) -> str:
    """Sign a revalidated grant as RFC 8785 canonical JSON in compact JWS."""
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("grant signing requires an Ed25519 private key")
    # Revalidation also refuses model_construct/model_copy bypasses on the caller.
    validated = AuthorityGrant.model_validate(grant.model_dump(warnings=False))
    return jws.serialize_compact(
        _protected(kid),
        rfc8785.dumps(validated.model_dump()),
        OKPKey.import_key(key),
        algorithms=[GRANT_ALGORITHM],
    )


def verify_grant(token: str, key: Ed25519PublicKey, kid: str) -> AuthorityGrant:
    """Authenticate a canonical, strictly typed grant against configured trust.

    This deliberately has no clock or business context. Its caller must enforce
    the signed expiry and other grant constraints before any business action.
    """
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceError("grant verification requires a trusted Ed25519 public key")
    expected = _protected(kid)
    try:
        if not isinstance(token, str) or not token or len(token) > 8192:
            raise ValueError("invalid compact JWS size or type")
        signed = jws.deserialize_compact(
            token, OKPKey.import_key(key), algorithms=[GRANT_ALGORITHM]
        )
        if signed.protected != expected:
            raise ValueError("unexpected protected header")
        payload = json.loads(signed.payload)
        if not isinstance(payload, dict) or rfc8785.dumps(payload) != signed.payload:
            raise ValueError("payload must be a canonical JSON object")
        return AuthorityGrant.model_validate(payload)
    except Exception:
        # This is a refusal at the evidence boundary. Do not leak a JOSE error,
        # attacker-controlled payload, or validation input through diagnostics.
        raise EvidenceError("invalid authority grant") from None


def _digest(value: Any) -> str:
    return "sha256:" + sha256(rfc8785.dumps(value)).hexdigest()


def sign_decision(payload: dict[str, Any], key: Ed25519PrivateKey, kid: str) -> str:
    """Sign the caller's local decision object; its model belongs to the auditor."""
    if not isinstance(payload, dict) or not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("decision signing requires an object and Ed25519 private key")
    return jws.serialize_compact(
        {**_protected(kid), "typ": DECISION_TYPE},
        rfc8785.dumps(payload),
        OKPKey.import_key(key),
        algorithms=[GRANT_ALGORITHM],
    )


def verify_decision(token: str, key: Ed25519PublicKey, kid: str) -> dict[str, Any]:
    """Authenticate canonical decision bytes; the auditor must validate its model.

    This helper does not authorize execution or interpret business fields. It
    neither coerces signed values nor treats an embedded key as a trust source.
    """
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceError("decision verification requires a trusted Ed25519 public key")
    expected = {**_protected(kid), "typ": DECISION_TYPE}
    try:
        if not isinstance(token, str) or not token or len(token) > 65_536:
            raise ValueError("invalid compact JWS size or type")
        signed = jws.deserialize_compact(
            token, OKPKey.import_key(key), algorithms=[GRANT_ALGORITHM]
        )
        if signed.protected != expected:
            raise ValueError("unexpected protected header")
        payload = json.loads(signed.payload)
        if not isinstance(payload, dict) or rfc8785.dumps(payload) != signed.payload:
            raise ValueError("payload must be a canonical JSON object")
        return payload
    except Exception:
        raise EvidenceError("invalid decision receipt") from None


def _trace_epoch(now: datetime) -> int:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise EvidenceError("TRACE evaluation requires an aware datetime")
    timestamp = int(now.timestamp())
    if not 1_700_000_000 <= timestamp <= MAX_UNIX_TIME:
        raise EvidenceError("TRACE evaluation time is outside the example profile")
    return timestamp


def create_trace(
    transcript: dict[str, Any], key: Ed25519PrivateKey, now: datetime
) -> dict[str, Any]:
    """Use released TRACE signing for the local software policy assertion.

    The outer local JWS decision binds this record's digest to UCP business
    evidence. UCP HTTP is not a MCP/A2A tool transcript, so this record does not
    overload ``tool_transcript`` or invent a reference resolver.
    The required measurement/build digest is the source of this helper, locally
    read by the signer, not a hardware measurement or proof that this code ran.
    ``transcript['policy']`` names the local controller's enforced application
    policy. There is no model, transparency anchor, or affirming appraisal.
    """
    if not isinstance(transcript, dict) or not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("TRACE creation requires a transcript and Ed25519 private key")
    if not isinstance(transcript.get("policy"), dict) or not transcript["policy"]:
        raise EvidenceError("TRACE creation requires the local application policy")
    source_digest = "sha256:" + sha256(Path(__file__).read_bytes()).hexdigest()
    payload: dict[str, Any] = {
        "eat_profile": TRACE_PROFILE_V0_2,
        "iat": _trace_epoch(now),
        "subject": TRACE_SUBJECT,
        "model": {"provider": "none", "model_id": "no-model-used"},
        "runtime": {"platform": "software-only", "measurement": source_digest},
        "policy": {
            "bundle_hash": _digest(transcript["policy"]),
            "enforcement_mode": "enforce",
        },
        "data_class": "synthetic-example",
        "origin": {"kind": "self", "producer": "released-ucp-local-controller"},
        "build_provenance": {"slsa_level": 0, "digest": source_digest},
        "appraisal": {"status": "none", "verifier": TRACE_APPRAISAL_VERIFIER},
    }
    record = sign_record(payload, key)
    validate_json(record)
    TrustRecord.model_validate(record, strict=True)
    return record


def verify_trace(
    record: dict[str, Any],
    key: Ed25519PublicKey,
    now: datetime,
    transcript: dict[str, Any],
    *,
    revoked_key_ids: frozenset[str] = frozenset(),
) -> None:
    """Verify released TRACE shape/signature, local trust, age, and policy hash.

    Revocation is checked against the caller's local list (empty for the fresh
    disposable example keys). This is not a published revocation service or a
    freshness-checked revocation bundle. Success never establishes payment,
    execution, hardware provenance, or the truth of the recorded observations.
    The business auditor must still verify the outer decision and every included
    signature and binding; this TRACE record alone does not bind all HTTP data.
    """
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceError("TRACE verification requires a trusted Ed25519 public key")
    try:
        if not isinstance(record, dict) or not isinstance(transcript, dict):
            raise ValueError("TRACE and transcript must be objects")
        if not isinstance(transcript.get("policy"), dict) or not transcript["policy"]:
            raise ValueError("local application policy is required")
        if not isinstance(revoked_key_ids, frozenset) or any(
            not isinstance(identifier, str) for identifier in revoked_key_ids
        ):
            raise ValueError("invalid configured revocation list")
        validate_json(record)
        TrustRecord.model_validate(record, strict=True)
        result = verify_record(
            record,
            key,
            allow_embedded_key=False,
            max_age_seconds=TRACE_MAX_AGE_SECONDS,
            max_future_skew_seconds=0,
            revocation=revoked_key_ids,
            now=_trace_epoch(now),
        )
        if result.revocation.outcome != "verified" or result.revocation.evidence != {
            "source": "store"
        }:
            raise ValueError("local revocation check was not performed")
        if (
            set(record)
            != {
                "eat_profile",
                "iat",
                "subject",
                "model",
                "runtime",
                "policy",
                "data_class",
                "origin",
                "build_provenance",
                "appraisal",
                "cnf",
                "signature",
            }
            or record["subject"] != TRACE_SUBJECT
            or record["model"] != {"provider": "none", "model_id": "no-model-used"}
            or record["runtime"]["platform"] != "software-only"
            or set(record["runtime"]) != {"platform", "measurement"}
            or record["data_class"] != "synthetic-example"
            or record["policy"]
            != {"bundle_hash": _digest(transcript["policy"]), "enforcement_mode": "enforce"}
            or record["appraisal"] != {"status": "none", "verifier": TRACE_APPRAISAL_VERIFIER}
            or record["origin"] != {"kind": "self", "producer": "released-ucp-local-controller"}
            or record["build_provenance"]
            != {"slsa_level": 0, "digest": record["runtime"]["measurement"]}
        ):
            raise ValueError("TRACE differs from the local observation profile")
    except Exception:
        raise EvidenceError("invalid TRACE observation record") from None
