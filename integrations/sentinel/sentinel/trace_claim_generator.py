"""
Agent Sentinel -> TRACE v0.2 claim generator.

Every enforcement event is emitted as an Ed25519-signed TRACE v0.2 JWT,
conformant at Level 0 (software-only; no hardware TEE attestation).

Signing is mandatory. Sentinel will not emit an unsigned governance claim.
Supply an Ed25519 signing key via the TRACE_PRIVATE_KEY_PEM environment
variable, or pass one explicitly to TraceClaimGenerator. If no key is
available, claim generation fails closed rather than emitting an unsigned
record.
"""

import base64
import json
import os
import time
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# Sentinel enforcement decision -> TRACE appraisal.status
_APPRAISAL_MAP = {
    "ADMIT": "affirming",
    "REVIEW": "warning",
    "DENY": "contraindicated",
    "BLOCK": "contraindicated",
}

_SELF_URI = "https://github.com/agentrust-io/integrations/tree/main/integrations/sentinel"


def load_signing_key(explicit: Optional[Ed25519PrivateKey] = None) -> Ed25519PrivateKey:
    """Return the Ed25519 signing key, or raise if none is configured.

    Fails closed: without a key, Sentinel refuses to emit unsigned claims.
    """
    if explicit is not None:
        return explicit
    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError(
            "TRACE_PRIVATE_KEY_PEM is not set. Agent Sentinel signs every TRACE "
            "claim and refuses to emit unsigned governance records. Generate an "
            "Ed25519 key and set it in the environment before enforcing."
        )
    return serialization.load_pem_private_key(pem.encode(), password=None)


def private_key_to_jwk(key: Ed25519PrivateKey) -> dict:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).decode().rstrip("="),
    }


def _isoified(value: Any) -> Any:
    """Recursively convert datetime/date values to ISO strings for JSON output."""
    if isinstance(value, dict):
        return {k: _isoified(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_isoified(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


@dataclass
class SignedTraceClaim:
    payload: Dict[str, Any]  # canonical TRACE v0.2 EAT payload (includes cnf.jwk)
    token: str  # EdDSA-signed JWT, offline-verifiable against cnf.jwk

    def to_json(self) -> str:
        return json.dumps(
            {"payload": self.payload, "token": self.token},
            separators=(",", ":"),
        )


class TraceClaimGenerator:
    def __init__(
        self,
        issuer_id: str = "sentinel",
        signing_key: Optional[Ed25519PrivateKey] = None,
    ):
        self.issuer_id = issuer_id
        # Loaded lazily so importing this module (and the FastAPI app) has no
        # side effects and does not require a key to be present.
        self._signing_key = signing_key

    def _key(self) -> Ed25519PrivateKey:
        if self._signing_key is None:
            self._signing_key = load_signing_key()
        return self._signing_key

    def build_payload(
        self,
        enforcement_event: Dict[str, Any],
        agent_id: str = "agent-fleet",
        decision: str = "DENY",
        model: str = "unknown/unknown",
    ) -> Dict[str, Any]:
        key = self._key()
        provider, _, model_id = model.partition("/")
        return {
            # Required TRACE EAT envelope
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": int(time.time()),
            "subject": f"spiffe://agentrust-io.com/agent/{agent_id}",
            # Confirmation key: the Ed25519 public key that signs this claim
            "cnf": {"jwk": private_key_to_jwk(key)},
            "model": {
                "provider": provider or "unknown",
                "model_id": model_id or model,
                "version": "unknown",
                # sha256 all-zeros: canonical Level 0 placeholder (no HW attestation)
                "weights_digest": "sha256:" + "0" * 64,
            },
            "runtime": {
                "platform": "software-only",
                "measurement": "sha384:" + "0" * 96,
                "rim_uri": _SELF_URI,
            },
            "policy": {
                "bundle_hash": "sha256:" + "0" * 64,
                "enforcement_mode": "enforce",
                "version": "1.0.0",
            },
            "data_class": "confidential",
            "build_provenance": {
                "slsa_level": 0,
                "builder": _SELF_URI,
                "digest": "sha256:" + "0" * 64,
            },
            # Appraisal carries the Sentinel enforcement decision
            "appraisal": {
                "status": _APPRAISAL_MAP.get(decision, "contraindicated"),
                "verifier": _SELF_URI,
                "policy_ref": "agent-sentinel-v1.0.0",
            },
            "transparency": "",
            # Sentinel-specific extension claim: the detection/enforcement detail
            "sentinel": {
                "issuer": self.issuer_id,
                "decision": decision,
                "event": _isoified(enforcement_event),
            },
        }

    def generate_claim(
        self,
        enforcement_event: Dict[str, Any],
        agent_id: str = "agent-fleet",
        decision: str = "DENY",
        model: str = "unknown/unknown",
    ) -> SignedTraceClaim:
        key = self._key()
        payload = self.build_payload(enforcement_event, agent_id, decision, model)
        token = jwt.encode(
            payload, key, algorithm="EdDSA", headers={"alg": "EdDSA", "typ": "JWT"}
        )
        return SignedTraceClaim(payload=payload, token=token)


def generate_trace_claim(
    event: Dict[str, Any],
    agent_id: str = "agent-fleet",
    decision: str = "DENY",
) -> str:
    """Convenience wrapper: return the signed TRACE claim as a JSON string.

    Requires a signing key (TRACE_PRIVATE_KEY_PEM); raises otherwise.
    """
    claim = TraceClaimGenerator().generate_claim(
        event, agent_id=agent_id, decision=decision
    )
    return claim.to_json()
