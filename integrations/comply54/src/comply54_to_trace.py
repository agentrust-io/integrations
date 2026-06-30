#!/usr/bin/env python3
"""
comply54 -> TRACE v0.1 Adapter
Reads a comply54 ComplianceResult JSON and emits a signed TRACE v0.1 JWT (Ed25519).
Conforms to TRACE spec at Level 0 (software-only; no hardware TEE attestation).

Usage:
    python comply54_to_trace.py result.json
    python comply54_to_trace.py result.json --agent-id payments-agent --model anthropic/claude-sonnet-4-6

The JWT is written to claim.jwt and printed to stdout.
Set TRACE_PRIVATE_KEY_PEM to supply a persistent Ed25519 key; otherwise a
fresh key is generated per run (suitable for testing).
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ── comply54 appraisal → TRACE appraisal status ───────────────────────────────

_APPRAISAL_MAP = {
    "allow":    "affirming",
    "audit":    "advisory",
    "escalate": "warning",
    "deny":     "contraindicated",
}


# ── Key helpers ───────────────────────────────────────────────────────────────

def load_or_generate_key() -> Ed25519PrivateKey:
    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if pem:
        return serialization.load_pem_private_key(pem.encode(), password=None)
    return Ed25519PrivateKey.generate()


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


# ── Mapping ───────────────────────────────────────────────────────────────────

def comply54_to_trace_payload(result: dict, agent_id: str, model: str) -> dict:
    overall = result.get("overall", "deny")
    audit_id = result.get("audit_id", "unknown")
    decisions = result.get("decisions", [])

    # Policy bundle hash: deterministic fingerprint of the pack IDs that ran
    pack_ids = sorted({d.get("pack", "") for d in decisions if d.get("pack")})
    bundle_input = json.dumps(pack_ids, sort_keys=True).encode()
    bundle_hash = f"sha256:{hashlib.sha256(bundle_input).hexdigest()}"

    # Jurisdictions covered by this evaluation
    jurisdictions = sorted({d.get("jurisdiction", "") for d in decisions if d.get("jurisdiction")})

    # Violations summary (embedded as a non-standard extension claim)
    violations = [
        {
            "pack": d.get("pack"),
            "regulation": d.get("regulation"),
            "action": d.get("action"),
            "messages": d.get("messages", [])[:1],  # first message only for compactness
        }
        for d in decisions
        if d.get("action") != "allow"
    ]

    appraisal_status = _APPRAISAL_MAP.get(overall, "contraindicated")

    provider, _, model_id = model.partition("/")

    return {
        # ── Required TRACE EAT envelope ──────────────────────────────────────
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": int(time.time()),
        "subject": f"spiffe://comply54.io/agent/{agent_id}",

        # ── Model identity (the agent being governed, not comply54) ──────────
        "model": {
            "provider": provider or "unknown",
            "model_id": model_id or model,
            "version": "unknown",
            "weights_digest": "sha256:not-attested",
        },

        # ── Runtime (software-only — Level 0) ────────────────────────────────
        "runtime": {
            "platform": "software-only",
            "measurement": "sha384:" + "0" * 96,
            "rim_uri": "https://github.com/comply54/comply54",
        },

        # ── Policy evidence: comply54 pack bundle ────────────────────────────
        "policy": {
            "bundle_hash": bundle_hash,
            "enforcement_mode": "enforce",
            "version": "0.1.0",
        },

        # ── Data classification ───────────────────────────────────────────────
        "data_class": "confidential",

        # ── Build provenance (software-only) ─────────────────────────────────
        "build_provenance": {
            "slsa_level": 0,
            "builder": "https://github.com/comply54/comply54",
            "digest": "sha256:not-attested",
        },

        # ── Appraisal: the comply54 decision ─────────────────────────────────
        "appraisal": {
            "status": appraisal_status,
            "verifier": "https://github.com/comply54/comply54",
            "policy_ref": f"comply54-v0.1.0/{','.join(pack_ids)}",
        },

        # ── Transparency (no log anchor at Level 0) ───────────────────────────
        "transparency": "",

        # ── comply54-specific extension claims ───────────────────────────────
        "comply54": {
            "audit_id": audit_id,
            "overall": overall,
            "jurisdictions": jurisdictions,
            "packs_evaluated": pack_ids,
            "violations": violations,
        },
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Convert comply54 ComplianceResult to TRACE v0.1 JWT")
    parser.add_argument("result_json", help="Path to comply54 ComplianceResult JSON file")
    parser.add_argument("--agent-id", default="fintech-agent", help="Agent SPIFFE identity suffix")
    parser.add_argument("--model", default="unknown/unknown", help="Model in provider/model-id format")
    parser.add_argument("--out", default="claim.jwt", help="Output JWT file (default: claim.jwt)")
    args = parser.parse_args()

    with open(args.result_json) as f:
        result = json.load(f)

    payload = comply54_to_trace_payload(result, args.agent_id, args.model)
    key = load_or_generate_key()
    payload["cnf"] = {"jwk": private_key_to_jwk(key)}

    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"alg": "EdDSA", "typ": "JWT"})

    Path(args.out).write_text(token)
    print(token)


if __name__ == "__main__":
    main()
