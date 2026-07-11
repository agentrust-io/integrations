"""Map a SpendGuard evidence bundle onto a TRACE Trust Record.

A SpendGuard evidence bundle is the signed audit output of one spend/gate
decision (see the upstream repo's `spendguard-agentrust-evidence/v1` layout):

    bundle.json            manifest: bundle_id, evidence_bundle_hash, file digests
    decision.json          signed CloudEvent: the allow/deny decision
    outcome.json           signed CloudEvent: reservation outcome (allow only)
    policy-bundle.json     policy bundle the decision was evaluated under
    tool-catalog.json      tool catalog in force at decision time
    build-provenance.json  build digests of the deciding SpendGuard build

This module maps those fields onto a TRACE Trust Record. Field mapping matches
the golden outputs of SpendGuard's own fixture verifier (`spendguard_agentrust`
in the upstream repo), so both sides derive the identical record shape from the
same evidence.

Verification of the SpendGuard-side CloudEvent signatures lives in the upstream
repo's conformance harness, not here; this integration demonstrates the mapping
and the agentrust-trace sign/verify round-trip.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

EAT_PROFILE = "tag:agentrust.io,2026:trace-v0.1"
VERIFIER = "agentic-spendguard-agentrust-exporter"
# SpendGuard's exporter asserts SLSA level 1 for its fixture builder; carried
# through unchanged so this record matches the upstream golden outputs.
FIXTURE_SLSA_LEVEL = 1


def _load(bundle_dir: Path, name: str) -> dict[str, Any]:
    return json.loads((bundle_dir / name).read_text(encoding="utf-8"))


def build_trace_record(bundle_dir: Path, *, iat: int, jwk: dict[str, str]) -> dict[str, Any]:
    """Build an unsigned TRACE Trust Record from a SpendGuard evidence bundle.

    `jwk` is the public JWK bound into `cnf`; the caller signs the returned
    record with the matching private key (`agentrust_trace.sign_record`).
    """
    bundle = _load(bundle_dir, "bundle.json")
    decision = _load(bundle_dir, "decision.json")
    build = _load(bundle_dir, "build-provenance.json")
    has_outcome = (bundle_dir / "outcome.json").exists()

    ce = decision["cloudevent"]
    data = ce["data_json"]
    sg = data["spendguard"]
    bundle_id = bundle["bundle_id"]

    return {
        "eat_profile": EAT_PROFILE,
        "iat": iat,
        "subject": f"spiffe://spendguard.local/tenant/{ce['tenant_id']}/run/{ce['run_id']}",
        "cnf": {"jwk": jwk},
        "data_class": data["data_class"],
        "model": data["model"],
        "policy": {
            "bundle_hash": sg["policy_bundle_hash"],
            "enforcement_mode": "enforce",
            "version": ce["schema_bundle_id"],
        },
        "runtime": {
            "measurement": bundle["evidence_bundle_hash"],
            "platform": "software-only",
        },
        "tool_transcript": {
            "call_count": 1 if has_outcome else 0,
            "hash": sg["tool_catalog_hash"],
            "transcript_uri": f"urn:spendguard:evidence:{bundle_id}",
        },
        "build_provenance": {
            "builder": build["builder"],
            "digest": build["container_image_digest"],
            "provenance_uri": f"urn:spendguard:build-provenance:{bundle_id}",
            "slsa_level": FIXTURE_SLSA_LEVEL,
        },
        "appraisal": {
            "policy_ref": ce["schema_bundle_id"],
            "status": "none",
            "timestamp": iat,
            "verifier": VERIFIER,
        },
        "transparency": "pending",
    }
