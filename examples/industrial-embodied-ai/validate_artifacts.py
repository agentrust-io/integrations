#!/usr/bin/env python3
"""Validate the committed industrial example artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from agent_manifest import canonicalize
from cmcp_runtime.config import load_config
from cmcp_verify import ApprovedHashes, verify_audit_bundle, verify_trace_claim
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


BASE = Path(__file__).resolve().parent


class ArtifactValidationError(Exception):
    """A committed artifact failed validation."""


def require(condition: object, message: str) -> None:
    # Not `assert`: python -O strips asserts, and every check here would pass.
    if not condition:
        raise ArtifactValidationError(message)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value)


def hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def external_evidence_keys() -> dict[str, bytes]:
    key_doc = json.loads(
        (BASE / "controller-receipt-public-key.json").read_text()
    )
    key_id = key_doc["key_id"]
    return {key_id: b64url_decode(key_doc["public_key_base64url"])}


def compute_policy_bundle_hash() -> str:
    policy_dir = BASE / "policy"
    manifest = json.loads((policy_dir / "manifest.json").read_text())
    policy_hashes = {
        path.relative_to(policy_dir).as_posix(): hashlib.sha256(
            path.read_text().encode()
        ).hexdigest()
        for path in sorted(policy_dir.glob("**/*.cedar"))
    }
    body = {
        "manifest": manifest,
        "policy_files": policy_hashes,
        "schema_hash": hashlib.sha256(
            (policy_dir / "schema.cedarschema").read_text().encode()
        ).hexdigest(),
    }
    return hash_bytes(canonical_bytes(body))


def compute_cmcp_catalog_hash(catalog: list[dict[str, Any]]) -> str:
    return hash_bytes(
        canonical_bytes(sorted(catalog, key=lambda entry: entry["tool_name"]))
    )


def compute_manifest_catalog_root(tools: list[dict[str, Any]]) -> str:
    leaves = []
    for tool in sorted(tools, key=lambda item: item["tool_id"]):
        preimage = (
            tool["tool_id"].encode()
            + b"\x00"
            + bytes.fromhex(tool["schema_hash"].split(":", maxsplit=1)[1])
            + bytes.fromhex(tool["description_hash"].split(":", maxsplit=1)[1])
        )
        leaves.append(hashlib.sha256(b"\x00" + preimage).digest())

    def merkle_tree_hash(nodes: list[bytes]) -> bytes:
        if len(nodes) == 1:
            return nodes[0]
        split = 1
        while split < len(nodes):
            split <<= 1
        split >>= 1
        return hashlib.sha256(
            b"\x01"
            + merkle_tree_hash(nodes[:split])
            + merkle_tree_hash(nodes[split:])
        ).digest()

    return "sha256:" + merkle_tree_hash(leaves).hex()


def verify_manifest_signature(manifest: dict[str, Any]) -> None:
    public_key = json.loads((BASE / "manifest-public-key.json").read_text())
    require(
        manifest["signature"]["key_id"] == public_key["key_id"],
        "manifest signed by an unexpected key",
    )
    signed_fields = manifest["signature"]["signed_fields"]
    # signed_fields travels inside the manifest, so a field it leaves out is
    # unauthenticated. Every top-level field except the signature must be listed.
    unsigned = set(manifest) - {"signature"} - set(signed_fields)
    require(not unsigned, f"manifest fields outside the signature: {sorted(unsigned)}")
    body = {key: manifest[key] for key in signed_fields if key in manifest}
    Ed25519PublicKey.from_public_bytes(
        b64url_decode(public_key["public_key_base64url"])
    ).verify(
        b64url_decode(manifest["signature"]["signature_value"]),
        canonical_bytes(body),
    )


def main() -> None:
    expected = json.loads((BASE / "artifact-hashes.json").read_text())
    catalog = json.loads((BASE / "catalog.json").read_text())
    manifest = json.loads((BASE / "agent-manifest.json").read_text())
    claim = json.loads(
        (BASE / "trace-output/example-trust-record.json").read_text()
    )
    audit_bundle = json.loads(
        (BASE / "trace-output/example-audit-bundle.json").read_text()
    )

    load_config(BASE / "cmcp-config.yaml")

    for entry in catalog:
        definition_hash = hash_bytes(
            canonical_bytes(entry["approved_definition"])
        )
        require(
            definition_hash == entry["definition_hash"],
            f"catalog definition_hash mismatch: {entry['tool_name']}",
        )

    policy_hash = compute_policy_bundle_hash()
    catalog_hash = compute_cmcp_catalog_hash(catalog)
    manifest_catalog_root = compute_manifest_catalog_root(
        manifest["artifacts"]["tool_manifest"]["tools"]
    )
    prompt_hash = hash_bytes(
        (BASE / "artifacts/system-prompt.txt").read_bytes()
    )

    require(
        expected["cmcp_policy_bundle_hash"] == policy_hash,
        "policy bundle hash mismatch",
    )
    require(expected["cmcp_catalog_hash"] == catalog_hash, "cMCP catalog hash mismatch")
    require(
        expected["agent_manifest_tool_catalog_root"] == manifest_catalog_root,
        "tool catalog root mismatch",
    )
    require(expected["system_prompt_hash"] == prompt_hash, "system prompt hash mismatch")
    require(
        manifest["artifacts"]["policy_bundle"]["hash"] == policy_hash,
        "manifest policy bundle hash mismatch",
    )
    require(
        manifest["artifacts"]["tool_manifest"]["catalog_hash"]
        == manifest_catalog_root,
        "manifest tool catalog hash mismatch",
    )
    require(
        manifest["artifacts"]["system_prompt"]["hash"] == prompt_hash,
        "manifest system prompt hash mismatch",
    )
    verify_manifest_signature(manifest)

    verification = verify_trace_claim(
        claim,
        ApprovedHashes(
            policy_bundle_hash=policy_hash,
            tool_catalog_hash=catalog_hash,
        ),
        # The committed fixture is expected to outlive the default 24-hour
        # online freshness window. Live runs still use the default window.
        max_attestation_age_seconds=315_360_000,
    )
    required = {
        "schema",
        "signature",
        "policy_bundle.hash",
        "tool_catalog.hash",
        "attestation_freshness",
        "audit_chain",
    }
    missing = required - set(verification.verified_fields)
    require(not missing, f"TRACE claim fields not verified: {sorted(missing)}")
    require(
        claim["trace"]["runtime"]["platform"] == "software-only",
        "committed fixture is expected to be a software-only record",
    )

    bundle_verification = verify_audit_bundle(
        audit_bundle,
        claim,
        external_evidence_keys=external_evidence_keys(),
    )
    require(
        bundle_verification.verified,
        f"audit bundle failed verification: {bundle_verification.failures}",
    )
    receipt_count = sum(
        1
        for entry in audit_bundle.get("entries", [])
        if entry.get("external_execution_evidence")
    )

    print("Configuration and artifact hashes: valid")
    print("Agent Manifest signature: valid")
    print("Runtime-issued TRACE signature and audit bundle: valid")
    if receipt_count:
        print(f"Controller execution receipts: valid ({receipt_count})")
    else:
        print("Controller execution receipts: not present in committed fixture")
    print("Hardware attestation: not present in committed development fixture")


if __name__ == "__main__":
    main()
