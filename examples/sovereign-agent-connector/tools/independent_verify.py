#!/usr/bin/env python3
"""Independent verifier for the AUCP MVE-1 evidence bundle.

This file intentionally imports no AUCP, cMCP, cA2A, TRACE, or registry code.
It is a clean-room reproduction of the experimental wire semantics using only
the Python standard library and ``cryptography`` for Ed25519 verification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE_PROFILE = "https://agentrust-io.com/profiles/aucp/v0.1"
LIVE_PROFILE = "https://agentrust-io.com/profiles/aucp/v0.1/cmcp-mve1"
BOUNDARIES = {"agreement", "delegation", "appraisal", "enforcement"}


class VerificationError(ValueError):
    pass


@dataclass(frozen=True)
class Verdict:
    workflow_id: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    platform: str
    hardware_attested: bool


def canonical(value: Any, *, ascii_only: bool = False) -> bytes:
    """Canonical JSON for this restricted experimental vector vocabulary.

    MVE-1 contains only strings, integers, booleans, null, arrays, and objects;
    it contains no floats. For that domain, sorted compact JSON is identical to
    the producer's RFC 8785 encoding. ``ascii_only`` reproduces cMCP/registry
    canonicalization, which explicitly escapes non-ASCII.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ascii_only,
        allow_nan=False,
    ).encode("ascii" if ascii_only else "utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def key_thumbprint(public_key_hex: str) -> bytes:
    x = base64.urlsafe_b64encode(bytes.fromhex(public_key_hex)).rstrip(b"=").decode()
    return hashlib.sha256(canonical({"crv": "Ed25519", "kty": "OKP", "x": x})).digest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def verify_ed25519(body: dict[str, Any], trusted_hex: str, *, cmcp: bool = False) -> None:
    require(body.get("issuer_key", trusted_hex) == trusted_hex, "unexpected signing key")
    signature = body.get("signature")
    require(isinstance(signature, str), "missing signature")
    unsigned = {key: value for key, value in body.items() if key != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_hex)).verify(
            decode_b64url(signature), canonical(unsigned, ascii_only=cmcp)
        )
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError("invalid Ed25519 signature") from exc


def verify_delegation(chain: list[dict[str, Any]], trusted_root_issuer: str) -> None:
    require(bool(chain), "empty delegation chain")
    require(chain[0]["issuer"] == trusted_root_issuer, "untrusted delegation root issuer")
    seen: set[str] = set()
    previous: dict[str, Any] | None = None
    for credential in chain:
        signature = credential.get("signature")
        require(isinstance(signature, str), "delegation credential is unsigned")
        body = {key: value for key, value in credential.items() if key != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(credential["issuer"])).verify(
                bytes.fromhex(signature), canonical(body)
            )
        except (InvalidSignature, ValueError) as exc:
            raise VerificationError("invalid delegation signature") from exc
        credential_id = credential["credential_id"]
        require(credential_id not in seen, "replayed delegation credential")
        seen.add(credential_id)
        require(credential["depth"] <= 8, "delegation depth exceeds profile maximum")
        if previous is None:
            require(credential["parent_id"] is None, "root names a parent")
            require(credential["depth"] == 0, "root depth is not zero")
        else:
            require(credential["parent_id"] == previous["credential_id"], "broken parent link")
            require(credential["issuer"] == previous["subject"], "broken issuer continuity")
            require(credential["depth"] == previous["depth"] + 1, "broken depth continuity")
            require(
                set(credential["scope"]).issubset(previous["scope"]),
                "delegated scope widens",
            )
        previous = credential


def project_policy(
    agreement: dict[str, Any],
    chain: list[dict[str, Any]],
    appraisal: dict[str, Any],
) -> dict[str, Any]:
    constraints = agreement["odrl"]["permission"][0]["constraints"]
    actions = set(constraints["actions"]).intersection(chain[-1]["scope"])
    require(bool(actions), "agreement and delegated authority do not intersect")
    require(appraisal["workload_key"] == chain[-1]["subject"], "appraisal does not bind leaf")
    return {
        "actions": sorted(actions),
        "purposes": sorted(constraints["purposes"]),
        "jurisdictions": sorted(constraints["jurisdictions"]),
        "destinations": sorted(constraints["destinations"]),
        "obligations": sorted(constraints["obligations"]),
        "appraised_jurisdiction": appraisal["jurisdiction"],
    }


def decide(policy: dict[str, Any], action: dict[str, str]) -> tuple[str, str]:
    allowed = (
        action["operation"] in policy["actions"]
        and action["purpose"] in policy["purposes"]
        and action["destination"] in policy["destinations"]
        and action["jurisdiction"] in policy["jurisdictions"]
        and action["jurisdiction"] == policy["appraised_jurisdiction"]
    )
    return ("allow", "dispatched") if allowed else ("deny", "not_dispatched")


def verify_merkle(receipt: dict[str, Any], proof: dict[str, Any], count: int, root: str) -> None:
    index = proof["leaf_index"]
    require(isinstance(index, int) and 0 <= index < count, "invalid registry leaf index")
    value = hashlib.sha256(b"\x00" + canonical(receipt, ascii_only=True)).digest()
    fn, sn = index, count - 1
    for encoded in proof["audit_path"]:
        require(sn != 0, "registry path is too long")
        sibling = bytes.fromhex(encoded.removeprefix("sha256:"))
        if fn & 1 or fn == sn:
            value = hashlib.sha256(b"\x01" + sibling + value).digest()
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            value = hashlib.sha256(b"\x01" + value + sibling).digest()
        fn >>= 1
        sn >>= 1
    require(sn == 0 and "sha256:" + value.hex() == root, "invalid registry inclusion proof")


def verify_base(base: dict[str, Any], anchors: dict[str, str]) -> dict[str, Any]:
    require(base["bundle_profile"] == BASE_PROFILE, "unsupported base profile")
    trust = base["trust"]
    require(trust == anchors, "bundle trust keys do not match out-of-band trust anchors")
    agreement, appraisal = base["agreement"], base["appraisal"]
    placement = base["placement_assertion"]
    chain, receipts, registry = base["delegation_chain"], base["receipts"], base["registry"]
    verify_ed25519(agreement, trust["owner"])
    verify_ed25519(appraisal, trust["appraisal_verifier"])
    verify_ed25519(placement, trust["placement_operator"])
    verify_delegation(chain, anchors["owner"])
    require(agreement["assignee_key"] == chain[0]["subject"], "agreement assignee mismatch")
    leaf = chain[-1]["subject"]
    require(appraisal["workload_key"] == leaf, "appraisal does not bind delegation leaf")
    require(placement["workload_key"] == leaf, "placement does not bind delegation leaf")
    require(
        appraisal["placement_assertion_hash"] == digest(placement),
        "appraisal does not bind placement assertion",
    )
    require(appraisal["jurisdiction"] == placement["jurisdiction"], "placement mismatch")
    evaluated_at = appraisal["evaluated_at"]
    require(
        appraisal["attestation"]["generated_at"]
        <= evaluated_at
        <= appraisal["attestation"]["valid_until"],
        "attestation was not fresh when appraised",
    )
    require(
        placement["issued_at"] <= evaluated_at <= placement["expires_at"],
        "placement was not valid when appraised",
    )
    require(
        appraisal["placement_evidence_basis"] == placement["evidence_basis"],
        "placement evidence basis mismatch",
    )
    require(
        not appraisal["placement_evidence_basis"].startswith("hardware"),
        "hardware cannot establish placement",
    )
    if appraisal["hardware_attested"]:
        require(appraisal["attestation"]["raw_evidence_present"], "hardware evidence is absent")
        require(appraisal["appraisal"]["status"] == "affirming", "hardware is not affirmed")
    policy = project_policy(agreement, chain, appraisal)
    require(policy == base["effective_policy"], "effective policy does not reproduce")
    require(len(receipts) == 2, "base action receipt set is incomplete")
    expected_hashes = {
        "agreement_hash": digest(agreement),
        "authority_chain_hash": digest(chain),
        "appraisal_hash": digest(appraisal),
        "effective_policy_hash": digest(policy),
    }
    seen: set[str] = set()
    for index, receipt in enumerate(receipts):
        verify_ed25519(receipt, trust["pep"])
        require(receipt["profile"] == BASE_PROFILE, "unsupported receipt profile")
        require(set(receipt["boundaries"]) == BOUNDARIES, "incomplete receipt boundaries")
        for field, expected in expected_hashes.items():
            require(receipt[field] == expected, f"receipt {field} mismatch")
        action_id = receipt["action"]["action_id"]
        require(action_id not in seen, "duplicate action receipt")
        seen.add(action_id)
        expected = decide(policy, receipt["action"])
        require(
            (receipt["decision"], receipt["dispatch_state"]) == expected,
            "receipt verdict does not reproduce",
        )
        verify_merkle(receipt, registry["proofs"][index], registry["leaf_count"], registry["root"])
    return policy


def audit_hash(entry: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in entry.items() if key != "entry_hash"}
    return hashlib.sha256(canonical(unsigned, ascii_only=True)).hexdigest()


def verify_live(bundle: dict[str, Any], anchors: dict[str, Any]) -> Verdict:
    require(bundle["profile"] == LIVE_PROFILE, "unsupported live profile")
    base = bundle["base_bundle"]
    base_anchors = anchors["base"]
    require(isinstance(base_anchors, dict), "base trust anchors are absent")
    policy = verify_base(base, base_anchors)
    context = bundle["verified_usage_context"]
    expected_context = {
        "workflow_id": base["receipts"][0]["workflow_id"],
        "agreement_hash": digest(base["agreement"]),
        "authority_chain_hash": digest(base["delegation_chain"]),
        "appraisal_hash": digest(base["appraisal"]),
        "effective_policy_hash": digest(policy),
        "actions": policy["actions"],
        "purposes": policy["purposes"],
        "jurisdictions": policy["jurisdictions"],
        "destinations": policy["destinations"],
        "leaf_workload_key": base["delegation_chain"][-1]["subject"],
    }
    require(context == expected_context, "verified usage context does not reproduce")

    entries = bundle["cmcp_audit_entries"]
    require(bool(entries), "empty cMCP audit chain")
    previous = "genesis"
    for index, entry in enumerate(entries):
        require(entry["sequence_number"] == index, "invalid audit sequence")
        require(entry["prev_entry_hash"] == previous, "broken audit linkage")
        require(entry["entry_hash"] == audit_hash(entry), "invalid audit entry hash")
        previous = entry["entry_hash"]
    tool_calls = [entry for entry in entries if entry["entry_type"] == "tool_call"]
    tools = {entry["call_id"]: entry for entry in tool_calls}
    require(len(tools) == len(tool_calls), "repeated cMCP tool call")
    require(
        set(tools) == {receipt["action"]["action_id"] for receipt in base["receipts"]},
        "cMCP tool calls do not match receipts",
    )

    trace = bundle["cmcp_trace"]
    require(
        bundle["cmcp_trace_public_key"] == anchors["cmcp_trace"],
        "cMCP TRACE key does not match its out-of-band trust anchor",
    )
    verify_ed25519(trace, anchors["cmcp_trace"], cmcp=True)
    audit = trace["gateway"]["audit_chain"]
    require(audit["root"] == entries[0]["entry_hash"], "TRACE audit root mismatch")
    require(audit["tip"] == entries[-1]["entry_hash"], "TRACE audit tip mismatch")
    require(audit["length"] == len(entries), "TRACE audit length mismatch")
    policy_hash = bundle["cmcp_policy"]["bundle_hash"]
    require(trace["trace"]["policy"]["bundle_hash"] == policy_hash, "TRACE policy mismatch")
    trace_key = bundle["cmcp_trace_public_key"]
    require(context["leaf_workload_key"] == trace_key, "delegation/TRACE key mismatch")
    report_data = bytes.fromhex(base["appraisal"]["attestation"]["report_data"])
    require(len(report_data) == 64, "attestation nonce is not 64 bytes")
    require(report_data[:32] == key_thumbprint(trace_key), "attestation/TRACE key mismatch")
    expected_root = hashlib.sha256(bytes.fromhex(entries[0]["entry_hash"])).digest()
    require(report_data[32:] == expected_root, "attestation/audit-root mismatch")
    runtime_nonce = trace["trace"]["runtime"].get("nonce")
    hardware_attested = base["appraisal"]["hardware_attested"] is True
    require(
        (trace["trace"]["runtime"]["platform"] != "software-only") == hardware_attested,
        "TRACE platform contradicts the signed appraisal",
    )
    if hardware_attested:
        require(isinstance(runtime_nonce, str), "hardware TRACE nonce is absent")
        require(decode_b64url(runtime_nonce) == report_data, "TRACE/appraisal nonce mismatch")

    bindings = bundle["adapter_bindings"]
    require(len(bindings) == len(base["receipts"]), "incomplete adapter bindings")
    binding_by_action = {binding["action_id"]: binding for binding in bindings}
    require(len(binding_by_action) == len(bindings), "duplicate adapter binding")
    allowed: list[str] = []
    denied: list[str] = []
    for receipt in base["receipts"]:
        action_id = receipt["action"]["action_id"]
        require(
            action_id in tools and action_id in binding_by_action,
            "missing action evidence join",
        )
        entry, binding = tools[action_id], binding_by_action[action_id]
        require(
            bundle["adapter_trust_key"] == anchors["adapter"],
            "adapter key does not match its out-of-band trust anchor",
        )
        verify_ed25519(binding, anchors["adapter"])
        dispatch = entry.get("detail", {}).get("dispatch_state")
        expected = {
            "usage_control_receipt_hash": digest(receipt),
            "cmcp_audit_entry_hash": "sha256:" + entry["entry_hash"],
            "cmcp_trace_hash": digest(trace),
            "cmcp_policy_bundle_hash": policy_hash,
            "decision": entry["policy_decision"],
            "dispatch_state": dispatch,
        }
        for field, value in expected.items():
            require(binding[field] == value, f"adapter binding {field} mismatch")
        require(receipt["decision"] == entry["policy_decision"], "oracle/cMCP decision mismatch")
        require(receipt["dispatch_state"] == dispatch, "oracle/cMCP dispatch mismatch")
        (allowed if entry["policy_decision"] == "allow" else denied).append(action_id)

    summary = trace["gateway"]["call_summary"]
    require(summary["tool_calls_total"] == len(tools), "TRACE call total mismatch")
    require(summary["tool_calls_allowed"] == len(allowed), "TRACE allowed count mismatch")
    require(summary["tool_calls_denied"] == len(denied), "TRACE denied count mismatch")
    platform = trace["trace"]["runtime"]["platform"]
    return Verdict(
        workflow_id=context["workflow_id"],
        allowed_actions=tuple(sorted(allowed)),
        denied_actions=tuple(sorted(denied)),
        platform=platform,
        hardware_attested=hardware_attested,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--trust-anchors", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
        anchors = json.loads(args.trust_anchors.read_text(encoding="utf-8"))
        verdict = verify_live(bundle, anchors)
    except (
        OSError,
        KeyError,
        IndexError,
        TypeError,
        AttributeError,
        OverflowError,
        ValueError,  # includes json.JSONDecodeError and VerificationError
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("PASS: AUCP MVE-1 bundle independently verified")
    print(f"workflow: {verdict.workflow_id}")
    print(f"allowed: {', '.join(verdict.allowed_actions)}")
    print(f"denied-before-dispatch: {', '.join(verdict.denied_actions)}")
    hardware = str(verdict.hardware_attested).lower()
    print(f"platform: {verdict.platform}; hardware-attested={hardware}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
