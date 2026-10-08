from __future__ import annotations

import base64
import copy
import importlib.util
import json
import sys
from dataclasses import asdict
from pathlib import Path

import pytest
from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import canonical_json

from agentrust_auc import cmcp_adapter
from agentrust_auc.cmcp_adapter import build_live_experiment, verify_live_bundle
from agentrust_auc.core import BundleError, _digest, _sign


def _independent_verifier():
    name = "independent_verify"
    if name not in sys.modules:
        path = Path(__file__).parents[1] / "tools" / "independent_verify.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def test_live_cmcp_adapter_allows_fr_and_never_dispatches_us() -> None:
    dispatched: list[str] = []
    result = build_live_experiment(lambda action: dispatched.append(action["action_id"]))

    assert dispatched == ["urn:uuid:action-allowed-001"]
    assert result.dispatched == ("urn:uuid:action-allowed-001",)
    tool_entries = [
        entry for entry in result.bundle["cmcp_audit_entries"] if entry["entry_type"] == "tool_call"
    ]
    observed = [
        (entry["policy_decision"], entry["detail"]["dispatch_state"]) for entry in tool_entries
    ]
    assert observed == [
        ("allow", "dispatched"),
        ("deny", "not_dispatched"),
    ]
    assert (
        result.bundle["base_bundle"]["delegation_chain"][-1]["subject"]
        == result.bundle["cmcp_trace_public_key"]
    )
    verify_live_bundle(result.bundle, result.trust_anchors)
    verify_live_bundle(json.loads(json.dumps(result.bundle)), result.trust_anchors)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["cmcp_audit_entries"][1].update({"policy_decision": "deny"}),
        lambda b: b["cmcp_trace"]["gateway"]["audit_chain"].update({"tip": "0" * 64}),
        lambda b: b["adapter_bindings"][0].update({"dispatch_state": "not_dispatched"}),
        lambda b: b["adapter_bindings"].pop(),
        lambda b: b["base_bundle"]["appraisal"]["attestation"].update({"report_data": "00" * 64}),
    ],
)
def test_live_bundle_fails_closed_on_evidence_tampering(mutate) -> None:
    result = build_live_experiment()
    bundle = copy.deepcopy(result.bundle)
    mutate(bundle)
    with pytest.raises(BundleError):
        verify_live_bundle(bundle, result.trust_anchors)


def test_internally_consistent_live_bundle_cannot_replace_trusted_authorities() -> None:
    trusted = build_live_experiment()
    attacker = build_live_experiment()

    with pytest.raises(BundleError, match="out-of-band trust anchors"):
        verify_live_bundle(attacker.bundle, trusted.trust_anchors)


class _DispatchTwiceChain(AuditChain):
    """Records the allowed action twice, as a replayed dispatch would."""

    def append(self, entry_type, **fields):
        if entry_type == "tool_call" and fields.get("policy_decision") == "allow":
            super().append(entry_type, **fields)
        return super().append(entry_type, **fields)


class _UnreceiptedDispatchChain(AuditChain):
    """Records one extra dispatched tool call that no AUCP receipt covers."""

    def append(self, entry_type, **fields):
        entry = super().append(entry_type, **fields)
        if entry_type == "tool_call" and fields.get("policy_decision") == "allow":
            super().append(entry_type, **{**fields, "call_id": "urn:uuid:unreceipted-001"})
        return entry


@pytest.mark.parametrize("chain_type", [_DispatchTwiceChain, _UnreceiptedDispatchChain])
def test_audit_tool_calls_must_match_receipts_one_to_one(monkeypatch, chain_type) -> None:
    monkeypatch.setattr(cmcp_adapter, "AuditChain", chain_type)
    monkeypatch.setattr(cmcp_adapter, "verify_live_bundle", lambda *_: None)
    result = build_live_experiment()
    bundle = json.loads(json.dumps(result.bundle))
    anchors = json.loads(json.dumps(asdict(result.trust_anchors)))

    with pytest.raises(BundleError, match="tool calls"):
        verify_live_bundle(bundle, result.trust_anchors)
    independent = _independent_verifier()
    with pytest.raises(independent.VerificationError):
        independent.verify_live(bundle, anchors)


def test_trace_platform_cannot_claim_hardware_the_appraisal_did_not(monkeypatch) -> None:
    adapter_keys = []
    original_keypair = cmcp_adapter.new_keypair

    def capture_keypair():
        keypair = original_keypair()
        adapter_keys.append(keypair[0])
        return keypair

    monkeypatch.setattr(cmcp_adapter, "new_keypair", capture_keypair)
    workload_key = SigningKey()
    result = build_live_experiment(workload_signing_key=workload_key)
    bundle = json.loads(json.dumps(result.bundle))
    assert bundle["base_bundle"]["appraisal"]["hardware_attested"] is False

    # The workload signs its own TRACE record, so it can claim any platform.
    trace = bundle["cmcp_trace"]
    trace["trace"]["runtime"]["platform"] = "amd-sev-snp"
    signature = workload_key.sign(canonical_json(trace))
    trace["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    bundle["adapter_bindings"] = [
        _sign(
            {
                **{k: v for k, v in binding.items() if k not in {"signature", "issuer_key"}},
                "cmcp_trace_hash": _digest(trace),
            },
            adapter_keys[-1],
        )
        for binding in bundle["adapter_bindings"]
    ]

    with pytest.raises(BundleError, match="platform"):
        verify_live_bundle(bundle, result.trust_anchors)
    independent = _independent_verifier()
    with pytest.raises(independent.VerificationError, match="platform"):
        independent.verify_live(bundle, json.loads(json.dumps(asdict(result.trust_anchors))))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["cmcp_audit_entries"][0].pop("latency_us"),
        lambda b: b["cmcp_audit_entries"].__setitem__(1, "not-an-entry"),
    ],
)
def test_malformed_live_bundle_raises_only_bundle_error(mutate) -> None:
    result = build_live_experiment()
    bundle = copy.deepcopy(result.bundle)
    mutate(bundle)
    with pytest.raises(BundleError):
        verify_live_bundle(bundle, result.trust_anchors)


def test_committed_mve1_vector_verifies_with_the_core_verifier() -> None:
    # The committed vector is regenerated by scripts/generate_live_bundle.py; the
    # audit-entry hashes cover exactly the fields the generating cMCP wrote.
    vectors = Path(__file__).parents[1] / "vectors" / "french-healthcare"
    bundle = json.loads((vectors / "cmcp-live-bundle.json").read_text(encoding="utf-8"))
    anchors = cmcp_adapter.LiveTrustAnchors.from_dict(
        json.loads((vectors / "cmcp-live-trust-anchors.json").read_text(encoding="utf-8"))
    )
    verify_live_bundle(bundle, anchors)
