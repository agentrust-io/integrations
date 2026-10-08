"""Experimental MVE-1 adapter over cMCP's real Cedar, audit, and TRACE paths."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    ToolTranscriptEntry,
    canonical_json,
    generate_trace_claim,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.tee.base import (
    SoftwareOnlyProvider,
    TEEProvider,
    audit_root_commitment,
    jwk_thumbprint,
    make_audit_bound_nonce,
)
from cmcp_runtime.tee.nras import AppraisalResult
from cmcp_verify.azure_cvm import verify_azure_cvm_measurement
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import (
    BundleError,
    BundleTrustAnchors,
    _digest,
    _fail_closed_as_bundle_error,
    _sign,
    _verify_signed,
    build_experiment,
    new_keypair,
    verify_bundle,
)


@dataclass(frozen=True)
class VerifiedUsageContext:
    """Only verified, normalized values cross into the cMCP adapter."""

    workflow_id: str
    agreement_hash: str
    authority_chain_hash: str
    appraisal_hash: str
    effective_policy_hash: str
    actions: tuple[str, ...]
    purposes: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    destinations: tuple[str, ...]
    leaf_workload_key: str

    @classmethod
    def from_bundle(
        cls, bundle: dict[str, Any], trust_anchors: BundleTrustAnchors
    ) -> VerifiedUsageContext:
        verify_bundle(bundle, trust_anchors)
        policy = bundle["effective_policy"]
        return cls(
            workflow_id=bundle["receipts"][0]["workflow_id"],
            agreement_hash=_digest(bundle["agreement"]),
            authority_chain_hash=_digest(bundle["delegation_chain"]),
            appraisal_hash=_digest(bundle["appraisal"]),
            effective_policy_hash=_digest(policy),
            actions=tuple(policy["actions"]),
            purposes=tuple(policy["purposes"]),
            jurisdictions=tuple(policy["jurisdictions"]),
            destinations=tuple(policy["destinations"]),
            leaf_workload_key=bundle["delegation_chain"][-1]["subject"],
        )


@dataclass(frozen=True)
class LiveTrustAnchors:
    """Out-of-band public keys trusted by a live AUCP bundle consumer."""

    base: BundleTrustAnchors
    cmcp_trace: str
    adapter: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> LiveTrustAnchors:
        try:
            return cls(
                base=BundleTrustAnchors.from_dict(value["base"]),
                cmcp_trace=value["cmcp_trace"],
                adapter=value["adapter"],
            )
        except (KeyError, TypeError) as exc:
            raise BundleError("live trust anchors are incomplete") from exc


@dataclass(frozen=True)
class LiveExperimentResult:
    bundle: dict[str, Any]
    dispatched: tuple[str, ...]
    trust_anchors: LiveTrustAnchors


def _cedar_policy(context: VerifiedUsageContext) -> str:
    destinations = sorted(context.destinations)
    if len(destinations) != 1:
        raise BundleError("MVE-1 expects exactly one approved destination")
    escaped = destinations[0].replace("\\", "\\\\").replace('"', '\\"')
    return (
        "// AUCP MVE-1: generated from verified agreement context\n"
        f'permit(principal, action, resource) when {{ resource == Resource::"{escaped}" }};'
    )


def _policy_bundle(context: VerifiedUsageContext) -> PolicyBundle:
    policy = _cedar_policy(context)
    bundle_hash = _digest(
        {
            "profile": "cmcp-aucp-mve1",
            "agreement_hash": context.agreement_hash,
            "effective_policy_hash": context.effective_policy_hash,
            "cedar": policy,
        }
    )
    return PolicyBundle(
        manifest=PolicyManifest(
            version="0.0.1",
            authored_at="2026-08-13T00:00:00Z",
            author_identity="agentrust-io/agentic-usage-control",
            commit_sha="example-mve1",
        ),
        policy_files={"aucp-mve1.cedar": policy},
        schema_content="{}",
        bundle_hash=bundle_hash,
    )


def _trace_signature_valid(claim: dict[str, Any], public_key_hex: str) -> bool:
    try:
        signature = base64.urlsafe_b64decode(claim["signature"] + "==")
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(signature, canonical_json(claim))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def _audit_entry_hash(raw: dict[str, Any]) -> str:
    """Hash exactly the fields the recorded entry carries, as cMCP computed it.

    Rebuilding an ``AuditEntry`` would add fields introduced by later cMCP
    releases (for example ``effective_data_class``) and break the hash of every
    chain recorded before them.
    """
    body = {key: value for key, value in raw.items() if key != "entry_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _verify_audit_entries(entries: list[dict[str, Any]]) -> None:
    if not entries:
        raise BundleError("cMCP audit chain is empty")
    previous = "genesis"
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            raise BundleError("cMCP audit entry is not an object")
        if raw.get("sequence_number") != index or raw.get("prev_entry_hash") != previous:
            raise BundleError("cMCP audit chain linkage is invalid")
        if _audit_entry_hash(raw) != raw.get("entry_hash"):
            raise BundleError("cMCP audit entry hash is invalid")
        previous = raw["entry_hash"]


def build_live_experiment(
    dispatch: Callable[[dict[str, str]], None] | None = None,
    *,
    tee_provider: TEEProvider | None = None,
    trusted_amd_ark_pem: bytes | None = None,
    workload_signing_key: SigningKey | None = None,
    placement_assertion: dict[str, Any] | None = None,
    placement_trust_key: str | None = None,
    evidence_appraiser: Callable[[Any], AppraisalResult] | None = None,
    placement_factory: Callable[[Any, str], tuple[dict[str, Any], str]] | None = None,
) -> LiveExperimentResult:
    """Run actions with one identity bound across delegation, TEE, audit, and TRACE."""
    signing_key = workload_signing_key or SigningKey()
    audit = AuditChain("aucp-mve1-fr-health")
    provider = tee_provider or SoftwareOnlyProvider()
    nonce = make_audit_bound_nonce(signing_key.public_key_bytes, audit.chain_root)
    report = provider.get_attestation_report(nonce)
    audit.set_session_report(report)
    audit.set_tee_anchor(audit.chain_root)

    now = datetime.now(tz=UTC)
    if report.provider == "azure-cvm-sev-snp":
        if trusted_amd_ark_pem is None:
            raise BundleError("Azure CVM appraisal requires a pinned AMD ARK")
        verification = verify_azure_cvm_measurement(
            report.measurement,
            report.raw_evidence,
            report.report_data,
            trusted_amd_ark_pem,
        )
        if not verification.verified or verification.unverified_fields:
            reason = verification.failure_reason or ",".join(verification.unverified_fields)
            raise BundleError(f"Azure CVM evidence did not fully verify: {reason}")
        appraisal = AppraisalResult(
            status="affirming",
            verifier="urn:agentrust:verifier:cmcp-azure-cvm",
            timestamp=now.isoformat(),
            ear_raw={
                "status": "affirming",
                "verified_fields": verification.verified_fields,
                "details": verification.details,
            },
        )
    elif evidence_appraiser is not None:
        appraisal = evidence_appraiser(report)
        if appraisal.status != "affirming":
            raise BundleError("external hardware appraiser did not affirm the evidence")
    else:
        appraisal = AppraisalResult(
            status="warning",
            verifier="urn:agentrust:verifier:software-mve",
            timestamp=now.isoformat(),
            ear_raw={"status": "warning", "reason": "software-only-development-evidence"},
        )

    if placement_factory is not None:
        if placement_assertion is not None or placement_trust_key is not None:
            raise BundleError("placement factory cannot be combined with a placement assertion")
        placement_assertion, placement_trust_key = placement_factory(
            report, signing_key.public_key_hex
        )

    base_result = build_experiment(
        workload_public_key=signing_key.public_key_hex,
        attestation_report=report,
        evidence_appraisal=appraisal,
        placement_assertion=placement_assertion,
        placement_trust_key=placement_trust_key,
    )
    base = base_result.bundle
    context = VerifiedUsageContext.from_bundle(base, base_result.trust_anchors)
    bundle = _policy_bundle(context)
    config = Config()
    config.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    evaluator = PolicyEvaluator(bundle, config)

    dispatched: list[str] = []
    result_by_action: dict[str, tuple[str, str, str]] = {}

    for receipt in base["receipts"]:
        action = receipt["action"]
        call_id = action["action_id"]
        request_hash = _digest(action)
        try:
            decision = evaluator.evaluate(
                {
                    "agent_id": context.leaf_workload_key,
                    "tool_name": action["destination"],
                    "resource": action["destination"],
                    "session_max_sensitivity": "health.phi",
                    "workflow_id": context.workflow_id,
                    "aucp_agreement_hash": context.agreement_hash,
                    "aucp_authority_chain_hash": context.authority_chain_hash,
                    "aucp_appraisal_hash": context.appraisal_hash,
                }
            )
            if not decision.allowed:
                raise BundleError("cMCP returned a non-allow decision without denying")
            if dispatch is not None:
                dispatch(action)
            dispatched.append(call_id)
            policy_decision, dispatch_state = "allow", "dispatched"
            rule = decision.rule_matched or "cedar-permit"
        except PolicyDeny as exc:
            policy_decision, dispatch_state = "deny", "not_dispatched"
            rule = str(exc)

        entry = audit.append(
            "tool_call",
            call_id=call_id,
            tool_name=action["destination"],
            server_identity=action["destination"],
            policy_decision=policy_decision,
            policy_rule_matched=rule,
            request_payload_hash=request_hash,
            response_payload_hash=None,
            response_inspection_result="n/a",
            session_sensitivity_before="health.phi",
            session_sensitivity_after="health.phi",
            workflow_id=context.workflow_id,
            detail={"dispatch_state": dispatch_state},
        )
        result_by_action[call_id] = (policy_decision, dispatch_state, entry.entry_hash)

    if not audit.verify_chain():
        raise BundleError("cMCP audit chain failed its own verification")

    allowed_count = sum(1 for value in result_by_action.values() if value[0] == "allow")
    denied_count = sum(1 for value in result_by_action.values() if value[0] == "deny")
    transcript = [
        ToolTranscriptEntry(
            tool_name=entry.tool_name or "unknown",
            data_class="health.phi",
            decision=entry.policy_decision or "n/a",
        )
        for entry in audit.entries
        if entry.entry_type == "tool_call"
    ]
    trace = generate_trace_claim(
        session_id="aucp-mve1-fr-health",
        signing_key=signing_key,
        attestation_report=AttestationReportInfo(
            provider=report.provider,
            measurement=report.measurement,
            report_data=report.report_data,
            attestation_generated_at=report.attestation_generated_at.isoformat(),
            attestation_validity_seconds=report.attestation_validity_seconds,
            measurement_note=report.measurement_note,
            raw_evidence=(
                base64.b64encode(report.raw_evidence).decode()
                if report.raw_evidence is not None
                else None
            ),
            quote_signature=(
                base64.b64encode(report.quote_signature).decode()
                if report.quote_signature is not None
                else None
            ),
            cert_chain=(
                base64.b64encode(report.attestation_key_chain_pem).decode()
                if report.attestation_key_chain_pem is not None
                else None
            ),
        ),
        policy_bundle=PolicyBundleInfo(
            hash=bundle.bundle_hash,
            enforcement_mode="enforcing",
            policy_version=bundle.manifest.version,
        ),
        tool_catalog=ToolCatalogInfo(hash=_digest(sorted(context.destinations))),
        call_summary=CallSummary(
            tool_calls_total=len(result_by_action),
            tool_calls_allowed=allowed_count,
            tool_calls_denied=denied_count,
            tool_calls_faulted=0,
            tools_invoked=sorted({item["action"]["destination"] for item in base["receipts"]}),
            session_max_sensitivity="health.phi",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=["health.phi", "jurisdiction:FR"],
                cross_boundary_events=[],
                edges_represent="temporal-adjacency",
            ),
        ),
        audit_chain_root=audit.chain_root,
        audit_chain_tip=audit.chain_tip,
        audit_chain_length=audit.length,
        transcript_entries=transcript,
    ).model_dump(exclude_none=True)
    trace_hash = _digest(trace)

    adapter_key, adapter_public = new_keypair()
    bindings = []
    for receipt in base["receipts"]:
        action_id = receipt["action"]["action_id"]
        decision, dispatch_state, audit_hash = result_by_action[action_id]
        bindings.append(
            _sign(
                {
                    "type": "auc:CmcpEvidenceBinding",
                    "profile": "https://agentrust-io.com/profiles/aucp/v0.1/cmcp-mve1",
                    "workflow_id": context.workflow_id,
                    "action_id": action_id,
                    "usage_control_receipt_hash": _digest(receipt),
                    "cmcp_audit_entry_hash": "sha256:" + audit_hash,
                    "cmcp_trace_hash": trace_hash,
                    "cmcp_policy_bundle_hash": bundle.bundle_hash,
                    "decision": decision,
                    "dispatch_state": dispatch_state,
                },
                adapter_key,
            )
        )

    live_bundle = {
        "profile": "https://agentrust-io.com/profiles/aucp/v0.1/cmcp-mve1",
        "base_bundle": base,
        "verified_usage_context": asdict(context),
        "cmcp_policy": {"cedar": _cedar_policy(context), "bundle_hash": bundle.bundle_hash},
        "cmcp_audit_entries": [asdict(entry) for entry in audit.entries],
        "cmcp_trace": trace,
        "cmcp_trace_public_key": signing_key.public_key_hex,
        "adapter_bindings": bindings,
        "adapter_trust_key": adapter_public,
    }
    trust_anchors = LiveTrustAnchors(
        base=base_result.trust_anchors,
        cmcp_trace=signing_key.public_key_hex,
        adapter=adapter_public,
    )
    verify_live_bundle(live_bundle, trust_anchors)
    return LiveExperimentResult(live_bundle, tuple(dispatched), trust_anchors)


@_fail_closed_as_bundle_error
def verify_live_bundle(bundle: dict[str, Any], trust_anchors: LiveTrustAnchors) -> None:
    """Verify MVE-1 without evaluating Cedar or importing a cMCP runtime instance."""
    base = bundle.get("base_bundle")
    if not isinstance(base, dict):
        raise BundleError("live bundle has no base AUCP bundle")
    context = VerifiedUsageContext.from_bundle(base, trust_anchors.base)
    expected_context = json.loads(json.dumps(asdict(context)))
    actual_context = json.loads(json.dumps(bundle.get("verified_usage_context")))
    if actual_context != expected_context:
        raise BundleError("verified usage context does not reproduce")

    entries = bundle.get("cmcp_audit_entries")
    if not isinstance(entries, list):
        raise BundleError("live bundle has no cMCP audit entries")
    _verify_audit_entries(entries)
    tool_calls = [entry for entry in entries if entry["entry_type"] == "tool_call"]
    tool_entries = {entry["call_id"]: entry for entry in tool_calls}
    receipt_ids = {receipt["action"]["action_id"] for receipt in base["receipts"]}
    # Every dispatch the gateway recorded must be covered by exactly one AUCP
    # receipt; a repeated or unreceipted tool call is an unaccounted action.
    if len(tool_entries) != len(tool_calls) or set(tool_entries) != receipt_ids:
        raise BundleError("cMCP audit tool calls do not match the AUCP receipts one to one")

    trace = bundle.get("cmcp_trace")
    public_key = bundle.get("cmcp_trace_public_key")
    if not isinstance(trace, dict) or not isinstance(public_key, str):
        raise BundleError("live bundle has no signed cMCP TRACE record")
    if public_key != trust_anchors.cmcp_trace:
        raise BundleError("cMCP TRACE key does not match its out-of-band trust anchor")
    if not _trace_signature_valid(trace, public_key):
        raise BundleError("cMCP TRACE signature is invalid")
    gateway = trace["gateway"]
    if gateway["audit_chain"]["root"] != entries[0]["entry_hash"]:
        raise BundleError("TRACE root does not bind the cMCP audit chain")
    if gateway["audit_chain"]["tip"] != entries[-1]["entry_hash"]:
        raise BundleError("TRACE tip does not bind the cMCP audit chain")
    if gateway["audit_chain"]["length"] != len(entries):
        raise BundleError("TRACE length does not bind the cMCP audit chain")
    policy_hash = bundle["cmcp_policy"]["bundle_hash"]
    if trace["trace"]["policy"]["bundle_hash"] != policy_hash:
        raise BundleError("TRACE policy hash does not bind the live Cedar bundle")
    report_data_hex = base["appraisal"]["attestation"]["report_data"]
    report_data = bytes.fromhex(report_data_hex)
    if report_data[:32] != jwk_thumbprint(bytes.fromhex(public_key)):
        raise BundleError("attestation does not bind the TRACE signing key")
    if report_data[32:64] != audit_root_commitment(entries[0]["entry_hash"]):
        raise BundleError("attestation does not bind the cMCP audit root")
    if context.leaf_workload_key != public_key:
        raise BundleError("delegation leaf does not bind the TRACE signing key")
    runtime = trace["trace"]["runtime"]
    runtime_nonce = runtime.get("nonce")
    hardware_attested = base["appraisal"]["hardware_attested"] is True
    # The TRACE record is signed by the workload itself, so its platform claim is
    # only accepted when it agrees with the independently signed appraisal.
    if (runtime.get("platform") != "software-only") != hardware_attested:
        raise BundleError("TRACE runtime platform contradicts the signed appraisal")
    if hardware_attested:
        if not isinstance(runtime_nonce, str):
            raise BundleError("hardware TRACE record has no attestation nonce")
        decoded_nonce = base64.urlsafe_b64decode(runtime_nonce + "=" * (-len(runtime_nonce) % 4))
        if decoded_nonce != report_data:
            raise BundleError("TRACE nonce disagrees with the appraised hardware report")

    bindings = bundle.get("adapter_bindings")
    if not isinstance(bindings, list) or len(bindings) != len(base["receipts"]):
        raise BundleError("live bundle has incomplete adapter bindings")
    if bundle.get("adapter_trust_key") != trust_anchors.adapter:
        raise BundleError("adapter key does not match its out-of-band trust anchor")
    by_action = {binding["action_id"]: binding for binding in bindings}
    trace_hash = _digest(trace)
    for receipt in base["receipts"]:
        action_id = receipt["action"]["action_id"]
        binding = by_action.get(action_id)
        entry = tool_entries.get(action_id)
        if binding is None or entry is None:
            raise BundleError("action is missing its cMCP evidence join")
        _verify_signed(binding, trust_anchors.adapter)
        expected_dispatch = entry.get("detail", {}).get("dispatch_state")
        expected = {
            "usage_control_receipt_hash": _digest(receipt),
            "cmcp_audit_entry_hash": "sha256:" + entry["entry_hash"],
            "cmcp_trace_hash": trace_hash,
            "cmcp_policy_bundle_hash": policy_hash,
            "decision": entry["policy_decision"],
            "dispatch_state": expected_dispatch,
        }
        for field, value in expected.items():
            if binding.get(field) != value:
                raise BundleError(f"cMCP binding {field} does not match evidence")
        if receipt["decision"] != entry["policy_decision"]:
            raise BundleError("cMCP decision disagrees with the AUCP oracle")
        if receipt["dispatch_state"] != expected_dispatch:
            raise BundleError("cMCP dispatch state disagrees with the AUCP oracle")


def write_live_bundle(path: str, trust_anchors_path: str | None = None) -> LiveExperimentResult:
    """Generate, verify, and write an MVE-1 live-adapter evidence bundle."""
    result = build_live_experiment()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result.bundle, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if trust_anchors_path is not None:
        with open(trust_anchors_path, "w", encoding="utf-8") as handle:
            json.dump(asdict(result.trust_anchors), handle, indent=2, sort_keys=True)
            handle.write("\n")
    return result
