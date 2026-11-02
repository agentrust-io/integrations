"""Synthetic interoperability probe of released cMCP and cA2A APIs.

No tool is dispatched and no live or hardware assurance is claimed.
"""
from dataclasses import dataclass
from importlib.metadata import version
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cmcp_runtime.runtime_gateway import GovernancePolicy, MCPGateway
from ca2a_runtime.trace_binding import HopContext, HopSpec, emit_dag, trace_record_hash

@dataclass(frozen=True)
class ProbeResult:
    admitted: bool
    reason: str
    versions: dict[str, str]
    hashes: tuple[str, ...]
    evidence_class: str = "synthetic"
    actual_dispatches: int = 0

def probe(*, transaction_id: str, subject: str, tool_name: str,
          allowed_tools: tuple[str, ...], policy_digest: str, nonce: str) -> ProbeResult:
    versions = {"cmcp-runtime": version("cmcp-runtime"),
                "ca2a-runtime": version("ca2a-runtime")}
    if versions != {"cmcp-runtime":"0.7.0", "ca2a-runtime":"0.4.0"}:
        return ProbeResult(False, "unpinned-version", versions, ())
    if not transaction_id or not subject or not nonce or len(policy_digest) != 71 or not policy_digest.startswith("sha256:") or any(c not in "0123456789abcdef" for c in policy_digest[7:]):
        return ProbeResult(False, "invalid-context", versions, ())
    gateway = MCPGateway(GovernancePolicy(allowed_tools=list(allowed_tools), max_tool_calls=1))
    try:
        allowed, reason = gateway.intercept_tool_call(subject, tool_name, {"transaction_id":transaction_id, "nonce":nonce, "policy_digest":policy_digest})
    except Exception:
        return ProbeResult(False, "gateway-error", versions, ())
    if not allowed:
        return ProbeResult(False, reason, versions, ())
    ctx = HopContext.software(model_provider="synthetic", model_id="no-model-run",
        image_label="interoperability-probe", policy_bundle_hash=policy_digest,
        runtime_nonce=nonce)
    hops = [HopSpec(subject=f"{subject}:{transaction_id}", signing_key=Ed25519PrivateKey.generate(), context=ctx, iat=1),
            HopSpec(subject=f"peer:{transaction_id}", signing_key=Ed25519PrivateKey.generate(), context=ctx, iat=2, credential_id=f"test:{transaction_id}")]
    try:
        records = emit_dag(hops)
        hashes = tuple(trace_record_hash(record) for record in records)
    except Exception:
        return ProbeResult(False, "trace-api-error", versions, ())
    if len(hashes) != 2 or not all(hashes):
        return ProbeResult(False, "missing-evidence", versions, ())
    return ProbeResult(True, "published-apis-executed-only", versions, hashes)
