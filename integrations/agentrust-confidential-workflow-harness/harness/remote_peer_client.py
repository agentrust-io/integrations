"""Live SSH-constrained released-cA2A request/response with caller-side cMCP.

The responder independently enforces delegation and holder binding. Transport
is an existing pinned-host-key SSH connection; the response is authenticated
by ca2a-runtime 0.4.0. This remains software-only, same-operator evidence.
"""
import hashlib
import json
import subprocess
from dataclasses import dataclass

from ca2a_runtime.attestation import VerifiedPeer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from harness.trace_live_binding import verify_bundle
from harness.replay_export import make_packet
from ca2a_runtime.delegation import build_holder_proof
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.response import PendingResponse, decode, encode
from ca2a_runtime.errors import CA2AError
from cmcp_runtime.runtime_gateway import GovernancePolicy, MCPGateway

CAPABILITY = "conduit.inspect"
SCHEMA = "frequency-ca2a-peer/1"


@dataclass(frozen=True)
class LivePeerResult:
    outcome: str
    transaction_id: str
    request_sha256: str | None = None
    start_receipt_hash: str | None = None
    finish_receipt_hash: str | None = None
    evidence_class: str = "live-software-two-host-same-operator"
    peer_assurance: str = "none"
    remote_ca2a_verified: bool = False
    trace_verified: bool = False
    trace_record_hash: str | None = None


def ssh_sender(host: str, key_path: str, *, timeout=20):
    if not host or not key_path:
        raise ValueError("pinned SSH endpoint and key required")

    def send(request):
        proc = subprocess.run([
            "ssh", "-F", "/dev/null", "-T",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=6", "-o", "ClearAllForwardings=yes",
            "-o", "IdentitiesOnly=yes",
            "-i", key_path, "ubuntu@" + host, "frequency-ca2a-peer",
        ], input=encode(request), stdout=subprocess.PIPE,
           stderr=subprocess.PIPE, timeout=timeout, check=False)
        if proc.returncode != 0 or len(proc.stdout) > 131072:
            raise RuntimeError("ssh-peer-failed-or-too-large")
        response = json.loads(proc.stdout)
        if not isinstance(response, dict):
            raise ValueError("invalid-peer-response")
        return response

    return send


def run(*, transaction_id: str, nonce: str, repo: str, issuer_private,
        holder_private, peer_public_key: str, send,
        permitted: bool = True, trace_public_key: str | None = None,
        evidence_sink=None) -> LivePeerResult:
    if not transaction_id or not nonce or not peer_public_key:
        return LivePeerResult("invalid-context", transaction_id)
    if not trace_public_key:
        return LivePeerResult("missing-trace-trust-anchor", transaction_id)
    gateway = MCPGateway(GovernancePolicy(
        allowed_tools=[CAPABILITY] if permitted else [], max_tool_calls=1))
    allowed, _ = gateway.intercept_tool_call("frequency-peer-origin",
                                           CAPABILITY, {
                                               "transaction_id": transaction_id,
                                               "nonce": nonce, "repo": repo})
    if not allowed:
        return LivePeerResult("refused-cmcp", transaction_id)
    pending = None
    try:
        hello = send({"schema": SCHEMA, "method": "challenge"})
        if (hello.get("status") != 200 or
                hello.get("peer_public_key") != peer_public_key or
                hello.get("assurance") != "none" or
                hello.get("capability") != CAPABILITY):
            return LivePeerResult("refused-peer-identity", transaction_id)
        challenge = hello["challenge"]
        pending = PendingResponse(VerifiedPeer(peer_public_key, "none", "software"),
            {"transaction_id": transaction_id, "nonce": nonce, "repo": repo,
             "capability": CAPABILITY}, timeout=20)
        issuer_pub = issuer_private.public_key().public_bytes_raw().hex()
        holder_pub = holder_private.public_key().public_bytes_raw().hex()
        credential = DelegationCredential(
            credential_id="transaction:" + transaction_id, issuer=issuer_pub,
            subject=holder_pub, scope=frozenset({CAPABILITY}), depth=0).sign(issuer_private)
        envelope = decode(pending.request_bytes)
        record_id = hashlib.sha256(encode(envelope)).hexdigest()
        proof = build_holder_proof(holder_private, credential,
            audience=peer_public_key, challenge=challenge,
            requested_capability=CAPABILITY, record_id=record_id)
        response = send({"schema": SCHEMA, "method": "execute",
                         "envelope": envelope,
                         "credential": {**credential.body(), "signature": credential.signature},
                         "holder_proof": proof.to_dict()})
        status = response["status"]
        verified = pending.verify(status, encode(response["envelope"]))
        if status == 403:
            return LivePeerResult("refused-authenticated-peer", transaction_id,
                                  verified.request_sha256, remote_ca2a_verified=False)
        if status != 200:
            return LivePeerResult("unknown-authenticated-execution", transaction_id,
                                  verified.request_sha256, remote_ca2a_verified=False)
        body = verified.body
        execution = body.get("execution")
        if (body.get("transaction_id") != transaction_id or
                body.get("nonce") != nonce or
                body.get("repo") != repo or
                body.get("capability") != CAPABILITY or
                body.get("assurance") != "software-only" or
                not isinstance(execution, dict) or
                execution.get("exit_code") != 0 or
                not isinstance(execution.get("start_receipt_hash"), str) or
                not isinstance(execution.get("finish_receipt_hash"), str)):
            return LivePeerResult("refused-output-binding", transaction_id,
                                  verified.request_sha256)
        trace_hash = None
        if trace_public_key is not None:
            try:
                trace_hash = verify_bundle(
                    body.get("trace_bundle"),
                    public_key=Ed25519PublicKey.from_public_bytes(
                        bytes.fromhex(trace_public_key)),
                    transaction_id=transaction_id, nonce=nonce,
                    request_sha256=verified.request_sha256,
                    repo=repo, execution=execution,
                    trusted_issuer=issuer_pub)
            except Exception:
                return LivePeerResult("untrusted-trace-evidence", transaction_id,
                    verified.request_sha256, remote_ca2a_verified=True)
        if evidence_sink is not None:
            try:
                evidence_sink(make_packet(
                    transaction_id=transaction_id, nonce=nonce,
                    request_sha256=verified.request_sha256,
                    repo=repo, peer_public_key=peer_public_key,
                    trusted_issuer=issuer_pub,
                    trace_bundle=body["trace_bundle"], execution=execution))
            except Exception:
                return LivePeerResult("unavailable-evidence-export", transaction_id,
                    verified.request_sha256, remote_ca2a_verified=True,
                    trace_verified=True, trace_record_hash=trace_hash)
        return LivePeerResult("authenticated-remote-ca2a-software", transaction_id,
                              verified.request_sha256,
                              execution["start_receipt_hash"],
                              execution["finish_receipt_hash"],
                              remote_ca2a_verified=True,
                              trace_verified=trace_hash is not None,
                              trace_record_hash=trace_hash)
    except (CA2AError, ValueError, TypeError, KeyError, OSError, RuntimeError,
            subprocess.TimeoutExpired):
        return LivePeerResult("unknown-or-refused-transport", transaction_id,
                              pending.request_sha256 if pending else None)
