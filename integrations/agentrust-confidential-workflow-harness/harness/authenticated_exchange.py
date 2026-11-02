"""Bounded, in-process cMCP admission and cA2A authenticated-response exercise.

This is NOT network delivery, hardware attestation or independent verification.
The caller explicitly appraises a test-generated software key at assurance 'none'.
"""
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cmcp_runtime.runtime_gateway import MCPGateway, GovernancePolicy
from ca2a_runtime.attestation import VerifiedPeer
from ca2a_runtime.response import PendingResponse, ResponseProducer, decode, encode

@dataclass(frozen=True)
class ExchangeResult:
    outcome: str
    request_sha256: str | None = None
    observation: str = "synthetic-process-local"
    actual_dispatches: int = 0

def exchange(*, transaction_id: str, nonce: str, allowed: bool = True,
             tamper: bool = False, replay: bool = False,
             expired: bool = False, refusal: bool = False,
             binding_mismatch: bool = False, missing_receipt: bool = False) -> ExchangeResult:
    if not transaction_id or not nonce:
        return ExchangeResult("refused-missing-context")
    gateway = MCPGateway(GovernancePolicy(allowed_tools=["test-tool"] if allowed else []))
    ok, _ = gateway.intercept_tool_call("test-agent", "test-tool",
                                       {"transaction_id": transaction_id, "nonce": nonce})
    if not ok:
        return ExchangeResult("refused-authorization")
    key = X25519PrivateKey.generate()
    peer = VerifiedPeer(key.public_key().public_bytes_raw().hex(), "none", "synthetic")
    now = [10.0]
    pending = PendingResponse(peer, {"transaction_id": transaction_id, "nonce": nonce},
                              timeout=5.0, clock=lambda: now[0])
    producer = ResponseProducer(key, decode(pending.request_bytes))
    if missing_receipt:
        return ExchangeResult("unknown-unobserved-delivery", pending.request_sha256)
    if refusal:
        raw = encode(producer.finish(403, {"error": {"code": "denied"}}))
        try:
            verified = pending.verify(403, raw)
            return ExchangeResult("refused-authenticated", verified.request_sha256)
        except Exception:
            return ExchangeResult("unknown-verification-error", pending.request_sha256)
    body = {"accepted": True, "transaction_id": transaction_id, "nonce": nonce}
    if binding_mismatch:
        body["nonce"] = "wrong-" + nonce
    raw = encode(producer.finish(200, body))
    if tamper:
        altered = decode(raw)
        altered["body"]["nonce"] = "tampered"
        raw = encode(altered)
    if expired:
        now[0] = 16.0
    try:
        verified = pending.verify(200, raw)
        if verified.body.get("transaction_id") != transaction_id or verified.body.get("nonce") != nonce:
            return ExchangeResult("refused-response-binding", verified.request_sha256)
        if replay:
            try:
                pending.verify(200, raw)
            except Exception:
                return ExchangeResult("refused-replay", verified.request_sha256)
            return ExchangeResult("unsafe-replay-accepted", verified.request_sha256)
        return ExchangeResult("authenticated-process-local", verified.request_sha256)
    except Exception:
        return ExchangeResult("refused-response-authentication", pending.request_sha256)
