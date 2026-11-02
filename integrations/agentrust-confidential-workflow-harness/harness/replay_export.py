"""Offline verification of a remote peer's signed software evidence packet.

The peer is identified only by keys enrolled OUTSIDE the packet. This validates
software signatures and claim binding, not that the operator is independent or
that confidential execution or hardware attestations occurred.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from harness.trace_live_binding import verify_bundle

SCHEMA = "frequency-ca2a-trace-replay-packet/1"


def make_packet(*, transaction_id, nonce, request_sha256, repo,
                peer_public_key, trusted_issuer, trace_bundle, execution):
    return {
        "schema": SCHEMA,
        "transaction_id": transaction_id,
        "nonce": nonce,
        "request_sha256": request_sha256,
        "repo": repo,
        "peer_public_key": peer_public_key,
        "trusted_issuer": trusted_issuer,
        "trace_bundle": trace_bundle,
        "execution": execution,
        "origin_ca2a_verification": "passed-in-process-not-exportable",
        "evidence_class": "live-software-two-host-same-operator",
    }


def verify_packet(packet: dict, *, trace_public_key: str,
                  trusted_issuer: str, peer_public_key: str) -> dict:
    if not isinstance(packet, dict) or set(packet) != {
        "schema", "transaction_id", "nonce", "request_sha256", "repo",
        "peer_public_key", "trusted_issuer", "trace_bundle", "execution",
        "origin_ca2a_verification", "evidence_class"}:
        raise ValueError("malformed-replay-packet")
    if (packet["schema"] != SCHEMA or
        packet["trusted_issuer"] != trusted_issuer or
        packet["peer_public_key"] != peer_public_key or
        packet["evidence_class"] != "live-software-two-host-same-operator" or
        packet["origin_ca2a_verification"] != "passed-in-process-not-exportable"):
        raise ValueError("replay-trust-or-evidence-class-mismatch")
    if not isinstance(packet["execution"], dict):
        raise ValueError("malformed-execution-evidence")
    e=packet["execution"]
    if (e.get("exit_code") != 0 or
        not isinstance(e.get("session_id"), str) or
        any(not isinstance(e.get(field),str) or len(e[field]) != 64 or
            any(c not in "0123456789abcdef" for c in e[field])
            for field in ("start_receipt_hash","finish_receipt_hash"))):
        raise ValueError("bad-execution-claim")
    pk=Ed25519PublicKey.from_public_bytes(bytes.fromhex(trace_public_key))
    record_hash=verify_bundle(
        packet["trace_bundle"], public_key=pk,
        transaction_id=packet["transaction_id"],
        nonce=packet["nonce"],
        request_sha256=packet["request_sha256"],
        repo=packet["repo"], execution=e,
        trusted_issuer=trusted_issuer, max_age_seconds=None)
    return {
        "verified": True,
        "record_hash": record_hash,
        "manifest_binding": "valid",
        "signed_by": trace_public_key,
        "assurance": "software-only",
        "independent_custody": False,
        "hardware_attested": False,
        "origin_response_authentication": "not-offline-replayable",
        "peer_channel_binding": "metadata-only-not-signed",
        "freshness": "historical-signature-only-not-current",
    }
