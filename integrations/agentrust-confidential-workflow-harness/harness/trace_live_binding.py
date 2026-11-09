"""Software-only TRACE Level 0 record and separately signed execution manifest.

TRACE policy.bundle_hash identifies the actual local acceptance policy,
NOT an execution receipt. A companion signed manifest binds the request and
Conduit outcome to the TRACE record's digest without abusing TRACE fields.
The signer is a VPS software key pinned by the origin, not independent custody.
"""
import hashlib
import time

from cryptography.exceptions import InvalidSignature
from agentrust_trace import verify_record
from ca2a_runtime.response import encode
from ca2a_runtime.trace_binding import HopContext, HopSpec, emit_dag, trace_record_hash

CAPABILITY = "conduit.inspect"
SUBJECT = "did:example:frequency-ca2a-vps-software"
PROFILE = "frequency-ca2a-software-manifest/1"


def policy_digest(*, repo: str, trusted_issuer: str) -> str:
    policy = {"capability": CAPABILITY, "repo": repo,
              "trusted_issuer": trusted_issuer, "network_allowed": False,
              "peer_assurance": "none"}
    return "sha256:" + hashlib.sha256(encode(policy)).hexdigest()


def sign_bundle(*, key, transaction_id: str, nonce: str,
                request_sha256: str, execution: dict, repo: str,
                trusted_issuer: str) -> dict:
    policy_hash = policy_digest(repo=repo, trusted_issuer=trusted_issuer)
    ctx = HopContext.software(
        model_provider="frequency-software-only",
        model_id="conduit-inspect-no-model",
        image_label="unmeasured-software-peer-conduit-inspect",
        policy_bundle_hash=policy_hash,
        runtime_nonce=nonce)
    record = emit_dag([HopSpec(
        subject=SUBJECT, signing_key=key,
        context=ctx, iat=int(time.time()))])[0]
    manifest = {
        "schema": PROFILE,
        "trace_record_hash": trace_record_hash(record),
        "policy_bundle_hash": policy_hash,
        "transaction_id": transaction_id,
        "nonce": nonce,
        "request_sha256": request_sha256,
        "repo": repo,
        "capability": CAPABILITY,
        "execution": execution,
        "assurance": "software-only-same-operator",
    }
    signature = key.sign(encode(manifest)).hex()
    return {"record": record, "manifest": manifest, "signature": signature}


def verify_bundle(bundle: dict, *, public_key, transaction_id: str, nonce: str,
                  request_sha256: str, repo: str, execution: dict,
                  trusted_issuer: str,
                  max_age_seconds: int | None = 120) -> str:
    if not isinstance(bundle, dict) or set(bundle) != {"record","manifest","signature"}:
        raise ValueError("trace-bundle-format")
    record, manifest, signature = (
        bundle["record"], bundle["manifest"], bundle["signature"])
    if not isinstance(record, dict) or not isinstance(manifest, dict):
        raise ValueError("trace-bundle-type")
    expected_policy = policy_digest(repo=repo, trusted_issuer=trusted_issuer)
    digest = trace_record_hash(record)
    expected = {
        "schema": PROFILE,
        "trace_record_hash": digest,
        "policy_bundle_hash": expected_policy,
        "transaction_id": transaction_id,
        "nonce": nonce,
        "request_sha256": request_sha256,
        "repo": repo,
        "capability": CAPABILITY,
        "execution": execution,
        "assurance": "software-only-same-operator",
    }
    if manifest != expected or record.get("policy", {}).get("bundle_hash") != expected_policy:
        raise ValueError("trace-manifest-binding-mismatch")
    try:
        public_key.verify(bytes.fromhex(signature), encode(manifest))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("trace-manifest-signature-invalid") from exc
    # Pin the remote signing key: embedded cnf.jwk is NOT a trust root.
    verify_record(record, public_key, expected_nonce=nonce,
                  max_age_seconds=max_age_seconds)
    if record.get("subject") != SUBJECT or record.get("runtime", {}).get("platform") != "software-only":
        raise ValueError("unexpected-trace-claim")
    return digest
