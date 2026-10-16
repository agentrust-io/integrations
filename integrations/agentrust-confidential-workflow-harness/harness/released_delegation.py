"""Released cA2A 0.4.0 holder-bound delegation check.

The verifier's root is explicitly supplied by the caller. It is NOT enrolled
with a remote independently controlled peer. The signed delegation and
holder proof are independently checked by the published runtime.
"""
from dataclasses import dataclass
from ca2a_runtime.delegation import build_holder_proof
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.peer import PeerRequest, handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.challenge import generate_secret, issue_challenge
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


@dataclass(frozen=True)
class DelegationDecision:
    granted: bool
    reason: str
    record_id: str


def appraise(*, credential: DelegationCredential, holder_private,
             trusted_issuer: str, record_id: str,
             capability: str = "conduit.inspect",
             local_capabilities=frozenset({"conduit.inspect"}),
             challenge_secret=None,
             holder_proof=None) -> DelegationDecision:
    if not record_id or not trusted_issuer:
        return DelegationDecision(False, "missing-context", record_id)
    # The challenge and audience are bound to a single local verifier occurrence.
    # Supplying proof overrides is intended for negative tests; other callers
    # must generate their proof for this verifier's challenge themselves.
    if challenge_secret is None:
        challenge_secret = generate_secret()
    challenge = issue_challenge(challenge_secret)
    channel = X25519PrivateKey.generate()
    audience = channel.public_key().public_bytes_raw().hex()
    try:
        if holder_proof is None:
            holder_proof = build_holder_proof(
            holder_private, credential, audience=audience,
            challenge=challenge, requested_capability=capability,
                record_id=record_id)
    except Exception as exc:
        return DelegationDecision(False, type(exc).__name__, record_id)
    request = PeerRequest([credential], capability, record_id, holder_proof=holder_proof)
    try:
        result = handle_peer_request(
            request, policy=LocalPolicy(frozenset(local_capabilities)),
            trusted_root_issuers={trusted_issuer},
            require_holder_proof=True,
            challenge_secret=challenge_secret, audience=audience)
        return DelegationDecision(
            result.granted_capability == capability,
            "released-ca2a-holder-and-delegation-verified", record_id)
    except Exception as exc:
        return DelegationDecision(False, type(exc).__name__, record_id)
