"""Compose released cA2A holder authorization and cMCP remote Conduit admission.

Both authorization checks occur on the originating host before live dispatch.
This is NOT actual cA2A network transport or a remotely issued peer receipt.
"""
from dataclasses import dataclass
from harness.conduit_live import run as conduit_run
from harness.released_delegation import appraise


@dataclass(frozen=True)
class CompositionResult:
    outcome: str
    transaction_id: str
    start_hash: str | None = None
    finish_hash: str | None = None
    evidence_class: str = "software-two-host-same-operator"
    ca2a_peer_transport: bool = False
    trace_verification: bool = False


def run(*, transaction_id: str, repo: str, cli: str,
        credential, holder_private, trusted_issuer: str,
        transport=None) -> CompositionResult:
    decision = appraise(
        credential=credential, holder_private=holder_private,
        trusted_issuer=trusted_issuer, record_id=transaction_id)
    if not decision.granted:
        return CompositionResult("refused-ca2a-delegation", transaction_id)
    args = {"transaction_id": transaction_id, "repo": repo, "cli": cli}
    if transport is not None:
        args["transport"] = transport
    result = conduit_run(**args)
    return CompositionResult(result.outcome, transaction_id,
                             result.start_hash, result.finish_hash)
