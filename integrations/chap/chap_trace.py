"""CHAP review decisions as TRACE `approval-outcome` references.

A TRACE Trust Record points at the human decision a run was taken under through a
`references` entry (trace-spec v0.2 section 3.1.2). This module builds that entry from
a CHAP `audit.read` entry, and checks one against a CHAP audit log.

It imports nothing from CHAP. The digest is SHA-256 over the RFC 8785 form of the
decision envelope, and the chain replay follows CHAP `audit-scitt/1.0`, so a relying
party can run the check with only the exported log.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

import rfc8785

REL = "approval-outcome"
ZERO_HASH = "sha256:" + "0" * 64
_ID_PREFIX = "audit/"

CONFIRMED = "approval-confirmed"
CONTRADICTED = "approval-contradicted"
NOT_AN_APPROVAL = "not-an-approval"
UNCONFIRMED = "approval-unconfirmed"


def envelope_digest(envelope: Mapping) -> str:
    """SHA-256 of the RFC 8785 form of a CHAP envelope, in CHAP's `sha256:<hex>` form."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(envelope)).hexdigest()


def _approvals(accept_override: bool) -> frozenset[str]:
    return frozenset({"decide.approve", "decide.override"} if accept_override
                     else {"decide.approve"})


def approval_reference(entry: Mapping, resolver: str, *, retention: str | None = None,
                       accept_override: bool = False) -> dict:
    """Build the `references` entry citing one CHAP approval.

    Refuses anything that is not an approval: a producer citing a `decide.reject`
    as `approval-outcome` would be making a false statement it signs. Refuses an
    empty `resolver`, which section 3.1.2 rule 4 tells a producer to omit.
    """
    method = entry["envelope"].get("method")
    if method not in _approvals(accept_override):
        raise ValueError(f"audit entry {entry.get('seq')} is {method!r}, not an approval")
    if not isinstance(resolver, str) or not resolver:
        raise ValueError("resolver must name the party obliged to keep the entry resolvable")
    reference = {"rel": REL, "id": f"{_ID_PREFIX}{entry['seq']}", "resolver": resolver,
                 "digest": envelope_digest(entry["envelope"])}
    if retention is not None:
        reference["retention"] = retention
    return reference


def chain_replays(entries: Iterable[Mapping], chain_head: str) -> bool:
    """Replay a CHAP audit-scitt/1.0 chain: link = sha256(JCS(envelope) || prev_hash).

    Every entry's stored `prev_hash` has to equal the running hash, and the final
    link has to equal `chain_head`. Without the head comparison the last entry is
    covered by nothing.
    """
    running = ZERO_HASH
    for entry in entries:
        if entry.get("prev_hash") != running:
            return False
        running = "sha256:" + hashlib.sha256(
            rfc8785.dumps(entry["envelope"]) + running.encode("utf-8")).hexdigest()
    return running == chain_head


@dataclass(frozen=True)
class ApprovalCheck:
    """What a relying party can conclude about the approval a reference points at."""

    verdict: str
    reference_resolves: bool
    digest_matches: bool | None
    decision: str | None
    chain_replays: bool


def check_approval(reference: Mapping, entries: list[Mapping], chain_head: str, *,
                   accept_override: bool = False) -> ApprovalCheck:
    """Check an `approval-outcome` reference against an exported CHAP audit log.

    The four verdicts are distinct answers, and a caller should not collapse them:
    `approval-unconfirmed` (no entry at that position) is not the same statement as
    `not-an-approval` or `approval-contradicted`.
    """
    if reference.get("rel") != REL:
        raise ValueError(f"reference rel is {reference.get('rel')!r}, not {REL!r}")
    ref_id = reference.get("id", "")
    if not isinstance(ref_id, str) or not ref_id.startswith(_ID_PREFIX) \
            or not ref_id[len(_ID_PREFIX):].isdigit():
        raise ValueError(f"reference id {ref_id!r} is not of the form audit/<seq>")
    seq = int(ref_id[len(_ID_PREFIX):])
    chain = chain_replays(entries, chain_head)
    entry = next((e for e in entries if e.get("seq") == seq), None)
    if entry is None:
        return ApprovalCheck(UNCONFIRMED, False, None, None, chain)
    digest_matches = envelope_digest(entry["envelope"]) == reference.get("digest")
    decision = entry["envelope"].get("method")
    if not (digest_matches and chain):
        verdict = CONTRADICTED
    elif decision not in _approvals(accept_override):
        verdict = NOT_AN_APPROVAL
    else:
        verdict = CONFIRMED
    return ApprovalCheck(verdict, True, digest_matches, decision, chain)
