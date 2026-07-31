"""Baseline sealing: is the thing we compare against still what we wrote?

The baseline is what every drift comparison is made against. An unsealed baseline
means anyone able to write it can add a component to the *approved* set, after
which the check reports "nothing added, nothing subtracted" indefinitely and
quietly. The evidence would share a fate with the adversary, which is the failure
this project exists to argue against.

A note on what this is, because the obvious design is worse than it looks. The
first version used an HMAC with a secret stored beside the baseline. A scanner
flagged the stored secret, and the flag was worth more than a suppression: the
only adversary an HMAC defeats here is one who can WRITE the state directory
without being able to READ it. On a developer machine that adversary is close to
fictional, since anything that can write your home directory can read it and would
simply retag. The secret bought almost no coverage while adding a credential to
leak and a claim inviting a reader to assume more protection than exists.

So: a bare digest. Same real coverage, nothing to steal. It catches corruption,
truncation and a hand-edit that does not recompute it. Neither a digest nor an
HMAC catches an attacker who owns the directory.

The control that does survive that attacker is off-box. `approve` prints the
digest, `verify` prints the digest of the baseline it read, and a human who
recorded the first sees a silent re-baseline. That is where the security lives, so
this module keeps the cheap local check and the engines point at the real one.
"""

from __future__ import annotations

from .hashing import now_iso, sha_mapping

__all__ = [
    "INTEGRITY_BROKEN",
    "INTEGRITY_OK",
    "INTEGRITY_UNSEALED",
    "SEAL_FIELD",
    "attach_seal",
    "check_seal",
    "state_digest",
]

#: Excluded from the digest it carries, since including it would be circular.
SEAL_FIELD = "integrity"

INTEGRITY_OK = "ok"
INTEGRITY_UNSEALED = "unsealed"  # no digest: written before sealing existed
INTEGRITY_BROKEN = "broken"      # digest present and wrong: edited outside the tool


def state_digest(snapshot: dict) -> str:
    """Digest of a snapshot's content, ignoring any seal it carries.

    Deterministic, so the value ``approve`` prints can be compared by eye against
    the value ``verify`` prints later.
    """
    return sha_mapping({k: v for k, v in snapshot.items() if k != SEAL_FIELD})


def attach_seal(snapshot: dict) -> dict:
    """Return a copy of ``snapshot`` sealed with a digest over its content."""
    return {**snapshot, SEAL_FIELD: {
        "alg": "SHA-256",
        "digest": state_digest(snapshot),
        "sealed_at": now_iso(),
    }}


def check_seal(snapshot: dict | None) -> str:
    """Recompute the seal and compare. Never raises.

    Catches accidental corruption, truncation, and a hand-edit that does not
    recompute the digest. Does not catch an attacker who owns the state directory,
    who can recompute it as easily as this function can.
    """
    if snapshot is None:
        return INTEGRITY_UNSEALED
    seal = snapshot.get(SEAL_FIELD)
    if not isinstance(seal, dict) or not isinstance(seal.get("digest"), str):
        return INTEGRITY_UNSEALED
    return INTEGRITY_OK if seal["digest"] == state_digest(snapshot) else INTEGRITY_BROKEN
