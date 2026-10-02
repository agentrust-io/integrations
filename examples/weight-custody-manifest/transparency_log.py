"""Transparency log: inclusion, consistency, and detecting a suppressed revocation.

    python transparency_log.py

Real WCM code, no hardware. WCM anchors manifests and revocations in an
append-only Merkle log (RFC 9162), so an operator cannot quietly serve a revoked
model or fork the history. This shows the three checks a monitor relies on:
an inclusion proof (an entry really is in the log), a consistency proof (the log
only ever appended, never rewrote), and a signed tree head (the log operator
actually vouched for this state). Then it shows the point of it all: a revocation
that is in the log cannot be hidden, and a forked log fails consistency.
"""
from __future__ import annotations

import hashlib

from wcm import (
    EntryType,
    TransparencyLog,
    generate_ed25519,
    verify_inclusion,
    verify_log_consistency,
    verify_sth,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def main() -> int:
    log_kp = generate_ed25519()
    log = TransparencyLog(log_kp)

    rule("Step 1 - Append two manifests; take a signed tree head")
    m1 = {"weights_hash": sha256(b"model-1"), "status": "in-force"}
    m2 = {"weights_hash": sha256(b"model-2"), "status": "in-force"}
    i1 = log.append(m1, entry_type=EntryType.manifest)
    i2 = log.append(m2, entry_type=EntryType.manifest)
    size1 = log.size
    sth1 = log.signed_tree_head()
    print("appended at indices    :", i1, i2, " log size:", log.size)
    print("STH signature valid    :", verify_sth(sth1, log_kp.public_bytes))

    rule("Step 2 - Inclusion proof: manifest 1 really is in the log")
    proof = log.inclusion_proof(i1)
    print("inclusion of m1 verifies:", verify_inclusion(m1, EntryType.manifest, proof, sth1))
    # A statement that was never logged does not verify against the same proof slot.
    forged = {"weights_hash": sha256(b"never-logged"), "status": "in-force"}
    print("inclusion of a forgery  :", verify_inclusion(forged, EntryType.manifest, proof, sth1))

    rule("Step 3 - Revoke model 1; the log only grows")
    rev = {"weights_hash": m1["weights_hash"], "reason": "safety-recall"}
    i3 = log.append(rev, entry_type=EntryType.revocation)
    sth2 = log.signed_tree_head()
    print("revocation appended at :", i3, " new size:", log.size)

    rule("Step 4 - Consistency proof: the new log is an append-only extension")
    cproof = log.consistency_proof(size1)
    print("old->new is consistent  :", verify_log_consistency(sth1, sth2, cproof))

    rule("Step 5 - A suppressed revocation is detectable")
    # The operator would love to serve model 1 as if it were never revoked. But the
    # revocation is in the append-only log, and a monitor can find it.
    found_at = log.find(rev, entry_type=EntryType.revocation)
    print("monitor finds the revocation at index:", found_at, "(cannot be hidden)")
    # And a revocation that a party CLAIMS but never logged simply is not there,
    # so 'I revoked it' is only credible if it is in the transparency log.
    unlogged = {"weights_hash": m2["weights_hash"], "reason": "claimed-but-not-logged"}
    print("an unlogged revocation claim ->      :", log.find(unlogged, entry_type=EntryType.revocation),
          "(not in the log, so not provable)")
    print()
    print("A forked or rewritten log would fail the Step 4 consistency check, so the")
    print("operator cannot both keep serving and pretend the revocation never happened.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
