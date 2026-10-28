#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate vectors/vectors.json for the MUSUBI companion for cA2A, profile v0.

Every delegation credential and revocation statement here is built and signed by cA2A's own library
(ca2a_runtime.delegation), so the vectors also show that the profile takes cA2A objects unchanged.
Keys are derived from fixed labels, Ed25519 is deterministic, and the Bitcoin headers are regtest
difficulty headers mined by settle_v1_1's test chain, so running this twice gives the same bytes.
"""
import hashlib, json, os, sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.delegation.revocation import RevocationStatement, credential_digest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import companion_v0 as C   # noqa: E402
import settle_v1_1 as v11  # noqa: E402

# the test chain commits records by JCS, the profile's encoding
v11.commitment_digest = lambda r: hashlib.sha256(C.jcs(C.body_of(r, ("anchor",)))).digest()


def key(label):
    k = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"musubi-ca2a-v0/" + label.encode()).digest())
    return k, k.public_key().public_bytes_raw().hex()


R, R_PUB = key("root")
A, A_PUB = key("agent-a")
B, B_PUB = key("agent-b")
B2, B2_PUB = key("agent-b2")
X, X_PUB = key("responder-x")
Y, Y_PUB = key("responder-y")
O, O_PUB = key("operator")
Q, Q_PUB = key("other-root")
Z, Z_PUB = key("outsider")
LOG_ID = "nenrin:ca2a-companion:test"
T0 = 1700000100
AS_OF = 1700001000
LABEL = "ca2a"

# block 95 is mined the same way every time, so a receipt can name it as seen before the log exists
_pre = v11._Chain(95, "00" * 32, LABEL)
_pre.block()
SEEN = {"height": 95, "hash": _pre.hashes[95]}


def cred(cid, iss_k, iss, sub, scope, depth, parent, **kw):
    return DelegationCredential(credential_id=cid, issuer=iss, subject=sub, scope=frozenset(scope),
                                depth=depth, parent_id=parent, **kw).sign(iss_k)


def wire(c):
    d = c.body()
    d["signature"] = c.signature
    return d


C0 = cred("cred-0", R, R_PUB, A_PUB, {"read", "write", "pay"}, 0, None)
C1 = cred("cred-1", A, A_PUB, B_PUB, {"read", "pay"}, 1, "cred-0")
CHAIN = [C0, C1]


def lin(chain):
    return [credential_digest(c) for c in chain]


LIN = lin(CHAIN)


def request(occ, responder=X_PUB, caller=B_PUB, chain=CHAIN, capability="pay"):
    return {"type": C.T_REQUEST, "caller": caller, "responder": responder, "lineage": lin(chain),
            "capability": capability, "occurrence_id": occ, "task_sha256": C.sha256_hex(occ.encode())}


def rs(occ, **kw):
    return C.request_sha256(request(occ, **kw))


REQ1 = request("occ-1")
RS1, RS2 = rs("occ-1"), rs("occ-2")


def use(req_sha, chain=CHAIN, holder_k=B, holder=B_PUB, responder=X_PUB):
    return C.sign({"type": C.T_USE, "chain": [wire(c) for c in chain], "holder": holder,
                   "responder": responder, "request_sha256": req_sha}, holder_k)


def policy(max_uses, issuer_k=A, issuer=A_PUB, target=C1):
    return C.sign({"type": C.T_USE_POLICY, "credential_digest": credential_digest(target), "issuer": issuer,
                   "max_uses": max_uses}, issuer_k)


def receipt(req_sha, kind="result", stage="executed", chain=CHAIN, caller=B_PUB, resp_k=X, resp=X_PUB,
            capability="pay", seen=None):
    return C.sign({"type": C.T_RECEIPT, "responder": resp, "caller": caller, "lineage": lin(chain),
                   "capability": capability, "request_sha256": req_sha, "seen_block": seen or SEEN,
                   "outcome": {"kind": kind, "stage": stage,
                               "response_sha256": C.sha256_hex(("resp:" + req_sha).encode())
                               if kind == "result" else None},
                   "attestation_sha256": None}, resp_k)


def revocation(target, k, pub, issued_at):
    return RevocationStatement(revoked_digest=credential_digest(target), revoker=pub,
                               issued_at=issued_at).sign(k).to_dict()


PARTIES = sorted([X_PUB, B_PUB])
NONCE = C.sha256_hex(b"session-nonce-1")
SID = C.session_id_of(PARTIES, NONCE)


def commit(k, pub, evidence, salt, parties=PARTIES, nonce=NONCE):
    sid = C.session_id_of(parties, nonce)
    return C.sign({"type": C.T_COMMIT, "session_id": sid, "participants": parties, "session_nonce": nonce,
                   "committer": pub, "commitment": C.commitment_of(sid, pub, evidence, salt)}, k)


def reveal(k, pub, evidence, salt, sid=SID):
    return C.sign({"type": C.T_REVEAL, "session_id": sid, "committer": pub, "evidence_sha256": evidence,
                   "salt": salt}, k)


def build_log(items, as_of=AS_OF, times=None):
    items = json.loads(json.dumps(items))      # never share item objects between vectors
    entries, prev = [], None
    for i, it in enumerate(items):
        e = C.sign({"type": C.T_ENTRY, "log_id": LOG_ID, "operator": O_PUB, "seq": i, "prev": prev,
                    "logged_at": times[i] if times else T0 + 10 * i, "item": it}, O)
        entries.append(e)
        prev = C.entry_digest(e)
    cp = C.sign({"type": C.T_CHECKPOINT, "log_id": LOG_ID, "operator": O_PUB, "size": len(entries),
                 "head": prev, "as_of": as_of}, O)
    return entries, cp


def anchor(cp, depth=6):
    ch = v11._Chain(95, "00" * 32, LABEL)
    ch.block()
    assert ch.hashes[95] == SEEN["hash"]
    lb = {"kind": "bitcoin_block", "height": 95, "hash": ch.hashes[95]}
    [anchored] = ch.block([cp])
    for _ in range(depth - 1):
        ch.block()
    return anchored, ch.view(), lb


def trust(lb, roots=(R_PUB,), min_depth=6):
    return {"log_id": LOG_ID, "operator": O_PUB, "root_issuers": list(roots), "lower_bound": lb,
            "max_target_bits": "207fffff", "min_depth": min_depth}


def bundle(items, chains=(), requests=(), roots=(R_PUB,), min_depth=6, as_of=AS_OF, times=None,
           mutate=None):
    entries, cp = build_log(items, as_of=as_of, times=times)
    cp, view, lb = anchor(cp)
    b = {"profile": C.PROFILE, "trust": trust(lb, roots, min_depth), "view": view,
         "log": {"entries": entries, "checkpoint": cp}, "chains": [[wire(c) for c in ch] for ch in chains]}
    if requests:
        b["requests"] = list(requests)
    b = json.loads(C.jcs(b))
    if mutate:
        mutate(b)
    return b


VECTORS = []


def vec(vid, desc, b):
    VECTORS.append({"id": vid, "description": desc, "bundle": b,
                    "expected": json.loads(C.jcs(C.settle(b)))})


def main():
    base = [policy(1), use(RS1), receipt(RS1)]
    vec("CA01_within", "single-use credential, one logged use, one signed result receipt",
        bundle(base, requests=[REQ1]))
    vec("CA02_single_use_across_requests",
        "the same single-use credential used for a second request; cA2A alone cannot see this, its "
        "replay check is within one chain",
        bundle(base + [use(RS2), receipt(RS2)]))
    vec("CA03_duplicate_execution", "two result receipts for one request occurrence",
        bundle(base + [receipt(RS1, stage="executed-again")]))
    vec("CA04_published_revocation",
        "the delegator revokes the leaf, the revocation is logged before the execution",
        bundle([policy(1), use(RS1), revocation(C1, A, A_PUB, T0), receipt(RS1)]))
    vec("CA05_backdated_revocation",
        "a revocation logged after the execution but dated before it: cA2A's audit says revoked, the "
        "log says it was not public at execution",
        bundle(base + [revocation(C1, A, A_PUB, T0)]))
    vec("CA06_delegate_cannot_revoke", "the leaf's own subject revokes it; cA2A gives it no authority",
        bundle([policy(1), use(RS1), revocation(C1, B, B_PUB, T0), receipt(RS1)]))
    c1_esc = cred("cred-1", A, A_PUB, B_PUB, {"read", "pay", "admin"}, 1, "cred-0")
    vec("CA07_scope_escalation", "the chain widens scope at hop 1; cA2A's own verifier refuses",
        bundle([receipt(RS1, chain=[C0, c1_esc])], chains=[[C0, c1_esc]]))
    vec("CA08_untrusted_root", "the root issuer is not in the relying party's trust list",
        bundle([receipt(RS1)], chains=[CHAIN], roots=(Q_PUB,)))
    c1_exp = cred("cred-1", A, A_PUB, B_PUB, {"read", "pay"}, 1, "cred-0", not_after=T0 + 5)
    vec("CA09_expired_at_log_time", "the leaf expired before the receipt was logged",
        bundle([receipt(RS1, chain=[C0, c1_exp])], chains=[[C0, c1_exp]], times=[T0 + 60]))
    vec("CA10_caller_not_leaf", "the receipt names a caller who is not the leaf subject",
        bundle([policy(1), use(RS1), receipt(RS1, caller=A_PUB)]))
    vec("CA11_use_not_logged", "a use policy exists but no use was logged",
        bundle([policy(1), receipt(RS1)], chains=[CHAIN]))
    vec("CA12_use_logged_late", "the use was logged after the execution",
        bundle([policy(1), receipt(RS1), use(RS1)], chains=[CHAIN]))
    vec("CA13_chain_not_supplied", "no use and no chain for the lineage: unassessed, never guessed",
        bundle([receipt(RS1)]))
    forged = receipt(RS1)
    forged["outcome"] = dict(forged["outcome"], kind="ack", response_sha256=None)
    vec("CA14_receipt_altered", "the outcome was changed after the responder signed",
        bundle([policy(1), use(RS1), forged]))
    req9 = request("occ-9", responder=A_PUB)
    rs9 = C.request_sha256(req9)
    vec("CA15_request_mismatch", "the supplied request names another responder than the one who signed",
        bundle([use(rs9), receipt(rs9)], requests=[req9]))
    vec("CA16_denial_then_result", "a denial does not count as an execution",
        bundle([policy(1), use(RS1), receipt(RS1, kind="denial", stage="pre-execution"), receipt(RS1)]))

    def tamper_item(b):
        b["log"]["entries"][2]["item"]["outcome"]["stage"] = "rewritten"
    vec("CA17_log_entry_rewritten", "an entry changed after the operator signed it",
        bundle(base, mutate=tamper_item))

    def drop_entry(b):
        del b["log"]["entries"][1]
    vec("CA18_entry_withheld", "an entry removed from the log under an unchanged checkpoint",
        bundle(base, mutate=drop_entry))

    def resign_cp(b):
        cp = b["log"]["checkpoint"]
        a = cp["anchor"]
        cp2 = C.sign(dict(C.body_of(cp, ("anchor",)), as_of=cp["as_of"] - 1), O)
        cp2["anchor"] = a
        b["log"]["checkpoint"] = cp2
    vec("CA19_checkpoint_resigned_after_anchor", "the operator re-signs the checkpoint after it was anchored",
        bundle(base, mutate=resign_cp))
    vec("CA20_anchor_too_shallow", "the relying party wants more confirmations than the view shows",
        bundle(base, min_depth=10))
    vec("CA21_as_of_after_anchor", "the checkpoint claims a time later than its anchoring block allows",
        bundle(base, as_of=1700000000 + C.TIME_SLACK + 1))
    vec("CA22_revocation_dated_after_logging",
        "a revocation dated after it was logged is kept and flagged; logged before the execution, it is in "
        "force by log order, while cA2A's audit by issued_at does not see it",
        bundle([policy(1), use(RS1), revocation(C1, A, A_PUB, T0 + 999), receipt(RS1)]))
    ev_x, ev_b = C.sha256_hex(b"evidence-x"), C.sha256_hex(b"evidence-b")
    s1, s2 = C.sha256_hex(b"salt-x"), C.sha256_hex(b"salt-b")
    vec("CA23_commit_reveal_ok", "both participants commit, then both reveal",
        bundle([commit(X, X_PUB, ev_x, s1), commit(B, B_PUB, ev_b, s2),
                reveal(X, X_PUB, ev_x, s1), reveal(B, B_PUB, ev_b, s2)]))
    vec("CA24_reveal_before_commit", "one participant reveals before the other commits",
        bundle([commit(X, X_PUB, ev_x, s1), reveal(X, X_PUB, ev_x, s1),
                commit(B, B_PUB, ev_b, s2), reveal(B, B_PUB, ev_b, s2)]))
    vec("CA25_reveal_mismatch", "a reveal that does not open the commitment",
        bundle([commit(X, X_PUB, ev_x, s1), commit(B, B_PUB, ev_b, s2),
                reveal(X, X_PUB, ev_b, s1), reveal(B, B_PUB, ev_b, s2)]))
    vec("CA26_tightest_policy", "two policies, 3 and 1: the second use exceeds",
        bundle([policy(3), policy(1), use(RS1), receipt(RS1), use(RS2), receipt(RS2)]))
    vec("CA27_policy_by_non_issuer", "a policy signed by the leaf's subject is not a limit",
        bundle([policy(1, B, B_PUB), use(RS1), receipt(RS1), use(RS2), receipt(RS2)]))
    vec("CA28_ancestor_revoked", "the root revokes hop 0 before the execution",
        bundle([policy(1), use(RS1), revocation(C0, R, R_PUB, T0), receipt(RS1)]))
    c1_bad = wire(C1)
    c1_bad["signature"] = wire(C0)["signature"]

    def forge_chain(b):
        b["chains"] = [[wire(C0), c1_bad]]
    vec("CA29_chain_signature_forged", "hop 1 carries a signature that is not over its body",
        bundle([receipt(RS1)], mutate=forge_chain))
    vec("CA30_unknown_item", "an unknown item type is rejected by name and the rest settles",
        bundle([{"type": "example.unknown.v1", "x": 1}] + base))
    vec("CA31_same_use_logged_twice", "the same use logged twice counts once",
        bundle([policy(1), use(RS1), use(RS1), receipt(RS1)]))

    # found by an adversarial review on 2026-10-17, each now refused
    c2 = cred("cred-2", B, B_PUB, B2_PUB, {"pay"}, 2, "cred-1")
    ch2 = [C0, C1, c2]
    rs_b2 = rs("occ-b2", caller=B2_PUB, chain=ch2)
    vec("CA32_redelegation_does_not_reset_a_limit",
        "a single-use credential delegated onward: a use below it still counts against its limit",
        bundle([policy(1), use(RS1), receipt(RS1), use(rs_b2, chain=ch2, holder_k=B2, holder=B2_PUB),
                receipt(rs_b2, chain=ch2, caller=B2_PUB)]))
    vec("CA33_early_logged_revocation_still_applies",
        "the operator logs a revocation a few seconds before its issued_at; it is flagged, kept, and "
        "applies to a later execution",
        bundle([policy(5), use(RS1), revocation(C1, A, A_PUB, T0 + 15), receipt(RS1)],
               times=[T0, T0 + 5, T0 + 10, T0 + 500]))
    vec("CA34_hex_with_trailing_newline", "a request hash with a trailing newline is not lowercase hex",
        bundle([use(RS1), receipt(RS1), receipt(RS1 + "\n")]))
    vec("CA35_use_names_its_responder", "a second responder cannot execute on a use logged for the first",
        bundle([policy(1), use(RS1), receipt(RS1), receipt(RS1, resp_k=Y, resp=Y_PUB)], chains=[CHAIN]))

    def forged_copy_after(b):
        b["chains"] = [[wire(C0), wire(C1)], [wire(C0), c1_bad]]
    vec("CA36_forged_chain_copy_does_not_displace",
        "a second copy of the chain with a bad signature does not replace the one that verifies",
        bundle([receipt(RS1)], mutate=forged_copy_after))
    vec("CA37_policy_is_not_retroactive", "a policy logged after two executions does not judge them",
        bundle([use(RS1), receipt(RS1), use(RS2), receipt(RS2), policy(1)]))
    ev_z, s3 = C.sha256_hex(b"evidence-z"), C.sha256_hex(b"salt-z")
    vec("CA38_outsider_cannot_spoil_a_session",
        "a key outside the session's participants reveals late; it is ignored",
        bundle([commit(X, X_PUB, ev_x, s1), commit(B, B_PUB, ev_b, s2), reveal(X, X_PUB, ev_x, s1),
                reveal(B, B_PUB, ev_b, s2), reveal(Z, Z_PUB, ev_z, s3)]))
    vec("CA39_capability_not_in_scope", "the receipt's capability is not in the leaf's scope",
        bundle([use(RS1), receipt(RS1, capability="write")]))
    vec("CA40_logged_before_seen_block",
        "the operator dates the receipt more than two hours before the block the responder saw",
        bundle([receipt(RS1)], chains=[CHAIN], times=[1700000000 - C.TIME_SLACK - 1]))
    vec("CA41_seen_block_not_in_view", "the receipt names a block the view does not hold: unassessed",
        bundle([receipt(RS1, seen={"height": 95, "hash": "11" * 32})], chains=[CHAIN]))

    # second review, 2026-10-17
    vec("CA43_one_use_per_responder",
        "a single-use credential: the same request logged as used with two responders is two uses",
        bundle([policy(1), use(RS1), use(RS1, responder=Y_PUB), receipt(RS1), receipt(RS1, resp_k=Y, resp=Y_PUB)]))
    c0r = cred("cred-0", R, R_PUB, A_PUB, {"read", "write", "pay"}, 0, None, not_after=T0 + 10 ** 6)
    vec("CA44_reissued_ancestor_does_not_reset_a_limit",
        "the root re-issues hop 0 under the same credential_id; uses of hop 1 under either count together",
        bundle([policy(1), use(RS1), receipt(RS1), use(RS2, chain=[c0r, C1]), receipt(RS2, chain=[c0r, C1])]))
    vec("CA45_logged_revocation_in_force_whatever_its_date",
        "a revocation logged before the execution but dated after it is in force by log order; cA2A's "
        "audit by issued_at says otherwise and is reported beside it",
        bundle([policy(5), use(RS1), revocation(C1, A, A_PUB, T0 + 3000), receipt(RS1)],
               times=[T0, T0 + 5, T0 + 10, T0 + 600]))

    def bad_trust(b):
        b["trust"]["max_depth"] = "8"
    vec("CA42_malformed_trust_is_refused", "a malformed trust configuration is refused, not raised",
        bundle(base, mutate=bad_trust))

    # evidence vectors: operator equivocation is provable from signed objects, and only from them
    ev = []
    e1, cp1 = build_log(base, as_of=AS_OF)
    e2, cp2 = build_log(base + [receipt(RS2)], as_of=AS_OF + 10)
    alt = [policy(1), use(RS1), receipt(RS1, stage="other")]
    e3, cp3 = build_log(alt, as_of=AS_OF + 20)
    e3b, cp3b = build_log(alt + [receipt(RS2)], as_of=AS_OF + 20)
    e4, cp4 = build_log(base[:2], as_of=AS_OF + 30)

    def add(i, fn, args):
        args = json.loads(C.jcs(args))
        f = {"compare_checkpoints": C.compare_checkpoints, "check_promise": C.check_promise}[fn]
        ev.append({"id": i, "fn": fn, "args": args, "expected": f(*args)})
    add("EV01_consistent", "compare_checkpoints", [cp1, cp2, e2])
    add("EV02_equivocation_same_size", "compare_checkpoints", [cp1, cp3, e3])
    add("EV03_promise_kept", "check_promise", [e1[2], e2, cp2])
    add("EV04_promise_broken", "check_promise", [e1[2], e3, cp3])
    add("EV05_newer_checkpoint_smaller", "compare_checkpoints", [cp4, cp2, e2])
    add("EV06_fork_with_smaller_log_supplied", "compare_checkpoints", [cp1, cp3b, e1])
    add("EV07_fork_detected_in_either_order", "compare_checkpoints", [cp3b, cp1, e3b])
    e2_edit = json.loads(json.dumps(e2))
    e2_edit[0]["logged_at"] += 1
    add("EV08_edited_entries_do_not_frame", "compare_checkpoints", [cp1, cp2, e2_edit])
    zf = C.sign(dict(C.body_of(e1[0]), operator=Z_PUB), Z)
    add("EV09_entry_from_another_key", "check_promise", [zf, e2, cp2])
    add("EV10_entries_not_of_the_checkpoint", "check_promise", [e2[2], e2, cp3])
    late_cp = C.sign({"type": C.T_CHECKPOINT, "log_id": LOG_ID, "operator": O_PUB, "size": 2,
                      "head": C.entry_digest(e1[1]), "as_of": AS_OF + 10 ** 6}, O)
    add("EV11_withheld_entry", "check_promise", [e1[2], e1[:2], late_cp])
    deep = {"x": 1}
    for _ in range(80):
        deep = {"x": deep}
    add("EV12_deep_nesting_is_input_error", "check_promise", [dict(e1[2], item=deep), e1, cp1])
    out = {"profile": C.PROFILE,
           "note": "credentials and revocations signed by ca2a_runtime; headers are regtest difficulty",
           "vectors": VECTORS, "evidence": ev}
    os.makedirs(os.path.join(HERE, "vectors"), exist_ok=True)
    with open(os.path.join(HERE, "vectors", "vectors.json"), "wb") as f:
        f.write(C.jcs(out))
    for v in VECTORS:
        e = v["expected"]
        if "refused" in e:
            print(v["id"], "REFUSED", e["refused"])
            continue
        if not e["log"]["verified"]:
            print(v["id"], "LOG", e["log"]["problem"])
            continue
        rs_ = ["%s:%s%s" % (r["seq"], r["disposition"], r.get("reasons") and str(r["reasons"]) or "")
               for r in e["receipts"]]
        print(v["id"], rs_, e["items_rejected"] or "", e["items_flagged"] or "",
              [(s["simultaneous"], s["problems"]) for s in e["sessions"]] or "")
    for x in ev:
        print(x["id"], x["expected"])


if __name__ == "__main__":
    main()
