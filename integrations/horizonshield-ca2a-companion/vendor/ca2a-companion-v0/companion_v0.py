#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI companion for cA2A, profile v0: the evidence layer cA2A says it does not have.

cA2A (agentrust-io/ca2a) verifies a delegation chain and, when it is handed one, a revocation snapshot.
Its own documents name what is missing around that check, and this file supplies those parts without
changing a single cA2A object:

  gap                                                     what this profile adds
  revocations have no publication protocol, and a          an append-only log, every entry signed by its
  supplier can withhold a statement (revocation.py,        operator, checkpoints anchored in Bitcoin; an
  RevocationSnapshot docstring)                            entry the operator signed and later dropped,
                                                           changed or left out of a checkpoint that should
                                                           cover it is shown by operator signatures
  no global used-credential database, so no single use    credential-use items carrying their whole chain;
  across requests (failure-modes.md)                       a limit on a credential counts every use of it,
                                                           under any chain and with any responder
  the response MAC is live-caller only, does not sign      execution receipts signed with an Ed25519 key,
  the execution lineage and makes no third-party           naming the lineage, the capability, the request
  verifiable receipt (response-authentication.md)          occurrence and the outcome
  hash links alone let an attacker rewrite the            the log head is anchored, so a rewrite after the
  provenance path (provenance-dag.md)                      anchor is detectable
  simultaneous attestation needs a commitment step         commit and reveal items in a session whose id
  (ROADMAP)                                                binds its participants

The delegation rules are cA2A's. Every chain is judged by ca2a_runtime.delegation.verify_chain and cA2A's
own revocation check. The only rule added on top is ordering: a revocation logged before a receipt is in
force for it, whatever its issued_at says; cA2A's audit verdict, which goes by issued_at, is reported
beside it.

What this profile does NOT give: it does not show that a responder key lives in a TEE, that the appraised
workload is the one that signed, or that a claimed result is true. A receipt proves who asserted what, in
which order relative to other logged statements, no earlier than the block it names as seen and no later
than the block that anchors it. Times inside that window are the operator's.

Usage:
  companion_v0.py --selftest
  companion_v0.py --settle BUNDLE.json          (prints the settlement as canonical JSON)
"""
import argparse, hashlib, json, os, re, sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ca2a_runtime.errors import CA2AError
from ca2a_runtime.delegation.credential import DelegationCredential, verify_chain
from ca2a_runtime.delegation.credential import _check_revocation as ca2a_check_revocation
from ca2a_runtime.delegation.revocation import (
    REVOCATION_TYPE, RevocationSnapshot, RevocationStatement, credential_digest)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import settle_v1_1 as v11  # noqa: E402  (Bitcoin header view and anchor proof, reused unchanged)

PROFILE = "musubi.ca2a.companion.v0"
T_ENTRY = "musubi.ca2a.log-entry.v0"
T_CHECKPOINT = "musubi.ca2a.checkpoint.v0"
T_USE_POLICY = "musubi.ca2a.use-policy.v0"
T_USE = "musubi.ca2a.credential-use.v0"
T_RECEIPT = "musubi.ca2a.execution-receipt.v0"
T_REQUEST = "musubi.ca2a.request.v0"
T_SESSION = "musubi.ca2a.session.v0"
T_COMMIT = "musubi.ca2a.commit.v0"
T_REVEAL = "musubi.ca2a.reveal.v0"
T_PREIMAGE = "musubi.ca2a.commitment-preimage.v0"
T_SETTLEMENT = "musubi.ca2a.settlement.v0"

# fullmatch everywhere: "$" would also match before a trailing newline, and bytes.fromhex skips it
HEX32 = re.compile(r"[0-9a-f]{64}")
HEX64 = re.compile(r"[0-9a-f]{128}")
HEX8 = re.compile(r"[0-9a-f]{8}")
HEADER = re.compile(r"[0-9a-f]{160}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TEXT = re.compile(r"[\x21-\x7e]{1,128}")          # printable ASCII, no space, 1 to 128 bytes
MAX_SAFE = 9007199254740991
OUTCOME_KINDS = ("result", "denial", "ack")
TIME_SLACK = 7200                                  # Bitcoin accepts a block time up to 2 h ahead
MAX_PARTIES = 16


class Bad(Exception):
    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


# ==== bytes
def jcs(obj):
    """RFC 8785 bytes. The profile's data model has no floats; strict_value refuses them first."""
    return rfc8785.dumps(obj)


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def strict_value(v, path="$", depth=0):
    """Only the JSON types cA2A signs: object, array, string, safe integer, bool, null."""
    if depth > 64:
        raise Bad("too_deep", path)
    if v is None or isinstance(v, bool):
        return
    if isinstance(v, str):
        try:
            v.encode("utf-8")          # a lone surrogate parses as JSON but has no bytes: JCS would raise
        except UnicodeEncodeError:
            raise Bad("lone_surrogate", path)
        return
    if isinstance(v, int):
        if not -MAX_SAFE <= v <= MAX_SAFE:
            raise Bad("integer_out_of_range", path)
        return
    if isinstance(v, list):
        for i, x in enumerate(v):
            strict_value(x, "%s[%d]" % (path, i), depth + 1)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise Bad("non_string_key", path)
            strict_value(x, "%s.%s" % (path, k), depth + 1)
        return
    raise Bad("type_not_in_profile", "%s is %s" % (path, type(v).__name__))


def load_strict(raw):
    """Parse bytes: UTF-8, no duplicate keys, no NaN or Infinity, no floats."""
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise Bad("duplicate_key", k)
            d[k] = v
        return d

    def no_const(s):
        raise Bad("non_finite_number", s)

    def no_float(s):
        raise Bad("float_not_in_profile", s)
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_const,
                     parse_float=no_float)
    strict_value(obj)
    return obj


def _nonneg(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE


def _is(rx, v):
    return isinstance(v, str) and rx.fullmatch(v) is not None


def _need(rx, v, code):
    if not _is(rx, v):
        raise Bad(code)


def _fields(obj, required, optional=(), what="object"):
    if not isinstance(obj, dict):
        raise Bad("not_an_object", what)
    keys = set(obj)
    missing = set(required) - keys
    unknown = keys - set(required) - set(optional)
    if missing or unknown:
        raise Bad("fields", "%s missing=%s unknown=%s" % (what, sorted(missing), sorted(unknown)))


def body_of(obj, drop=("signature",)):
    return {k: v for k, v in obj.items() if k not in drop}


def check_sig(obj, key_field):
    key, sig = obj.get(key_field), obj.get("signature")
    _need(HEX32, key, "bad_key")
    _need(HEX64, sig, "bad_signature_encoding")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(sig), jcs(body_of(obj, ("signature", "anchor"))))
    except (InvalidSignature, ValueError) as exc:
        raise Bad("signature_invalid", "%s by %s: %s" % (obj.get("type", "?"), key_field, exc))


def sign(obj, priv):
    """Builder helper: returns a copy with signature over JCS(body without signature or anchor)."""
    o = body_of(obj, ("signature", "anchor"))
    o["signature"] = priv.sign(jcs(o)).hex()
    return o


def entry_digest(entry):
    return sha256_hex(jcs(entry))


def request_sha256(request):
    _fields(request, ("type", "caller", "responder", "lineage", "capability", "occurrence_id",
                      "task_sha256"), ("session_id",), "request")
    if request["type"] != T_REQUEST:
        raise Bad("wrong_type", "request")
    return sha256_hex(jcs(request))


def session_id_of(participants, nonce):
    return sha256_hex(jcs({"type": T_SESSION, "participants": participants, "nonce": nonce}))


def commitment_of(session_id, committer, evidence_sha256, salt):
    return sha256_hex(jcs({"type": T_PREIMAGE, "session_id": session_id, "committer": committer,
                           "evidence_sha256": evidence_sha256, "salt": salt}))


def _block(b, what):
    _fields(b, ("height", "hash"), (), what)
    if not _nonneg(b["height"]):
        raise Bad("bad_height", what)
    _need(HEX32, b["hash"], "bad_block_hash")


def _lineage(lin):
    if not (isinstance(lin, list) and 1 <= len(lin) <= 64 and all(_is(DIGEST, d) for d in lin)):
        raise Bad("bad_lineage")


# ==== items
def parse_item(item, extensions=None):
    """Validate one logged item on its own: shape and its author's signature. Returns (kind, item).
    extensions: {type: parser} of a profile built on this one; this profile's own settlement passes none, so
    what it says about a bundle never depends on which other profiles are loaded."""
    if not isinstance(item, dict) or not isinstance(item.get("type"), str):
        raise Bad("item_untyped")
    t = item["type"]
    if extensions and t in extensions:
        return extensions[t](item)
    if t == REVOCATION_TYPE:
        st = RevocationStatement.from_dict(item)          # cA2A's own strict parser
        st.verify_signature()
        return "revocation", item
    if t == T_USE_POLICY:
        _fields(item, ("type", "credential_digest", "issuer", "max_uses", "signature"), (), t)
        _need(DIGEST, item["credential_digest"], "bad_digest")
        if not (_nonneg(item["max_uses"]) and item["max_uses"] >= 1):
            raise Bad("bad_max_uses")
        check_sig(item, "issuer")
        return "use-policy", item
    if t == T_USE:
        _fields(item, ("type", "chain", "holder", "responder", "request_sha256", "signature"), (), t)
        if not (isinstance(item["chain"], list) and 1 <= len(item["chain"]) <= 64):
            raise Bad("bad_chain")
        _need(HEX32, item["responder"], "bad_key")
        _need(HEX32, item["request_sha256"], "bad_request_sha256")
        check_sig(item, "holder")
        return "use", item
    if t == T_RECEIPT:
        _fields(item, ("type", "responder", "caller", "lineage", "capability", "request_sha256",
                       "seen_block", "outcome", "attestation_sha256", "signature"), (), t)
        _need(HEX32, item["caller"], "bad_key")
        _lineage(item["lineage"])
        _need(TEXT, item["capability"], "bad_capability")
        _need(HEX32, item["request_sha256"], "bad_request_sha256")
        _block(item["seen_block"], "seen_block")
        a = item["attestation_sha256"]
        if a is not None:
            _need(HEX32, a, "bad_attestation_sha256")
        oc = item["outcome"]
        _fields(oc, ("kind", "stage", "response_sha256"), (), "outcome")
        if oc["kind"] not in OUTCOME_KINDS:
            raise Bad("bad_outcome_kind")
        _need(TEXT, oc["stage"], "bad_stage")
        r = oc["response_sha256"]
        if r is not None:
            _need(HEX32, r, "bad_response_sha256")
        if oc["kind"] == "result" and r is None:
            raise Bad("result_without_response_sha256")
        check_sig(item, "responder")
        return "receipt", item
    if t == T_COMMIT:
        _fields(item, ("type", "session_id", "participants", "session_nonce", "committer", "commitment",
                       "signature"), (), t)
        p = item["participants"]
        if not (isinstance(p, list) and 2 <= len(p) <= MAX_PARTIES and all(_is(HEX32, k) for k in p)
                and p == sorted(set(p))):
            raise Bad("bad_participants")
        _need(HEX32, item["session_nonce"], "bad_session_nonce")
        if item["session_id"] != session_id_of(p, item["session_nonce"]):
            raise Bad("session_id_does_not_bind_participants")
        if item["committer"] not in p:
            raise Bad("committer_not_a_participant")
        _need(HEX32, item["commitment"], "bad_commitment")
        check_sig(item, "committer")
        return "commit", item
    if t == T_REVEAL:
        _fields(item, ("type", "session_id", "committer", "evidence_sha256", "salt", "signature"), (), t)
        _need(HEX32, item["session_id"], "bad_session_id")
        _need(HEX32, item["evidence_sha256"], "bad_evidence_sha256")
        _need(HEX32, item["salt"], "bad_salt")
        check_sig(item, "committer")
        return "reveal", item
    raise Bad("unknown_item_type", t)


# ==== log and anchor
def _checkpoint(cp, anchored):
    base = ("type", "log_id", "operator", "size", "head", "as_of", "signature")
    if anchored:
        _fields(cp, base + ("anchor",), (), "checkpoint")
    else:
        _fields(cp, base, ("anchor",), "checkpoint")
    if cp["type"] != T_CHECKPOINT:
        raise Bad("wrong_type", "checkpoint")
    _need(TEXT, cp["log_id"], "bad_log_id")
    if not (_nonneg(cp["size"]) and _nonneg(cp["as_of"])):
        raise Bad("checkpoint_numbers")
    if not ((cp["size"] == 0 and cp["head"] is None) or (cp["size"] > 0 and _is(HEX32, cp["head"]))):
        raise Bad("bad_head")
    check_sig(cp, "operator")


def verify_entries(entries, cp):
    """The entries are exactly the log the signed checkpoint describes. Raises Bad."""
    if not isinstance(entries, list) or len(entries) != cp["size"]:
        raise Bad("size_mismatch")
    prev, last_t = None, None
    for i, e in enumerate(entries):
        _fields(e, ("type", "log_id", "operator", "seq", "prev", "logged_at", "item", "signature"), (),
                "entry %d" % i)
        if e["type"] != T_ENTRY or e["log_id"] != cp["log_id"] or e["operator"] != cp["operator"]:
            raise Bad("entry_not_for_this_log", str(i))
        if isinstance(e["seq"], bool) or e["seq"] != i:
            raise Bad("seq_gap", str(i))
        if e["prev"] != prev:
            raise Bad("chain_broken", str(i))
        if not _nonneg(e["logged_at"]) or (last_t is not None and e["logged_at"] < last_t):
            raise Bad("logged_at_not_monotonic", str(i))
        if e["logged_at"] > cp["as_of"]:
            raise Bad("entry_after_checkpoint", str(i))
        strict_value(e)
        check_sig(e, "operator")
        prev, last_t = entry_digest(e), e["logged_at"]
    if cp["head"] != prev:
        raise Bad("head_mismatch")


def _trust(trust):
    _fields(trust, ("log_id", "operator", "root_issuers", "lower_bound", "max_target_bits", "min_depth"),
            ("max_depth",), "trust")
    _need(TEXT, trust["log_id"], "bad_trust")
    _need(HEX32, trust["operator"], "bad_trust")
    r = trust["root_issuers"]
    if not (isinstance(r, list) and r and all(_is(HEX32, k) for k in r)):
        raise Bad("bad_trust", "root_issuers")
    lb = trust["lower_bound"]
    _fields(lb, ("height", "hash"), ("kind",), "lower_bound")
    _block({"height": lb["height"], "hash": lb["hash"]}, "lower_bound")
    _need(HEX8, trust["max_target_bits"], "bad_trust")
    if not (_nonneg(trust["min_depth"]) and trust["min_depth"] >= 1):
        raise Bad("bad_trust", "min_depth")
    if "max_depth" in trust and not (_nonneg(trust["max_depth"]) and trust["max_depth"] <= 64):
        raise Bad("bad_trust", "max_depth")


def verify_log(entries, checkpoint, trust, view):
    """Check the entries against a signed, anchored checkpoint. Returns a status dict; raises Bad."""
    _checkpoint(checkpoint, anchored=True)
    if checkpoint["log_id"] != trust["log_id"] or checkpoint["operator"] != trust["operator"]:
        raise Bad("checkpoint_not_for_this_log")
    verify_entries(entries, checkpoint)
    a = checkpoint["anchor"]
    _fields(a, ("height", "block_hash", "proof"), (), "anchor")
    if not _nonneg(a["height"]):
        raise Bad("bad_anchor_height")
    _need(HEX32, a["block_hash"], "bad_anchor_block_hash")
    if not (isinstance(view, dict) and isinstance(view.get("headers"), list)
            and all(isinstance(x, dict) and _is(HEADER, x.get("hex")) for x in view["headers"])):
        raise Bad("view_rejected", "headers must be 160 lowercase hex, no whitespace")
    pseudo = {"grant": {"finality": {"max_target_bits": trust["max_target_bits"]}},
              "lower_bound": trust["lower_bound"]}
    res, problem = v11.verify_view(view, pseudo)
    if res is None:
        raise Bad("view_rejected", problem)
    h = a["height"]
    if res["hashes"].get(h) != a["block_hash"]:
        raise Bad("anchor_block_not_in_view")
    got = v11.run_proof(hashlib.sha256(jcs(body_of(checkpoint, ("anchor",)))).digest(), a["proof"])
    if got is None or got != res["merkle"][h]:
        raise Bad("anchor_proof_fails")
    depth = res["tip"] - h + 1
    if depth < trust["min_depth"]:
        raise Bad("anchor_too_shallow", "%d < %d" % (depth, trust["min_depth"]))
    times = {x["height"]: int.from_bytes(bytes.fromhex(x["hex"])[68:72], "little") for x in view["headers"]}
    if checkpoint["as_of"] > times[h] + TIME_SLACK:
        raise Bad("checkpoint_as_of_after_anchor", "%d > %d" % (checkpoint["as_of"], times[h]))
    return {"size": checkpoint["size"], "head": checkpoint["head"], "as_of": checkpoint["as_of"],
            "anchor_height": h, "anchor_depth": depth, "anchor_block_time": times[h]}, res["hashes"], times


def compare_checkpoints(cp_a, cp_b, entries):
    """Two signed checkpoints of one log, and the entries of the larger one (either, at equal size).
    Equivocation: the same size with different heads, the smaller head not a prefix of the larger log,
    or a newer checkpoint that is smaller. The checkpoints' signatures make the verdict portable."""
    try:
        strict_value([cp_a, cp_b, entries])
        _checkpoint(cp_a, anchored=False)
        _checkpoint(cp_b, anchored=False)
        if (cp_a["log_id"], cp_a["operator"]) != (cp_b["log_id"], cp_b["operator"]):
            return {"result": "different_logs"}
        small, big = sorted((cp_a, cp_b), key=lambda c: c["size"])
        if small["size"] == big["size"]:
            if small["head"] != big["head"]:
                return {"result": "operator_equivocation", "why": "same size, different heads"}
            return {"result": "consistent", "prefix": small["size"]}
        verify_entries(entries, big)
        prefix_head = None if small["size"] == 0 else entry_digest(entries[small["size"] - 1])
        if prefix_head != small["head"]:
            return {"result": "operator_equivocation", "why": "the smaller log is not a prefix of the larger"}
        if small["as_of"] > big["as_of"]:
            return {"result": "operator_equivocation", "why": "a newer checkpoint is smaller"}
        return {"result": "consistent", "prefix": small["size"]}
    except Bad as exc:
        return {"result": "invalid_input", "problem": exc.code}


def check_promise(signed_entry, entries, checkpoint):
    """A submitter keeps the operator-signed entry it was given at submission. A checkpoint covers every
    entry logged at or before its as_of. If the checkpoint should cover the entry but is too short, or holds
    a different entry at that seq, the operator's signatures prove it withheld or rewrote the entry."""
    try:
        strict_value([signed_entry, entries, checkpoint])
        _checkpoint(checkpoint, anchored=False)
        _fields(signed_entry, ("type", "log_id", "operator", "seq", "prev", "logged_at", "item",
                               "signature"), (), "signed_entry")
        if (signed_entry["type"], signed_entry["log_id"], signed_entry["operator"]) != \
                (T_ENTRY, checkpoint["log_id"], checkpoint["operator"]):
            return {"result": "different_logs"}
        if not _nonneg(signed_entry["seq"]):
            raise Bad("bad_seq")
        check_sig(signed_entry, "operator")
        s = signed_entry["seq"]
        if not _nonneg(signed_entry["logged_at"]):
            raise Bad("bad_logged_at")
        if checkpoint["size"] <= s:
            # a checkpoint covers every entry logged at or before its as_of
            if checkpoint["as_of"] >= signed_entry["logged_at"]:
                return {"result": "operator_withheld", "seq": s}
            return {"result": "not_yet_covered", "seq": s}
        verify_entries(entries, checkpoint)
        if entry_digest(entries[s]) != entry_digest(signed_entry):
            return {"result": "operator_equivocation", "seq": s}
        return {"result": "kept", "seq": s}
    except Bad as exc:
        return {"result": "invalid_input", "problem": exc.code}


# ==== settlement
def _ca2a(chain, trust, at_time, snapshot, by_log_order=False):
    """cA2A's verdict. With by_log_order, the structure and windows are judged at at_time as usual, then
    cA2A's own revocation check runs with every statement in the snapshot in force (at_time None), because
    the snapshot holds exactly what the log published before the receipt."""
    try:
        if not by_log_order:
            verify_chain(chain, max_depth=trust.get("max_depth", 8),
                         trusted_root_issuers=tuple(trust["root_issuers"]), at_time=at_time,
                         revocations=snapshot)
            return "ok"
        verify_chain(chain, max_depth=trust.get("max_depth", 8),
                     trusted_root_issuers=tuple(trust["root_issuers"]), at_time=at_time, revocations=None)
        ca2a_check_revocation(chain, snapshot, at_time=None, now=at_time, max_staleness=None)
        return "ok"
    except CA2AError as exc:
        return exc.code


def _parse_chain(raw):
    if not (isinstance(raw, list) and raw and all(isinstance(c, dict) for c in raw)):
        raise Bad("bad_chain")
    try:
        return [DelegationCredential.from_dict(c) for c in raw]
    except CA2AError as exc:
        raise Bad("chain_unparseable", exc.code)
    except (TypeError, ValueError, KeyError) as exc:
        raise Bad("chain_unparseable", type(exc).__name__)


def _sigs_ok(chain):
    try:
        for c in chain:
            c.verify_signature()
        return True
    except CA2AError:
        return False


def settle(bundle):
    """bundle = {profile, trust, view, log: {entries, checkpoint}, chains: [[credential, ...], ...],
    requests: [request, ...]}. Deterministic; returns the settlement object, never raises on input."""
    out = {"type": T_SETTLEMENT, "profile": PROFILE}
    try:
        _fields(bundle, ("profile", "trust", "view", "log", "chains"), ("requests",), "bundle")
        if bundle["profile"] != PROFILE:
            raise Bad("wrong_profile")
        strict_value(bundle)
        _trust(bundle["trust"])
        _fields(bundle["log"], ("entries", "checkpoint"), (), "log")
        if not isinstance(bundle["chains"], list) or not isinstance(bundle.get("requests", []), list):
            raise Bad("bad_bundle", "chains and requests are lists")
    except Bad as exc:
        out["refused"] = exc.code
        return out
    trust, log = bundle["trust"], bundle["log"]
    try:
        status, hashes, times = verify_log(log["entries"], log["checkpoint"], trust, bundle["view"])
    except Bad as exc:
        out["log"] = {"verified": False, "problem": exc.code}
        return out
    out["log"] = dict(status, verified=True)
    entries = log["entries"]

    supplied = {}
    for raw in bundle["chains"]:
        try:
            chain = _parse_chain(raw)
        except Bad:
            continue
        k = tuple(credential_digest(c) for c in chain)
        if k not in supplied or (not _sigs_ok(supplied[k]) and _sigs_ok(chain)):
            supplied[k] = chain                      # a copy that verifies beats one that does not
    requests = {}
    for r in bundle.get("requests", []):
        try:
            requests.setdefault(request_sha256(r), r)
        except Bad:
            continue

    items, rejected, flagged = [], [], []
    for e in entries:
        seq, t = e["seq"], e["logged_at"]
        try:
            kind, item = parse_item(e["item"])
            extra = {}
            if kind == "use":
                chain = _parse_chain(item["chain"])
                if item["holder"] != chain[-1].subject:
                    raise Bad("holder_not_leaf_subject")
                code = _ca2a(chain, trust, t, None)
                if code != "ok":
                    raise Bad("use_chain:" + code)
                extra = {"chain_obj": chain, "lineage": [credential_digest(c) for c in chain]}
            if kind == "revocation" and item["issued_at"] > t:
                flagged.append({"seq": seq, "flag": "revocation_dated_after_logging"})
            items.append(dict(extra, seq=seq, t=t, kind=kind, item=item))
        except Bad as exc:
            rejected.append({"seq": seq, "reason": exc.code})
        except CA2AError as exc:
            rejected.append({"seq": seq, "reason": exc.code})
    out["items_rejected"] = rejected
    out["items_flagged"] = flagged
    out["counts"] = {k: sum(1 for x in items if x["kind"] == k)
                     for k in ("revocation", "use-policy", "use", "receipt", "commit", "reveal")}
    revs = [(x["seq"], RevocationStatement.from_dict(x["item"])) for x in items if x["kind"] == "revocation"]
    as_of = log["checkpoint"]["as_of"]
    full_snapshot = RevocationSnapshot(as_of=as_of, statements=tuple(s for _, s in revs))
    uses = [x for x in items if x["kind"] == "use"]
    policies = [x for x in items if x["kind"] == "use-policy"]
    # a use of a credential is one (request, responder) pair under any chain that contains it; ranks are
    # by log order, computed once
    rank = {}
    for u in uses:
        pair = (u["item"]["request_sha256"], u["item"]["responder"])
        for d in set(u["lineage"]):
            book = rank.setdefault(d, {})
            if pair not in book:
                book[pair] = len(book) + 1

    receipts, executed = [], {}
    for x in items:
        if x["kind"] != "receipt":
            continue
        it, seq, t = x["item"], x["seq"], x["t"]
        lineage = it["lineage"]
        r = {"seq": seq, "request_sha256": it["request_sha256"], "outcome": it["outcome"]["kind"],
             "stage": it["outcome"]["stage"], "responder": it["responder"], "capability": it["capability"]}
        own = next((u for u in uses if u["seq"] < seq and u["lineage"] == lineage
                    and u["item"]["request_sha256"] == it["request_sha256"]
                    and u["item"]["responder"] == it["responder"]), None)
        chain = own["chain_obj"] if own else supplied.get(tuple(lineage))
        sb = it["seen_block"]
        if chain is None or hashes.get(sb["height"]) != sb["hash"]:
            r["disposition"] = "unassessed"
            r["reasons"] = (["chain_not_supplied"] if chain is None else []) + \
                ([] if hashes.get(sb["height"]) == sb["hash"] else ["seen_block_not_in_view"])
            receipts.append(r)
            continue
        reasons = []
        if sb["height"] >= status["anchor_height"]:
            reasons.append("seen_block_not_before_anchor")
        if t + TIME_SLACK < times[sb["height"]]:
            reasons.append("logged_before_seen_block")
        leaf = chain[-1]
        if it["caller"] != leaf.subject:
            reasons.append("caller_not_leaf_subject")
        if it["capability"] not in leaf.scope:
            reasons.append("capability_not_in_scope")
        req = requests.get(it["request_sha256"])
        r["request_known"] = req is not None
        if req is not None and (req["caller"], req["responder"], req["lineage"], req["capability"]) != \
                (it["caller"], it["responder"], lineage, it["capability"]):
            reasons.append("request_does_not_match_receipt")
        # cA2A's own verdict, twice: with the revocations logged before this receipt, and with every
        # revocation the anchored log holds (cA2A's audit semantics, by the revoker's issued_at)
        published = RevocationSnapshot(as_of=as_of, statements=tuple(s for q, s in revs if q < seq))
        r["ca2a_at_execution"] = _ca2a(chain, trust, t, published, by_log_order=True)
        r["ca2a_audit"] = _ca2a(chain, trust, t, full_snapshot)
        if r["ca2a_at_execution"] not in ("ok", "CREDENTIAL_REVOKED"):
            reasons.append("outside_delegation:" + r["ca2a_at_execution"])
        elif r["ca2a_at_execution"] == "CREDENTIAL_REVOKED":
            reasons.append("executed_after_published_revocation")
        elif r["ca2a_audit"] == "CREDENTIAL_REVOKED":
            reasons.append("revocation_published_late")
        # use limits: a policy on any hop, signed by that hop's issuer and logged before this receipt,
        # counts every distinct (request, responder) made under that credential, in any chain, in log order
        limits = []
        for i, d in enumerate(lineage):
            caps = [p["item"]["max_uses"] for p in policies if p["seq"] < seq
                    and p["item"]["credential_digest"] == d and p["item"]["issuer"] == chain[i].issuer]
            if not caps:
                continue
            limit = min(caps)
            if own is None:
                reasons.append("use_not_logged_before_execution")
                limits.append({"hop": i, "limit": limit, "rank": None})
                continue
            k = rank[d][(it["request_sha256"], it["responder"])]
            limits.append({"hop": i, "limit": limit, "rank": k})
            if k > limit:
                reasons.append("use_limit_exceeded")
        if limits:
            r["use_limits"] = limits
        key = (it["responder"], it["request_sha256"])
        if it["outcome"]["kind"] == "result":
            if key in executed:
                reasons.append("duplicate_execution")
                r["first_execution_seq"] = executed[key]
            else:
                executed[key] = seq
        r["reasons"] = sorted(set(reasons))
        r["disposition"] = "within_delegation" if not reasons else (
            "late_revocation_only" if r["reasons"] == ["revocation_published_late"] else "outside")
        receipts.append(r)
    out["receipts"] = receipts

    sessions = {}
    for x in items:
        if x["kind"] == "commit":
            it = x["item"]
            s = sessions.setdefault(it["session_id"], {"participants": it["participants"], "commits": {},
                                                       "reveals": {}})
            s["commits"].setdefault(it["committer"], dict(it, seq=x["seq"]))
    for x in items:
        if x["kind"] == "reveal":
            it = x["item"]
            s = sessions.get(it["session_id"])
            if s is not None and it["committer"] in s["participants"]:
                s["reveals"].setdefault(it["committer"], dict(it, seq=x["seq"]))
    sres = []
    for sid in sorted(sessions):
        s = sessions[sid]
        rows, problems = [], []
        for p in s["participants"]:
            c, v = s["commits"].get(p), s["reveals"].get(p)
            row = {"committer": p, "commit_seq": c and c["seq"], "reveal_seq": v and v["seq"]}
            if c is None:
                problems.append("commit_missing")
            if v is None:
                problems.append("reveal_missing")
            elif c is not None:
                row["matches"] = commitment_of(sid, p, v["evidence_sha256"], v["salt"]) == c["commitment"]
                if not row["matches"]:
                    problems.append("reveal_does_not_match")
            rows.append(row)
        cs = [r["commit_seq"] for r in rows if r["commit_seq"] is not None]
        vs = [r["reveal_seq"] for r in rows if r["reveal_seq"] is not None]
        if cs and vs and max(cs) > min(vs):
            problems.append("a_reveal_preceded_a_commit")
        sres.append({"session_id": sid, "parties": rows, "simultaneous": not problems,
                     "problems": sorted(set(problems))})
    out["sessions"] = sres
    return out


# ==== cli
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--settle", help="bundle JSON file")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "vectors", "vectors.json"), "rb") as f:
            vs = json.loads(f.read())   # our own file; EV12 is deeper than load_strict allows on purpose
        bad = 0
        for v in vs["vectors"]:
            got = json.loads(jcs(settle(v["bundle"])))
            if got != v["expected"]:
                bad += 1
                print("FAIL", v["id"])
        fns = {"compare_checkpoints": compare_checkpoints, "check_promise": check_promise}
        for x in vs["evidence"]:
            if json.loads(jcs(fns[x["fn"]](*x["args"]))) != x["expected"]:
                bad += 1
                print("FAIL", x["id"])
        n = len(vs["vectors"]) + len(vs["evidence"])
        print("%d/%d vectors agree" % (n - bad, n))
        sys.exit(1 if bad else 0)
    if a.settle:
        # exit 0: a settlement with receipts; 2: refused or the log did not verify; 3: the file is unreadable
        try:
            with open(a.settle, "rb") as f:
                b = load_strict(f.read())
        except (Bad, ValueError, RecursionError, OSError) as exc:
            code = exc.code if isinstance(exc, Bad) else "unreadable_input"
            sys.stdout.write(jcs({"type": T_SETTLEMENT, "profile": PROFILE, "refused": code}).decode("utf-8") + "\n")
            sys.exit(3)
        out = settle(b)
        sys.stdout.write(jcs(out).decode("utf-8") + "\n")
        sys.exit(2 if "refused" in out or not out.get("log", {}).get("verified") else 0)
    ap.print_help()


if __name__ == "__main__":
    main()
