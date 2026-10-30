#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
musubi-trace-terms-v0: TRACE says each call was allowed and what ran it. This says whether the calls the
contractor signed, taken together, kept the contract both parties signed.

A TRACE authorization (agentrust-trace, profile pic-trace-bridge-v1) is one signed decision for one
tool call, checked at the moment of the call. A TRACE Trust Record is one runtime's statement of what
ran (model, policy bundle, platform, data class, build). Neither says what two parties agreed, and
neither adds anything up. This layer takes both as evidence, unchanged, under an a2a-contract-v0 that
both parties signed, and answers four questions about the presented acts that anyone can recompute:

  1. Was every executed call authorized by an authorizer the principal agreed to, under a decision
     TRACE's own verifier accepts? (verify_bridge from agentrust-trace, not a reimplementation)
  2. Was every tool, mapped to the contract's actions, inside the grant? A bridge scope may be wider
     than the contract; the contract wins.
  3. Did the calls together stay within the counts the parties agreed? Every call can be allowed and
     the fifth still be one too many.
  4. When the parties agreed on the runtime, does the Trust Record each act names come from an agreed
     producer, about an agreed agent, and state that runtime?

The contractor's act commits by digest to every piece of evidence the verdict reads. Evidence that is
missing or is not what the act names makes the act undetermined, never outside the terms: whoever
assembles a bundle cannot make the contractor look outside the terms by swapping what it did not sign.
It reads, it does not run anything, and it never fetches. What a verdict does not establish is in
SPEC.md section 8: above all, it says nothing about acts that were not presented, and a Trust Record's
claims are its producer's statements; nothing here appraises a hardware attestation.

CLI:
  python3 trace_terms_v0.py check bundle.json      prints the evaluation, exit 0 within_terms,
                                                   1 outside_terms, 2 refused, 3 undetermined
  python3 trace_terms_v0.py --selftest             reruns vectors/vectors.json
"""
import base64
import calendar
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "..", "musubi-v0"), os.path.join(HERE, "..", "agreement-v0"),
           os.path.join(HERE, "..", "sdk-python", "src")):
    _p = os.path.normpath(_p)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import contract_v0 as C  # noqa: E402
from agreement_verify import canonical, ed25519_verify, norm_domain, parse_strict  # noqa: E402
from nenrin_verify import trace as NT  # noqa: E402

VERSION = "0.1.0"
TERMS_SCHEMA = "musubi-trace-terms-v0"
ACT_SCHEMA = "musubi-trace-act-v0"
EVAL_SCHEMA = "musubi-trace-terms-eval-v0"
TERMS_CONTEXT = b"musubi-trace-terms-v0\n"
ACT_CONTEXT = b"musubi-trace-act-v0\n"
BRIDGE_PROFILE = "tag:agentrust-io.com,2026:pic-trace-bridge-v1"
AGENTRUST_TRACE_PIN = "0.11.0"
DEFAULT_MAX_AGE = 86400
MAX_ACTS = 1024
MAX_JWKS = 64
# grant clauses this profile does not judge. A contract carrying one is refused rather than judged as if the
# clause were not there: use settle (contract_v0 and the settle layers) for those.
UNJUDGED_GRANT = ("conditional", "limits", "approval_policy", "data_access", "expiry_height")
# requirements this profile does not judge either: an evidence or recovery requirement other than "n/a", an
# admission requirement, or any requirement it does not know. Settle judges those.
JUDGED_REQUIREMENTS = {"evidence": "n/a", "recovery": "n/a"}


def _utc(v):
    """Seconds since the epoch for an "YYYY-MM-DDTHH:MM:SSZ" string, None otherwise."""
    if not (isinstance(v, str) and len(v) == 20 and v[4] == "-" and v[7] == "-" and v[10] == "T"
            and v[13] == ":" and v[16] == ":" and v[19] == "Z"):
        return None
    try:
        import time as _t
        return calendar.timegm(_t.strptime(v, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return None
SAFE = 2 ** 53 - 1

TERMS_KEYS = {"schema", "contract_sha256", "authorizers", "tools", "max_calls", "max_calls_total", "runtime",
              "signatures"}
RUNTIME_KEYS = {"producers", "subjects", "models", "policy_bundle_hashes", "enforcement_mode", "data_classes",
                "platforms", "min_slsa_level", "appraisal_status", "max_age_seconds"}
ACT_KEYS = {"schema", "contract_sha256", "seq", "bridge_sha256", "tool_call_digest", "declaration_digest",
            "pic_intent_digest", "pic_args_digest", "transcript_digest", "trace_sha256", "executed_at",
            "signatures"}
ITEM_KEYS = {"act", "bridge", "declaration", "pic_intent_digest", "pic_args_digest", "tool_call", "transcript",
             "trust_record"}
BUNDLE_KEYS = {"contract", "terms", "authorizer_jwks", "acts"}

# Codes that put an attributed act outside the terms: each rests only on what the contractor signed and on
# signatures nobody else can forge. Every other code leaves the act undetermined.
DEVIATIONS = {
    "seq_conflict", "executed_before_agreed_at", "executed_after_expiry", "authorizer_not_agreed", "authorization_denied", "authorization_mismatch",
    "authorization_invalid", "executed_without_valid_authorization", "tool_not_in_terms", "prohibited_action",
    "action_not_granted", "authorization_reused", "calls_exceed_terms", "runtime_evidence_not_named",
    "trace_refused", "producer_not_agreed", "subject_not_agreed", "model_not_agreed", "policy_not_agreed",
    "enforcement_not_agreed", "data_class_not_agreed", "platform_not_agreed", "slsa_below_terms",
    "appraisal_not_agreed", "trace_stale_at_act",
}
UNDETERMINED = {"evidence_not_as_signed", "authorizer_key_not_supplied", "runtime_evidence_missing"}


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _sha_hex(b):
    return hashlib.sha256(b).hexdigest()


def _hex64(v):
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _trace_digest(v):
    return isinstance(v, str) and v.startswith("sha256:") and _hex64(v[7:])


def _thumb(v):
    return isinstance(v, str) and len(v) == 43 and all(
        c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in v)


def _strlist(v, nonempty=False):
    return (isinstance(v, list) and all(isinstance(x, str) and x for x in v) and len(set(v)) == len(v)
            and (len(v) > 0 or not nonempty))


def terms_signing_bytes(terms):
    return TERMS_CONTEXT + canonical({k: v for k, v in terms.items() if k != "signatures"}).encode("utf-8")


def act_signing_bytes(act):
    return ACT_CONTEXT + canonical({k: v for k, v in act.items() if k != "signatures"}).encode("utf-8")


def trace_jcs_digest(obj):
    """sha256:<hex> of RFC 8785, the digest TRACE's own bridge uses (agentrust_trace.intent_bridge.digest_jcs).
    Raises NT.Refusal when the value has no RFC 8785 form."""
    return "sha256:" + _sha_hex(NT.jcs(obj).encode("utf-8"))


def bridge_sha256(bridge):
    """The act names the whole signed bridge object, signature included, by the hex sha256 of its RFC 8785 bytes."""
    return _sha_hex(NT.jcs(bridge).encode("utf-8"))


def _normal(v):
    """The value its RFC 8785 digest names: 1790000030.0 and 1790000030 have one digest, so every reader here and
    in TRACE sees the integer. Without this, whoever assembles a bundle could rewrite an integer as an equal float,
    keep every digest and signature valid, and make a strict reader reject what the contractor signed."""
    return json.loads(NT.jcs(v))


def _canon_ok(v):
    try:
        NT.jcs(v)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- stage A: contract and terms
def _terms_problems(t):
    p = []
    if not isinstance(t, dict):
        return ["terms_malformed:not_object"]
    if t.get("schema") != TERMS_SCHEMA:
        return ["terms_schema"]
    if set(t.keys()) != TERMS_KEYS:
        return ["terms_malformed:members"]
    if not _hex64(t["contract_sha256"]):
        p.append("terms_malformed:contract_sha256")
    if not (_strlist(t["authorizers"], nonempty=True) and all(_thumb(x) for x in t["authorizers"])):
        p.append("terms_malformed:authorizers")
    tools = t["tools"]
    tools_ok = isinstance(tools, dict) and tools and all(isinstance(k, str) and k and isinstance(v, str) and v
                                                         for k, v in tools.items())
    if not tools_ok:
        p.append("terms_malformed:tools")
    mc = t["max_calls"]
    if not (isinstance(mc, dict) and all(isinstance(k, str) and k and _is_int(v) and 1 <= v <= SAFE
                                         for k, v in mc.items())):
        p.append("terms_malformed:max_calls")
    elif tools_ok and any(k not in set(tools.values()) for k in mc):
        # a cap on a name no tool maps to would never apply, and nobody reading the terms would see that
        p.append("terms_malformed:max_calls_unknown_action")
    mt = t["max_calls_total"]
    if not (mt is None or (_is_int(mt) and 1 <= mt <= SAFE)):
        p.append("terms_malformed:max_calls_total")
    rt = t["runtime"]
    if rt is not None:
        if not isinstance(rt, dict) or set(rt.keys()) != RUNTIME_KEYS:
            p.append("terms_malformed:runtime")
        else:
            if not (_strlist(rt["producers"], nonempty=True) and all(_thumb(x) for x in rt["producers"])):
                p.append("terms_malformed:runtime.producers")
            if not _strlist(rt["subjects"], nonempty=True):
                p.append("terms_malformed:runtime.subjects")
            m = rt["models"]
            if not (m is None or (isinstance(m, list) and m and all(
                    isinstance(x, dict) and set(x.keys()) == {"provider", "model_id"} and
                    all(isinstance(x[k], str) and x[k] for k in x) for x in m))):
                p.append("terms_malformed:runtime.models")
            for f in ("policy_bundle_hashes", "data_classes", "platforms", "appraisal_status"):
                if not (rt[f] is None or _strlist(rt[f], nonempty=True)):
                    p.append("terms_malformed:runtime." + f)
            if rt["enforcement_mode"] is not None and not (isinstance(rt["enforcement_mode"], str)
                                                           and rt["enforcement_mode"]):
                p.append("terms_malformed:runtime.enforcement_mode")
            s = rt["min_slsa_level"]
            if not (s is None or (_is_int(s) and 0 <= s <= 4)):
                p.append("terms_malformed:runtime.min_slsa_level")
            a = rt["max_age_seconds"]
            if not (a is None or (_is_int(a) and 0 <= a <= 31536000)):
                p.append("terms_malformed:runtime.max_age_seconds")
    if not isinstance(t["signatures"], list):
        p.append("terms_malformed:signatures")
    if not p and not _canon_ok({k: v for k, v in t.items() if k != "signatures"}):
        p.append("terms_malformed:not_canonical")
    return p


def _terms_signature_problems(terms, contract):
    """Both contract parties, by the keys the contract pins, over the terms' signing bytes. The same rule
    contract_v0.verify_contract applies to the contract itself."""
    pin = {norm_domain(p.get("domain")): p.get("public_key_ed25519_b64")
           for p in (contract.get("parties") or []) if isinstance(p, dict)}
    msg = terms_signing_bytes(terms)
    signed, out = set(), []
    for s in terms["signatures"]:
        if not isinstance(s, dict) or set(s.keys()) != {"domain", "alg", "signature"} or s.get("alg") != "ed25519":
            out.append("terms_signature_malformed")
            continue
        d = norm_domain(s.get("domain"))
        if d not in pin:
            out.append("terms_stranger_signature")
            continue
        if ed25519_verify(pin[d], s.get("signature"), msg) is True:
            signed.add(d)
        else:
            out.append("terms_bad_signature")
    if any(d not in signed for d in pin):
        out.append("terms_one_sided")
    return sorted(set(out))


def _contractor_key(contract):
    for p in contract.get("parties") or []:
        if isinstance(p, dict) and p.get("role") == "contractor":
            return p.get("public_key_ed25519_b64")
    return None


# --------------------------------------------------------------------------- one act
def _act_shape(act):
    if not isinstance(act, dict) or act.get("schema") != ACT_SCHEMA or set(act.keys()) != ACT_KEYS:
        return False
    return (_hex64(act["contract_sha256"]) and _is_int(act["seq"]) and 1 <= act["seq"] <= SAFE
            and _hex64(act["bridge_sha256"]) and _trace_digest(act["tool_call_digest"])
            and _trace_digest(act["declaration_digest"]) and isinstance(act["pic_intent_digest"], str)
            and isinstance(act["pic_args_digest"], str)
            and (act["transcript_digest"] is None or _trace_digest(act["transcript_digest"]))
            and (act["trace_sha256"] is None or _hex64(act["trace_sha256"]))
            and _is_int(act["executed_at"]) and 1700000000 <= act["executed_at"] <= SAFE
            and isinstance(act["signatures"], list) and _canon_ok({k: v for k, v in act.items() if k != "signatures"}))


def _signed_by(act, key_b64):
    if not key_b64 or not isinstance(act, dict) or not isinstance(act.get("signatures"), list):
        return False
    try:
        msg = act_signing_bytes(act)
    except Exception:
        return False
    for s in act["signatures"]:
        if (isinstance(s, dict) and set(s.keys()) == {"role", "sig_b64"} and s.get("role") == "contractor"
                and ed25519_verify(key_b64, s.get("sig_b64"), msg) is True):
            return True
    return False


def _bridge_signature_verifies(bridge, jwk):
    """Ed25519 over RFC 8785 of {"profile", "authorization"}: the bytes agentrust-trace's sign_bridge signs. Used
    only to tell who signed a bridge; whether the bridge allows the call is TRACE's verify_bridge's answer."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not (isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"):
            return False
        x = NT._b64url_canonical(jwk.get("x"))
        sig = NT._b64url_canonical(bridge.get("signature"))
        if x is None or len(x) != 32 or sig is None or len(sig) != 64:
            return False
        body = NT.jcs({"profile": bridge["profile"], "authorization": bridge["authorization"]}).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(x).verify(sig, body)
        return True
    except Exception:
        return False


def _thumbprint(jwk):
    try:
        from agentrust_trace.sign import jwk_thumbprint
        return jwk_thumbprint(jwk)
    except Exception:
        return None


def _authorizer(bridge, jwks, agreed):
    """Which supplied key signed this bridge. Returns (jwk, thumbprint, code): code None for an agreed key,
    authorizer_not_agreed when only a key the terms do not list verifies it, authorizer_key_not_supplied when no
    supplied key verifies it (undetermined: the relying party did not hand over the key)."""
    auth = bridge.get("authorization") if isinstance(bridge, dict) else None
    kid = auth.get("authorizer_key_id") if isinstance(auth, dict) else None
    cands = [(j, _thumbprint(j)) for j in jwks if isinstance(kid, str) and j.get("kid") == kid]
    for j, tp in cands:
        if tp is not None and tp in agreed and _bridge_signature_verifies(bridge, j):
            return j, tp, None
    for j, tp in cands:
        if tp is not None and tp not in agreed and _bridge_signature_verifies(bridge, j):
            return j, tp, "authorizer_not_agreed"
    return None, None, "authorizer_key_not_supplied"


def _verify_bridge(item, jwk, now):
    """TRACE's own verifier decides whether the decision allows this call. Returns ([codes], why)."""
    from agentrust_trace import intent_bridge as IB
    try:
        IB.verify_bridge(item["bridge"], jwk, declaration=item["declaration"],
                         pic_intent_digest=item["pic_intent_digest"], pic_args_digest=item["pic_args_digest"],
                         tool_call=item["tool_call"], transcript=item["transcript"], now=now)
        return [], None
    except IB.AuthorizationDenied as e:
        return ["authorization_denied", "executed_without_valid_authorization"], str(e)
    except IB.AuthorizationMismatch as e:
        return ["authorization_mismatch", "executed_without_valid_authorization"], str(e)
    except IB.IntentBridgeError as e:
        return ["authorization_invalid", "executed_without_valid_authorization"], str(e)
    except Exception as e:  # anything TRACE's verifier raises that is not its own error type
        return ["authorization_invalid", "executed_without_valid_authorization"], "%s: %s" % (type(e).__name__, e)


def _evidence_mismatches(item, act):
    """Each piece of evidence the act commits to, compared with what the bundle carries. A mismatch means the
    bundle does not hold what the contractor signed: the act is undetermined, never outside the terms."""
    bad = []
    if bridge_sha256(item["bridge"]) != act["bridge_sha256"]:
        bad.append("bridge")
    if trace_jcs_digest(item["tool_call"]) != act["tool_call_digest"]:
        bad.append("tool_call")
    if trace_jcs_digest(item["declaration"]) != act["declaration_digest"]:
        bad.append("declaration")
    if item["pic_intent_digest"] != act["pic_intent_digest"]:
        bad.append("pic_intent_digest")
    if item["pic_args_digest"] != act["pic_args_digest"]:
        bad.append("pic_args_digest")
    if act["transcript_digest"] is None:
        if item["transcript"] is not None:
            bad.append("transcript")
    elif item["transcript"] is None or trace_jcs_digest(item["transcript"]) != act["transcript_digest"]:
        bad.append("transcript")
    return bad


def _runtime_check(R, act, rt):
    """Section 6. The Trust Record is checked as the NENRIN ledger's intake checks it, at the stated act time,
    then its claims are compared with what both parties agreed. Equality only; nothing is appraised.
    The caller has already established that R is the record the act names."""
    codes, info = [], {}
    try:
        c = NT.check_trace_record(R, act["executed_at"])
    except NT.Refusal as e:
        return ["trace_refused"], {"trace_refusal": e.code}
    except Exception as e:
        return ["trace_refused"], {"trace_refusal": type(e).__name__}
    info["producer"] = c["key_thumbprint"]
    if c["key_thumbprint"] not in rt["producers"]:
        codes.append("producer_not_agreed")
    if c["subject"] not in rt["subjects"]:
        codes.append("subject_not_agreed")
    model = R.get("model") if isinstance(R.get("model"), dict) else {}
    if rt["models"] is not None and not any(model.get("provider") == m["provider"] and
                                            model.get("model_id") == m["model_id"] for m in rt["models"]):
        codes.append("model_not_agreed")
    pol = R.get("policy") if isinstance(R.get("policy"), dict) else {}
    if rt["policy_bundle_hashes"] is not None and pol.get("bundle_hash") not in rt["policy_bundle_hashes"]:
        codes.append("policy_not_agreed")
    if rt["enforcement_mode"] is not None and pol.get("enforcement_mode") != rt["enforcement_mode"]:
        codes.append("enforcement_not_agreed")
    if rt["data_classes"] is not None and R.get("data_class") not in rt["data_classes"]:
        codes.append("data_class_not_agreed")
    run = R.get("runtime") if isinstance(R.get("runtime"), dict) else {}
    if rt["platforms"] is not None and run.get("platform") not in rt["platforms"]:
        codes.append("platform_not_agreed")
    bp = R.get("build_provenance") if isinstance(R.get("build_provenance"), dict) else {}
    if rt["min_slsa_level"] is not None:
        lvl = bp.get("slsa_level")
        if not (_is_int(lvl) and lvl >= rt["min_slsa_level"]):
            codes.append("slsa_below_terms")
    ap = R.get("appraisal") if isinstance(R.get("appraisal"), dict) else {}
    if rt["appraisal_status"] is not None and ap.get("status") not in rt["appraisal_status"]:
        codes.append("appraisal_not_agreed")
    max_age = DEFAULT_MAX_AGE if rt["max_age_seconds"] is None else rt["max_age_seconds"]
    if act["executed_at"] - c["iat"] > max_age:
        codes.append("trace_stale_at_act")
    return codes, info


def _item_readable(item):
    if not (isinstance(item, dict) and set(item.keys()) == ITEM_KEYS and _act_shape(item["act"])
            and isinstance(item["bridge"], dict) and isinstance(item["tool_call"], dict)
            and isinstance(item["declaration"], dict)
            and isinstance(item["pic_intent_digest"], str) and isinstance(item["pic_args_digest"], str)
            and (item["transcript"] is None or isinstance(item["transcript"], dict))
            and (item["trust_record"] is None or isinstance(item["trust_record"], dict))):
        return False
    # every TRACE object the verdict digests must have an RFC 8785 form
    return all(_canon_ok(item[k]) for k in ("bridge", "tool_call", "declaration")) and \
        (item["transcript"] is None or _canon_ok(item["transcript"]))


# --------------------------------------------------------------------------- the evaluation
def _refused(out, codes):
    out["verdict"], out["refusals"] = "refused", sorted(set(codes))
    return out


def evaluate(bundle):
    out = {"schema": EVAL_SCHEMA, "evaluator": "trace_terms_v0.py " + VERSION,
           "agentrust_trace": None, "verdict": None, "refusals": [], "acts": [], "counts": {}, "findings": []}
    try:
        import agentrust_trace
        out["agentrust_trace"] = getattr(agentrust_trace, "__version__", None)
    except Exception:
        return _refused(out, ["agentrust_trace_missing"])
    if out["agentrust_trace"] != AGENTRUST_TRACE_PIN:
        out["findings"].append("agentrust_trace_not_the_pinned_version")

    if not isinstance(bundle, dict) or set(bundle.keys()) != BUNDLE_KEYS:
        return _refused(out, ["bundle_malformed"])
    contract, terms = bundle["contract"], bundle["terms"]
    try:
        cv = C.verify_contract(contract)
    except Exception:
        return _refused(out, ["contract:unreadable"])
    if cv.get("verdict") != "accepted":
        return _refused(out, ["contract:" + r["code"] for r in cv["refusals"]])
    csha = cv["contract_sha256"]
    out["contract_sha256"] = csha
    g0 = contract.get("grant") or {}
    unj = ["grant_clause_not_judged:" + k for k in UNJUDGED_GRANT if g0.get(k) not in (None, [], {})]
    if contract.get("parent_contract") is not None:
        unj.append("contract_clause_not_judged:parent_contract")
    rq = contract.get("requirements")
    if not isinstance(rq, dict):
        unj.append("contract_clause_not_judged:requirements")
    else:
        for k, v in rq.items():
            if JUDGED_REQUIREMENTS.get(k) != v:
                unj.append("contract_clause_not_judged:requirements." + str(k))
    agreed_at = _utc(contract.get("agreed_at"))
    if agreed_at is None:
        unj.append("contract_clause_not_judged:agreed_at")
    expiry = None
    if contract.get("expiry") is not None:
        expiry = _utc(contract.get("expiry"))
        if expiry is None:
            unj.append("contract_clause_not_judged:expiry")
    if unj:
        return _refused(out, unj)
    tp = _terms_problems(terms)
    if tp:
        return _refused(out, tp)
    if terms["contract_sha256"] != csha:
        return _refused(out, ["terms_for_other_contract"])
    sp = _terms_signature_problems(terms, contract)
    if sp:
        return _refused(out, sp)
    jw, acts = bundle["authorizer_jwks"], bundle["acts"]
    if not (isinstance(jw, list) and len(jw) <= MAX_JWKS and all(isinstance(j, dict) for j in jw)):
        return _refused(out, ["bundle_malformed:authorizer_jwks"])
    if not (isinstance(acts, list) and len(acts) <= MAX_ACTS):
        return _refused(out, ["bundle_malformed:acts"])
    out["terms_sha256"] = _sha_hex(terms_signing_bytes(terms))

    grant = contract.get("grant") or {}
    authorized = set(grant.get("authorized_actions") or [])
    prohibited = set(grant.get("prohibited_actions") or [])
    agreed = set(terms["authorizers"])
    ckey = _contractor_key(contract)
    rt = terms["runtime"]

    rows = []
    for i, item in enumerate(acts):
        row = {"index": i, "seq": None, "status": None, "codes": []}
        rows.append(row)
        signed = isinstance(item, dict) and _signed_by(item.get("act"), ckey)
        if not _item_readable(item):
            # a contractor-signed act that is not well formed is still the contractor's: undetermined, not dropped.
            # Anything else unreadable is nobody's act and is only reported.
            if signed:
                row["status"], row["codes"] = "unreadable", ["act_malformed", "signed_by_contractor"]
            else:
                row["status"], row["codes"] = "not_attributed", ["act_malformed"]
            continue
        item = dict(item)
        for k in ("bridge", "tool_call", "declaration", "transcript"):
            if item[k] is not None:
                item[k] = _normal(item[k])
        if item["trust_record"] is not None and _canon_ok(item["trust_record"]):
            item["trust_record"] = _normal(item["trust_record"])
        act = item["act"]
        row["seq"] = act["seq"]
        if not signed:
            row["status"], row["codes"] = "not_attributed", ["act_not_signed_by_contractor"]
            continue
        if act["contract_sha256"] != csha:
            row["status"], row["codes"] = "other_contract", ["contractor_act_for_other_contract"]
            continue
        row["status"] = "attributed"
        row["_item"] = item
        row["_bytes"] = act_signing_bytes(act)

    # Attributed acts in the contractor's own order. The same act bytes twice count once; two different acts the
    # contractor signed with one seq are both read, both counted, and both outside the terms.
    def _matches(r):
        """Every piece of evidence is the one the act names, the Trust Record included."""
        it, a = r["_item"], r["_item"]["act"]
        try:
            if _evidence_mismatches(it, a):
                return False
            if a["trace_sha256"] is None:
                return it["trust_record"] is None
            return it["trust_record"] is not None and _canon_ok(it["trust_record"]) and \
                NT.sha256hex(NT.jcs(it["trust_record"])) == a["trace_sha256"]
        except Exception:
            return False
    # within one set of identical act bytes, the copy whose evidence matches what the act names is read first, so
    # neither the order of the list nor a second copy with other evidence decides the verdict
    attributed = sorted((r for r in rows if r["status"] == "attributed"),
                        key=lambda r: (r["seq"], r["_bytes"], 0 if _matches(r) else 1, r["index"]))
    by_seq = {}
    for r in attributed:
        by_seq.setdefault(r["seq"], set()).add(r["_bytes"])
    seen_bytes, seen_auth = set(), set()
    per_action, total = {}, 0
    for r in attributed:
        item, b = r.pop("_item"), r.pop("_bytes")
        act = item["act"]
        if b in seen_bytes:
            r["status"], r["codes"] = "duplicate", ["same_act_again"]
            continue
        seen_bytes.add(b)
        codes, why = [], {}
        if len(by_seq[act["seq"]]) > 1:
            codes.append("seq_conflict")
        bad = _evidence_mismatches(item, act)
        if bad:
            codes.append("evidence_not_as_signed")
            why["evidence_not_as_signed"] = bad
        else:
            jwk, thumb, acode = _authorizer(item["bridge"], bundle["authorizer_jwks"], agreed)
            if acode == "authorizer_key_not_supplied":
                codes.append(acode)
            else:
                if acode == "authorizer_not_agreed":
                    codes += ["authorizer_not_agreed", "executed_without_valid_authorization"]
                bc, bwhy = _verify_bridge(item, jwk, act["executed_at"])
                codes += bc
                if bwhy:
                    why["authorization"] = bwhy
                aid = item["bridge"]["authorization"].get("authorization_id")
                if isinstance(aid, str):
                    if (thumb, aid) in seen_auth:
                        codes.append("authorization_reused")
                    seen_auth.add((thumb, aid))
        tool = item["tool_call"].get("name")
        action = terms["tools"].get(tool) if isinstance(tool, str) else None
        r["tool"] = tool if isinstance(tool, str) else None
        r["action"] = action
        if not bad:
            if action is None:
                codes.append("tool_not_in_terms")
            elif action in prohibited:
                codes.append("prohibited_action")
            elif action not in authorized:
                codes.append("action_not_granted")
        # every attributed act counts toward the total, valid or not: the contractor signed that it ran. Its
        # action is known only when the tool call is the one the act names; otherwise it counts as unverified,
        # so a swapped tool call cannot move a count from one action to another.
        total += 1
        if bad:
            key = "unverified"
        else:
            key = action if action is not None else ("tool:" + tool if isinstance(tool, str) else "tool:?")
        per_action[key] = per_action.get(key, 0) + 1
        if act["executed_at"] < agreed_at:
            codes.append("executed_before_agreed_at")
        if expiry is not None and act["executed_at"] >= expiry:
            codes.append("executed_after_expiry")
        if (not bad and action is not None and action in terms["max_calls"]
                and per_action[key] > terms["max_calls"][action]) \
                or (terms["max_calls_total"] is not None and total > terms["max_calls_total"]):
            codes.append("calls_exceed_terms")
        if rt is not None:
            if act["trace_sha256"] is None:
                codes.append("runtime_evidence_not_named")
            elif item["trust_record"] is None or not _canon_ok(item["trust_record"]) or \
                    NT.sha256hex(NT.jcs(item["trust_record"])) != act["trace_sha256"]:
                codes.append("runtime_evidence_missing")
            else:
                rc, info = _runtime_check(item["trust_record"], act, rt)
                codes += rc
                if info:
                    why.update(info)
        elif item["trust_record"] is not None:
            r["findings"] = ["runtime_not_in_terms_record_not_read"]
        codes = sorted(set(codes))
        r["codes"] = codes
        if why:
            r["why"] = why
        if any(c in DEVIATIONS for c in codes):
            r["status"] = "outside_terms"
        elif any(c in UNDETERMINED for c in codes):
            r["status"] = "undetermined"
        else:
            r["status"] = "within_terms"

    out["acts"] = rows
    st = [r["status"] for r in rows]
    out["counts"] = {"acts": len(rows), "counted_calls": total, "per_action": dict(sorted(per_action.items())),
                     "within_terms": st.count("within_terms"), "outside_terms": st.count("outside_terms"),
                     "undetermined": st.count("undetermined"), "not_attributed": st.count("not_attributed"),
                     "other_contract": st.count("other_contract"), "duplicate": st.count("duplicate"),
                     "unreadable": st.count("unreadable")}
    if "outside_terms" in st:
        out["verdict"] = "outside_terms"
    elif any(s in ("undetermined", "unreadable", "other_contract") for s in st) or total == 0:
        out["verdict"] = "undetermined"
    else:
        out["verdict"] = "within_terms"
    if total == 0:
        out["findings"].append("no_attributed_acts")
    if "not_attributed" in st:
        out["findings"].append("acts_not_signed_by_the_contractor_are_reported_not_counted")
    out["findings"] += ["only_the_presented_acts_are_judged", "executed_at_is_the_contractors_statement",
                        "pic_digests_compared_not_recomputed",
                        "trust_record_claims_are_producer_statements_not_appraised"]
    out["findings"] = sorted(set(out["findings"]))
    return out


# --------------------------------------------------------------------------- signing helpers (for builders)
def sign_terms(terms, priv, domain):
    """Append one party's signature. priv is an Ed25519PrivateKey."""
    terms["signatures"] = [s for s in terms.get("signatures") or []]
    sig = priv.sign(terms_signing_bytes(terms))
    terms["signatures"].append({"domain": domain, "alg": "ed25519",
                                "signature": base64.b64encode(sig).decode("ascii")})
    return terms


def make_act(contract_sha, seq, item, executed_at, trust_record=None):
    """The act a contractor signs for one executed call, committing to every piece of evidence by digest."""
    return {"schema": ACT_SCHEMA, "contract_sha256": contract_sha, "seq": seq,
            "bridge_sha256": bridge_sha256(item["bridge"]), "tool_call_digest": trace_jcs_digest(item["tool_call"]),
            "declaration_digest": trace_jcs_digest(item["declaration"]),
            "pic_intent_digest": item["pic_intent_digest"], "pic_args_digest": item["pic_args_digest"],
            "transcript_digest": None if item.get("transcript") is None else trace_jcs_digest(item["transcript"]),
            "trace_sha256": None if trust_record is None else NT.sha256hex(NT.jcs(trust_record)),
            "executed_at": executed_at, "signatures": []}


def sign_act(act, priv):
    act["signatures"] = []
    sig = priv.sign(act_signing_bytes(act))
    act["signatures"] = [{"role": "contractor", "sig_b64": base64.b64encode(sig).decode("ascii")}]
    return act


def _signature(ev):
    """What the vectors compare: verdict, stage A refusals, and per act (index, status, sorted codes)."""
    return {"verdict": ev["verdict"], "refusals": ev["refusals"],
            "acts": [{"index": r["index"], "status": r["status"], "codes": r["codes"]} for r in ev["acts"]]}


def selftest():
    with open(os.path.join(HERE, "vectors", "vectors.json"), encoding="utf-8") as f:
        doc = parse_strict(f.read())
    fails = 0
    for v in doc["vectors"]:
        got = _signature(evaluate(v["bundle"]))
        ok = got == v["expect"]
        fails += 0 if ok else 1
        print(("  ok   " if ok else "  FAIL ") + v["id"] + "  " + v["title"])
        if not ok:
            print("       want " + json.dumps(v["expect"], sort_keys=True))
            print("       got  " + json.dumps(got, sort_keys=True))
    n = len(doc["vectors"])
    print("\n=== %d / %d (musubi-trace-terms-v0) ===" % (n - fails, n))
    return 1 if fails else 0


def main(argv):
    if argv[1:2] == ["--selftest"]:
        return selftest()
    if len(argv) == 3 and argv[1] == "check":
        with open(argv[2], encoding="utf-8") as f:
            text = f.read()
        try:
            bundle = parse_strict(text)
        except Exception as e:
            print(json.dumps({"schema": EVAL_SCHEMA, "verdict": "refused",
                              "refusals": ["bundle_not_strict_json"], "why": type(e).__name__}))
            return 2
        ev = evaluate(bundle)
        print(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=False))
        return {"within_terms": 0, "outside_terms": 1, "refused": 2, "undetermined": 3}[ev["verdict"]]
    print(__doc__.strip().split("CLI:")[1])
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
