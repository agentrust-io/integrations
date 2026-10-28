"""Artifact-tamper matrix for pic_trace_verify (record + bridge-only verification)."""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest
from agentrust_trace import verify_record
from agentrust_trace.intent_bridge import sign_bridge
from agentrust_trace.sign import key_to_jwk, sign_record
from agentrust_trace.validate import validate_json

import pic_trace_guard as g
from pic_trace_verify import (
    AdapterVerifyError,
    verify_adapter_artifacts,
    verify_authorization_artifacts,
)

from conftest import BRIDGE_KEY, EVIDENCE_KEY, RECORD_KEY


@pytest.fixture
def bundle(coordinator, runner):
    outcome, _ = runner(coordinator, rid="verifier-1")
    assert outcome.status == "record-emitted", outcome.absence
    ra = outcome.record_artifacts
    a = ra.authorization
    return SimpleNamespace(
        record=ra.record, transcript=ra.transcript, bridge=a.bridge,
        raw=a.pic_decision_raw, declaration=a.declaration,
        intent=a.pic_intent_digest, args=a.pic_args_digest,
        tool_call=a.tool_call, jwk=a.authorizer_jwk,
    )


def _flip(s: str) -> str:
    return ("B" if s[0] != "B" else "A") + s[1:]


def _mut(obj, fn):
    out = copy.deepcopy(obj)
    fn(out)
    return out


def _resign(record):
    r = copy.deepcopy(record)
    r.pop("signature", None)
    return sign_record(r, RECORD_KEY)


def _mut_record_resigned(b, fn):
    return _resign(_mut(b.record, fn))


def _record_with_different_cnf_key(record):
    # Sign with EVIDENCE_KEY and set cnf.jwk to its public key, leaving subject unchanged:
    # schema and signature verification pass, so the subject-binding check is what rejects.
    out = copy.deepcopy(record)
    out["cnf"]["jwk"] = key_to_jwk(EVIDENCE_KEY)
    out.pop("signature", None)
    return sign_record(out, EVIDENCE_KEY)


def _verify(b, **over):
    kw = dict(
        record=b.record, bridge=b.bridge, pic_decision_raw=b.raw, declaration=b.declaration,
        pic_intent_digest=b.intent, pic_args_digest=b.args, tool_call=b.tool_call,
        authorizer_jwk=b.jwk, transcript=b.transcript,
    )
    kw.update(over)
    return verify_adapter_artifacts(**kw)


def _verify_authz(b, **over):
    kw = dict(
        bridge=b.bridge, pic_decision_raw=b.raw, declaration=b.declaration,
        pic_intent_digest=b.intent, pic_args_digest=b.args, tool_call=b.tool_call,
        authorizer_jwk=b.jwk,
    )
    kw.update(over)
    return verify_authorization_artifacts(**kw)


# --- Baseline --------------------------------------------------------------

def test_valid_bundle_verifies(bundle):
    checked = _verify(bundle)
    assert checked["authorization_id_bound_to_decision"] is True
    assert checked["record_signature"] is True
    assert checked["reference_matches_supplied_bridge"] is True
    assert checked["subject_binds_cnf_jwk"] is True
    assert checked["transcript_bound_and_hashed"] is True


def test_valid_bundle_verifies_without_transcript(bundle):
    # Transcript-preimage verification is deliberately optional.
    checked = _verify(bundle, transcript=None)
    assert checked["record_signature"] is True
    assert "transcript_bound_and_hashed" not in checked


# --- Full record-verification tamper matrix --------------------------------

_RECORD_TAMPERS = [
    ("bridge-signature",
     lambda b: {"bridge": _mut(b.bridge, lambda x: x.__setitem__("signature", _flip(x["signature"])))}),
    ("declaration",
     lambda b: {"declaration": {"profile": "pic-standard-action-declaration/v1", "tool": "x", "impact": "y"}}),
    ("tool-call",
     lambda b: {"tool_call": {"name": "other", "arguments": {}}}),
    ("pic-intent-digest", lambda b: {"pic_intent_digest": "0" * 64}),
    ("pic-args-digest", lambda b: {"pic_args_digest": "0" * 64}),
    ("decision-bytes", lambda b: {"pic_decision_raw": b.raw + b"x"}),
    ("origin-source-event-id",
     lambda b: {"record": _mut_record_resigned(b, lambda r: r["origin"].__setitem__("source_event_id", "urn:sha256:" + "0" * 64))}),
    ("reference-rel",
     lambda b: {"record": _mut_record_resigned(b, lambda r: r["references"][0].__setitem__("rel", "unrelated"))}),
    ("reference-id",
     lambda b: {"record": _mut_record_resigned(b, lambda r: r["references"][0].__setitem__("id", "urn:sha256:" + "0" * 64))}),
    ("reference-digest",
     lambda b: {"record": _mut_record_resigned(b, lambda r: r["references"][0].__setitem__("digest", "sha256:" + "0" * 64))}),
    ("record-signature",
     lambda b: {"record": _mut(b.record, lambda r: r.__setitem__("signature", _flip(r["signature"])))}),
    ("subject-did-key",
     lambda b: {"record": _mut_record_resigned(b, lambda r: r.__setitem__("subject", g.did_key(EVIDENCE_KEY)))}),
    ("transcript-profile",
     lambda b: {"transcript": _mut(b.transcript, lambda t: t.__setitem__("profile", "wrong"))}),
    ("transcript-decision-digest",
     lambda b: {"transcript": _mut(b.transcript, lambda t: t.__setitem__("pic_decision_digest", "sha256:" + "0" * 64))}),
    ("transcript-bridge-digest",
     lambda b: {"transcript": _mut(b.transcript, lambda t: t.__setitem__("authorization_bridge_digest", "sha256:" + "0" * 64))}),
    ("transcript-tool-call",
     lambda b: {"transcript": _mut(b.transcript, lambda t: t.__setitem__("tool_call", {"name": "x", "arguments": {}}))}),
    ("transcript-hash",
     lambda b: {"transcript": _mut(b.transcript, lambda t: t["observation"]["observation"].__setitem__("marker_exists_after", True))}),
]


@pytest.mark.parametrize("label,factory", _RECORD_TAMPERS, ids=[t[0] for t in _RECORD_TAMPERS])
def test_adapter_artifact_tampering_detected(bundle, label, factory):
    with pytest.raises(AdapterVerifyError):
        _verify(bundle, **factory(bundle))


# --- Dedicated semantic cases that must reach their intended check ---------

def test_changed_cnf_key_reaches_subject_binding(bundle):
    # Signed by a different key with matching cnf.jwk: schema and signature pass, so the
    # failure is specifically the subject<->confirmation-key binding, not the signature.
    record = _record_with_different_cnf_key(bundle.record)
    validate_json(record)
    verify_record(record, record["cnf"]["jwk"])
    with pytest.raises(AdapterVerifyError, match="subject did:key"):
        _verify(bundle, record=record)


def test_duplicate_matching_reference_rejected(bundle):
    # A second reference with the same bridge id but a different resolver so JSON Schema
    # uniqueItems cannot reject it as an identical object; schema+signature pass first.
    def add_duplicate(record):
        duplicate = copy.deepcopy(record["references"][0])
        duplicate["resolver"] = "urn:pic-standard:test:second-resolver"
        record["references"].append(duplicate)

    record = _mut_record_resigned(bundle, add_duplicate)
    validate_json(record)
    verify_record(record, record["cnf"]["jwk"])
    with pytest.raises(AdapterVerifyError, match="exactly one reference"):
        _verify(bundle, record=record)


# --- Bridge-only verification (verify_authorization_artifacts) -------------

def test_authorization_artifacts_verify(bundle):
    checked = _verify_authz(bundle)
    assert checked["authorization_id_bound_to_decision"] is True
    assert checked["bridge_signature"] is True
    assert checked["bridge_intent_digest"] is True
    assert checked["bridge_args_digest"] is True


_AUTHZ_TAMPERS = [
    ("decision-bytes", lambda b: {"pic_decision_raw": b.raw + b"x"}),
    ("declaration", lambda b: {"declaration": {"profile": "x", "tool": "y", "impact": "z"}}),
    ("tool-call", lambda b: {"tool_call": {"name": "x", "arguments": {}}}),
    ("pic-intent-digest", lambda b: {"pic_intent_digest": "0" * 64}),
    ("pic-args-digest", lambda b: {"pic_args_digest": "0" * 64}),
    ("prefixed-input-digest", lambda b: {"pic_intent_digest": "sha256:" + b.intent}),  # bare hex expected
    ("bridge-signature", lambda b: {"bridge": _mut(b.bridge, lambda x: x.__setitem__("signature", _flip(x["signature"])))}),
]


@pytest.mark.parametrize("label,factory", _AUTHZ_TAMPERS, ids=[t[0] for t in _AUTHZ_TAMPERS])
def test_authorization_artifacts_tampering_detected(bundle, label, factory):
    with pytest.raises(AdapterVerifyError):
        _verify_authz(bundle, **factory(bundle))


def test_signed_bare_hex_bridge_rejected(bundle):
    # A genuinely signed bridge whose pic.intent_digest is bare hex (not sha256:<hex>)
    # must be rejected by verification, not accepted because the signature is valid.
    authz = copy.deepcopy(bundle.bridge["authorization"])
    authz["pic"]["intent_digest"] = bundle.intent  # bare hex
    malformed = sign_bridge(authz, BRIDGE_KEY)
    with pytest.raises(AdapterVerifyError):
        _verify_authz(bundle, bridge=malformed)
