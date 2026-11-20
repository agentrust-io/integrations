"""Taint gating, StepUpReceipt enforcement, dispatch ordering, observation, and record emission."""

from __future__ import annotations

import json
import re
import threading
import time

import cta_trace_guard as g
import cta_trace_verify as v
import pytest
from agentrust_trace import key_to_jwk, verify_record
from agentrust_trace.validate import validate_json
from agentrust_trace_adapters import software_measurement
from conftest import (
    ARGS,
    ARTIFACT_STORE,
    BRIDGE_KEY,
    CONFIG_TOOL,
    HARNESS,
    NOW,
    OTHER_KEY,
    POLICY,
    POLICY_BYTES,
    POLICY_KEY,
    READ_TOOL,
    RECORD_KEY,
    TOOL,
    UNPINNED_TOOL,
    Clock,
    Harness,
    Run,
    make_config,
    make_observe,
    policy_bytes,
    raw_public,
    seq_clock,
    verify_all,
)

TRUSTED = v.TRUSTED_ONLY
TAINTED = v.UNTRUSTED_INGESTED


# --- Session taint ----------------------------------------------------------

def test_fresh_session_is_trusted_only(harness):
    assert harness.guard.taint_level("never-seen") == TRUSTED


def test_untrusted_ingestion_is_sticky(harness):
    guard = harness.guard
    assert guard.ingest_untrusted("s1") == TAINTED
    assert guard.ingest_untrusted("s1") == TAINTED
    assert guard.taint_level("s1") == TAINTED
    assert guard.taint_level("s2") == TRUSTED
    clean = harness.run(tool_name=CONFIG_TOOL, args={}, request="clean")
    assert clean.status == "record-emitted"
    assert clean.taint == TAINTED
    assert guard.taint_level("s1") == TAINTED


@pytest.mark.parametrize("bad", ["", "has space", None, "x" * 513])
def test_ingest_untrusted_rejects_bad_session_id(harness, bad):
    with pytest.raises(g.CtaGuardError):
        harness.guard.ingest_untrusted(bad)


def test_forged_trusted_claim_cannot_downgrade_taint(harness):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(claimed_taint="TRUSTED_ONLY")
    assert (out.status, out.code) == ("blocked", "CTA_TAINTED_CONTROL_PLANE")
    assert out.taint == TAINTED
    assert out.taint_claim_ignored is True
    assert harness.calls == []
    assert harness.guard.taint_level("s1") == TAINTED


def test_claimed_untrusted_raises_taint_and_it_stays(harness):
    first = harness.run(claimed_taint="UNTRUSTED_INGESTED")
    assert (first.status, first.reason) == ("blocked", "no_step_up_receipt")
    assert harness.guard.taint_level("s1") == TAINTED
    second = harness.run(request="r2")
    assert (second.status, second.reason) == ("blocked", "no_step_up_receipt")
    assert harness.calls == []


def test_trusted_claim_in_clean_session_is_not_reported_as_ignored(harness):
    out = harness.run(claimed_taint="TRUSTED_ONLY")
    assert out.status == "record-emitted"
    assert out.taint_claim_ignored is False


@pytest.mark.parametrize("claim", ["", "MIXED_TAINT", "trusted_only", True, 1])
def test_unknown_taint_claim_is_a_precondition_failure(harness, claim):
    out = harness.run(claimed_taint=claim)
    assert (out.status, out.code, out.reason) == ("precondition-failed", "CTA_BAD_REQUEST", "bad_taint_claim")
    assert harness.calls == []


# --- Tool effect class ------------------------------------------------------

def test_untrusted_read_only_hint_is_ignored(harness):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(runtime_annotations={"readOnlyHint": True, "destructiveHint": False})
    assert out.effect_class == v.STATE_MUTATING
    assert (out.status, out.code) == ("blocked", "CTA_TAINTED_CONTROL_PLANE")
    assert harness.calls == []


def test_pinned_declaration_beats_a_destructive_runtime_hint(harness):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(tool_name=CONFIG_TOOL, args={}, runtime_annotations={"readOnlyHint": False})
    assert out.effect_class == v.READ_ONLY
    assert out.status == "record-emitted"


def test_unknown_tool_defaults_to_state_mutating_with_untrusted_output(harness):
    declaration = harness.guard.declaration_for(UNPINNED_TOOL)
    assert (declaration.effect_class, declaration.output_trust) == (v.STATE_MUTATING, "untrusted")
    harness.guard.ingest_untrusted("s1")
    out = harness.run(tool_name=UNPINNED_TOOL, runtime_annotations={"readOnlyHint": True})
    assert (out.status, out.effect_class) == ("blocked", v.STATE_MUTATING)
    assert harness.calls == []


def test_unknown_tool_in_a_trusted_session_runs_and_then_taints_it(harness):
    first = harness.run(tool_name=UNPINNED_TOOL, request="r1")
    assert (first.status, first.effect_class) == ("record-emitted", v.STATE_MUTATING)
    assert harness.guard.taint_level("s1") == TAINTED
    assert harness.run(tool_name=UNPINNED_TOOL, request="r2").status == "blocked"
    assert len(harness.calls) == 1


def test_read_only_tool_needs_no_receipt_under_taint(harness):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(tool_name=CONFIG_TOOL, args={})
    authorization = out.record_artifacts.authorization.bridge["authorization"]
    assert out.status == "record-emitted"
    assert authorization["decision_basis"] == v.BASIS_READ_ONLY
    assert "step_up_receipt_hash" not in authorization


def test_untrusted_tool_output_taints_the_session_after_dispatch(harness):
    read = harness.run(tool_name=READ_TOOL, args={}, request="r1")
    assert (read.status, read.taint) == ("record-emitted", TRUSTED)
    assert harness.guard.taint_level("s1") == TAINTED
    assert harness.run(request="r2").status == "blocked"


def test_trusted_tool_output_does_not_taint_the_session(harness):
    assert harness.run(tool_name=CONFIG_TOOL, args={}, request="r1").status == "record-emitted"
    assert harness.guard.taint_level("s1") == TRUSTED
    assert harness.run(request="r2").status == "record-emitted"


def test_failing_untrusted_output_tool_still_taints_the_session(harness):
    def boom(**kwargs):
        raise RuntimeError("tool failed")

    out = harness.run(tool_name=READ_TOOL, args={}, fn=boom)
    assert out.status == "dispatch-error"
    assert harness.guard.taint_level("s1") == TAINTED


# --- Gate decisions ---------------------------------------------------------

def test_trusted_session_mutation_is_allowed_on_a_trusted_context_basis(trusted_run):
    out = trusted_run.outcome
    authorization = out.record_artifacts.authorization.bridge["authorization"]
    assert authorization["decision_basis"] == v.BASIS_TRUSTED_CONTEXT
    assert authorization["taint_lattice_level"] == TRUSTED
    assert authorization["tool_effect_class"] == v.STATE_MUTATING
    assert "step_up_receipt_hash" not in authorization
    assert out.result == {"ok": True}
    assert out.tool_entered and out.code is None and out.reason is None
    assert trusted_run.harness.calls == [ARGS]


def test_tainted_mutation_without_receipt_is_blocked_before_tool_entry(harness, monkeypatch):
    signed = []
    real_sign = g.sign_envelope

    def spy(*args, **kwargs):
        signed.append(args[0])
        return real_sign(*args, **kwargs)

    monkeypatch.setattr(g, "sign_envelope", spy)
    harness.guard.ingest_untrusted("s1")
    out = harness.run()
    assert (out.status, out.code, out.reason) == ("blocked", "CTA_TAINTED_CONTROL_PLANE", "no_step_up_receipt")
    assert not out.tool_entered and harness.calls == []
    assert out.authorization is None and out.record_artifacts is None
    assert out.events == ("request_reserved", "taint_evaluated")
    assert signed == []


def test_receipt_is_ignored_when_the_gate_does_not_need_one(harness):
    out = harness.run(receipt="not even json")
    assert out.status == "record-emitted"
    assert "step_up_verified" not in out.events


# --- StepUpReceipt ----------------------------------------------------------

def test_step_up_receipt_allows_a_tainted_mutation(stepup_run):
    out = stepup_run.outcome
    artifacts = out.record_artifacts
    authz = artifacts.authorization
    authorization = authz.bridge["authorization"]
    assert authorization["decision_basis"] == v.BASIS_STEP_UP
    assert authorization["taint_lattice_level"] == TAINTED
    receipt_digest = v.digest_jcs(authz.step_up_receipt)
    assert authorization["step_up_receipt_hash"] == receipt_digest
    assert artifacts.transcript["step_up_receipt_digest"] == receipt_digest
    assert out.events.index("step_up_verified") < out.events.index("bridge_signed")
    assert stepup_run.harness.calls == [ARGS]
    assert verify_all(stepup_run)["step_up_receipt_bound"] is True


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"session": "other-session"}, "different session"),
        ({"request": "other-request"}, "different request"),
        ({"tool_name": "other_tool"}, "different tool"),
        ({"args": {"path": "other.txt"}}, "different arguments"),
        ({"iat": NOW - 1000, "exp": NOW - 1}, "expired"),
        ({"iat": NOW + 1000, "exp": NOW + 1300}, "not yet valid"),
        ({"iat": NOW, "exp": NOW + 60}, "must exceed the 60-second skew"),
        ({"iat": NOW, "exp": NOW + 3601}, "exceeds one hour"),
        ({"kid": v.key_id(raw_public(OTHER_KEY))}, "does not identify the trusted"),
        ({"key": OTHER_KEY}, "signature is invalid"),
        ({"iat": True, "exp": True}, "receipt iat"),
        ({"receipt_id": "has space"}, "receipt_id"),
        ({"approver": ""}, "approver"),
        ({"args_digest": "sha256:ABC"}, "receipt args_digest"),
    ],
)
def test_invalid_receipt_blocks_a_tainted_mutation(harness, overrides, fragment):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(receipt=harness.receipt(**overrides))
    assert (out.status, out.code, out.reason) == ("blocked", "CTA_TAINTED_CONTROL_PLANE", "step_up_receipt_invalid")
    assert fragment in out.detail
    assert not out.tool_entered and harness.calls == []
    assert out.authorization is None and out.record_artifacts is None


def _tamper_signature(receipt, how):
    signature = receipt["signature"]
    if how == "flip-first":
        replacement = "B" if signature[0] == "A" else "A"
        return {**receipt, "signature": replacement + signature[1:]}
    if how == "pad":
        return {**receipt, "signature": signature + "="}
    if how == "alternate-spelling":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        return {**receipt, "signature": signature[:-1] + alphabet[alphabet.index(signature[-1]) ^ 1]}
    if how == "wrong-length":
        return {**receipt, "signature": signature[:80]}
    return {**receipt, "signature": 12345}


@pytest.mark.parametrize(
    "how, fragment",
    [
        ("flip-first", "signature is invalid"),
        ("pad", "not unpadded base64url"),
        ("alternate-spelling", "not canonical base64url"),
        ("wrong-length", "decode to 64 bytes"),
        ("not-a-string", "must be a base64url string"),
    ],
)
def test_malformed_receipt_signature_is_refused(harness, how, fragment):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(receipt=_tamper_signature(harness.receipt(), how))
    assert out.reason == "step_up_receipt_invalid"
    assert fragment in out.detail
    assert harness.calls == []


def _damage(receipt, how):
    if how == "missing-profile":
        return {k: val for k, val in receipt.items() if k != "profile"}
    if how == "extra-field":
        return {**receipt, "note": "x"}
    if how == "wrong-profile":
        return {**receipt, "profile": "cta-step-up-receipt-v2"}
    if how == "missing-body-field":
        return {**receipt, "receipt": {k: val for k, val in receipt["receipt"].items() if k != "exp"}}
    if how == "extra-body-field":
        return {**receipt, "receipt": {**receipt["receipt"], "scope": "*"}}
    return {**receipt, "receipt": "not-an-object"}


@pytest.mark.parametrize(
    "how, fragment",
    [
        ("missing-profile", "missing required fields"),
        ("extra-field", "unknown fields"),
        ("wrong-profile", "unknown step-up receipt profile"),
        ("missing-body-field", "missing required fields"),
        ("extra-body-field", "unknown fields"),
        ("not-an-object", "must be an object"),
    ],
)
def test_receipt_structure_is_exact(harness, how, fragment):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(receipt=_damage(harness.receipt(), how))
    assert out.reason == "step_up_receipt_invalid"
    assert fragment in out.detail
    assert harness.calls == []


@pytest.mark.parametrize(
    "text, fragment",
    [
        ('{"profile": "a", "profile": "b"}', "duplicate key"),
        ('{"profile": NaN}', "non-finite"),
        ('{"profile": 1e999}', "non-finite"),
        ("{not json", "malformed JSON"),
        ("[1, 2]", "must be a JSON object"),
        (b"\xff\xfe", "not valid UTF-8"),
        (12345, "must be a JSON object"),
    ],
)
def test_receipt_json_is_parsed_strictly(harness, text, fragment):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(receipt=text)
    assert out.reason == "step_up_receipt_invalid"
    assert fragment in out.detail
    assert harness.calls == []


def test_receipt_supplied_as_json_bytes_is_accepted(harness):
    harness.guard.ingest_untrusted("s1")
    out = harness.run(receipt=json.dumps(harness.receipt()).encode("utf-8"))
    assert out.status == "record-emitted"


def test_float_spelled_timestamp_is_refused_even_though_its_jcs_form_verifies(harness):
    harness.guard.ingest_untrusted("s1")
    text = json.dumps(harness.receipt()).replace(f'"exp": {NOW + 300}', f'"exp": {NOW + 300}.0')
    assert f"{NOW + 300}.0" in text
    out = harness.run(receipt=text)
    assert out.reason == "step_up_receipt_invalid"
    assert "receipt exp" in out.detail


def test_float_timestamp_in_a_mapping_is_refused_like_the_same_text(harness):
    harness.guard.ingest_untrusted("s1")
    receipt = harness.receipt()
    receipt["receipt"]["exp"] = float(receipt["receipt"]["exp"])  # same JCS bytes, so the signature holds
    out = harness.run(receipt=receipt)
    assert out.reason == "step_up_receipt_invalid"
    assert "receipt exp" in out.detail
    assert harness.calls == []


def test_receipt_cannot_be_replayed_after_request_id_eviction():
    h = Harness(tombstone_capacity=1)
    h.guard.ingest_untrusted("s1")
    receipt = h.receipt(request="r1")
    assert h.run(request="r1", receipt=receipt).status == "record-emitted"
    assert h.run(request="r2", tool_name=CONFIG_TOOL, args={}).status == "record-emitted"
    replay = h.run(request="r1", receipt=receipt)  # r1's tombstone is gone; the receipt is not
    assert (replay.status, replay.reason) == ("blocked", "step_up_receipt_replayed")
    assert len(h.calls) == 2


def test_receipt_ledger_forgets_a_receipt_only_after_it_expires():
    ledger = g._ReceiptLedger()
    assert ledger.spend("a", 100, 0)
    assert not ledger.spend("a", 100, 99)
    assert ledger.spend("a", 200, 100)


# --- Request ids ------------------------------------------------------------

def test_duplicate_request_id_is_refused(harness):
    assert harness.run(request="dup").status == "record-emitted"
    again = harness.run(request="dup")
    assert (again.status, again.code, again.reason) == (
        "precondition-failed", "CTA_REQUEST_ID_REUSED", "request_id_reused",
    )
    assert len(harness.calls) == 1


def test_blocked_request_id_is_still_spent(harness):
    harness.guard.ingest_untrusted("s1")
    assert harness.run(request="r1").status == "blocked"
    retry = harness.run(request="r1", receipt=harness.receipt(request="r1"))
    assert retry.code == "CTA_REQUEST_ID_REUSED"
    assert harness.calls == []


def test_concurrent_duplicate_request_ids_dispatch_once():
    h = Harness()
    outcomes = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        outcomes.append(h.run(request="same"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(h.calls) == 1
    assert sorted(o.status for o in outcomes) == ["precondition-failed"] * 7 + ["record-emitted"]


def test_request_store_evicts_the_oldest_tombstone():
    store = g._RequestStore(2)
    for rid in ("a", "b", "c"):
        assert store.reserve(rid)
        store.finish(rid)
    assert store.reserve("a")  # evicted
    assert not store.reserve("c")


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("session", "", "bad_session_id"),
        ("session", "has space", "bad_session_id"),
        ("session", None, "bad_session_id"),
        ("request", "x" * 513, "bad_request_id"),
        ("request", "caf\u00e9", "bad_request_id"),
        ("tool_name", 5, "bad_tool_name"),
    ],
)
def test_bad_identifiers_fail_the_precondition(harness, field, value, reason):
    out = harness.run(**{field: value})
    assert (out.status, out.code, out.reason) == ("precondition-failed", "CTA_BAD_REQUEST", reason)
    assert harness.calls == [] and out.events == ()


@pytest.mark.parametrize("arguments", [["not", "a", "mapping"], {"x": {1, 2}}, {"x": float("nan")}, {"x": 2**60}, {1: "k"}])
def test_arguments_without_a_canonical_form_fail_the_precondition(harness, arguments):
    out = harness.run(args=arguments)
    assert (out.status, out.reason) == ("precondition-failed", "bad_arguments")
    assert harness.calls == []


def test_non_callable_tool_or_observer_fails_the_precondition(harness):
    for tool_fn, observe in (("nope", make_observe("r")), (harness.tool, None)):
        out = harness.guard.run(
            session_id="s", request_id="r", tool_name=TOOL, tool_fn=tool_fn, arguments=ARGS, observe=observe,
        )
        assert (out.status, out.reason) == ("precondition-failed", "bad_callable")


def test_arguments_are_snapshotted_before_dispatch(harness):
    nested = {"opts": {"a": 1}}

    def mutating_tool(**kwargs):
        kwargs["opts"]["a"] = 2
        return {"ok": True}

    out = harness.run(args=nested, fn=mutating_tool)
    assert out.status == "record-emitted"
    assert nested == {"opts": {"a": 1}}
    assert out.record_artifacts.transcript["tool_call"]["arguments"] == {"opts": {"a": 1}}


# --- Bridge order and validity ---------------------------------------------

def test_bridge_is_signed_and_verified_before_the_tool_is_entered(harness, monkeypatch):
    order = []
    real_sign, real_verify = g.sign_envelope, g.verify_bridge

    def sign(profile, *args, **kwargs):
        if profile == v.BRIDGE_PROFILE:
            order.append("bridge_signed")
        return real_sign(profile, *args, **kwargs)

    def verify(*args, **kwargs):
        order.append("bridge_verified")
        return real_verify(*args, **kwargs)

    def tool(**kwargs):
        order.append("tool_entered")
        return {"ok": True}

    monkeypatch.setattr(g, "sign_envelope", sign)
    monkeypatch.setattr(g, "verify_bridge", verify)
    out = harness.run(fn=tool)
    assert order == ["bridge_signed", "bridge_verified", "tool_entered"]
    assert out.events.index("bridge_signed") < out.events.index("bridge_verified") < out.events.index("tool_entered")


def test_complete_event_order_for_a_record(trusted_run):
    assert trusted_run.outcome.events == (
        "request_reserved", "taint_evaluated", "bridge_signed", "bridge_verified", "tool_entered",
        "tool_returned", "observation_verified", "record_signed", "record_verified",
    )


def test_bridge_that_expires_before_dispatch_blocks_the_tool():
    h = Harness(clock=seq_clock([NOW, NOW + 301]))
    out = h.run()
    assert (out.status, out.code, out.reason) == (
        "authorization-failed", "CTA_AUTHORIZATION_FAILED", "bridge_verification_failed",
    )
    assert "expired" in out.detail
    assert h.calls == [] and not out.tool_entered and out.authorization is None


def test_clock_stepping_back_before_dispatch_blocks_the_tool():
    h = Harness(clock=seq_clock([NOW, NOW - 1]))
    out = h.run()
    assert out.status == "authorization-failed"
    assert "not yet valid" in out.detail
    assert h.calls == []


@pytest.mark.parametrize("bad", [True, False, -1, 0, 1, 1_699_999_999, 1.5, str(NOW), None, 2**53])
def test_invalid_clock_value_fails_closed_before_dispatch(bad):
    h = Harness(clock=Clock(bad))
    out = h.run()
    assert (out.status, out.code, out.reason) == ("adapter-error", "CTA_ADAPTER_ERROR", "adapter_error")
    assert h.calls == [] and not out.tool_entered


def test_bridge_expiry_overflow_fails_closed_before_dispatch():
    h = Harness(clock=Clock(v.SAFE_INT_MAX - 10))
    out = h.run()
    assert out.status == "adapter-error"
    assert h.calls == []


def test_raising_clock_fails_closed_before_dispatch():
    def clock():
        raise RuntimeError("clock unavailable")

    h = Harness(clock=clock)
    out = h.run()
    assert out.status == "adapter-error"
    assert h.calls == []


# --- Dispatch and observation ----------------------------------------------

def test_tool_exception_yields_no_record_but_keeps_a_verifiable_bridge(harness):
    def boom(**kwargs):
        raise RuntimeError("tool failed")

    out = harness.run(fn=boom)
    assert (out.status, out.code, out.reason) == ("dispatch-error", "CTA_DISPATCH_ERROR", "tool_raised")
    assert out.tool_entered and out.record_artifacts is None
    assert out.events[-2:] == ("tool_entered", "tool_raised")
    authz = out.authorization
    checked = v.verify_authorization_artifacts(
        bridge=authz.bridge, declaration=authz.declaration, tool_call=authz.tool_call,
        authorizer_jwk=authz.authorizer_jwk,
    )
    assert checked["bridge_signature"] is True


@pytest.mark.parametrize(
    "verdict, reason",
    [("contradicted", "observation_contradicted"), ("not-established", "observation_not-established")],
)
def test_unestablished_observation_emits_no_record(harness, verdict, reason):
    out = harness.run(observe=make_observe("r1", verdict=verdict))
    assert (out.status, out.code, out.reason) == ("observation-failed", "CTA_OBSERVATION_FAILED", reason)
    assert out.tool_entered and out.authorization is not None and out.record_artifacts is None
    authz = out.authorization
    assert v.verify_authorization_artifacts(
        bridge=authz.bridge, declaration=authz.declaration, tool_call=authz.tool_call,
        authorizer_jwk=authz.authorizer_jwk,
    )["bridge_signature"] is True


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda d: d["observation"].update(request_id="other"), "different request"),
        (lambda d: d["observation"].update(tool_name="other"), "different tool"),
        (lambda d: d["observation"].update(args_digest=v.digest_jcs({"path": "x"})), "different arguments"),
        (lambda d: d["observation"].update(tool_call_count=2), "tool_call_count"),
        (lambda d: d["observation"].update(tool_call_count=True), "tool_call_count"),
        (lambda d: d["observation"].update(tool_call_count=1.0), "tool_call_count"),
        (lambda d: d["observation"].pop("args_digest"), "does not name the observed call"),
        (lambda d: d.update(observed_at=True), "observed_at"),
        (lambda d: d.update(observed_at=NOW - 1), "precedes the authorization"),
        (lambda d: d.update(observer=""), "observer"),
        (lambda d: d.update(extra=1), "unknown fields"),
        (lambda d: d.pop("observer"), "missing required fields"),
        (lambda d: d.update(observation="not-an-object"), "must be an object"),
        (lambda d: d["observation"].update(note=float("inf")), "RFC 8785"),
    ],
)
def test_observation_that_does_not_match_the_call_emits_no_record(harness, mutate, fragment):
    out = harness.run(observe=make_observe("r1", mutate=mutate))
    assert (out.status, out.reason) == ("observation-failed", "observation_binding_mismatch")
    assert fragment in out.detail
    assert out.tool_entered and out.record_artifacts is None and out.authorization is not None


def test_observer_exception_emits_no_record(harness):
    def observe(result):
        raise RuntimeError("observer unavailable")

    out = harness.run(observe=observe)
    assert (out.status, out.reason) == ("observation-failed", "observer_error")
    assert out.record_artifacts is None


@pytest.mark.parametrize(
    "returned",
    [None, "established", g.Observation("maybe", {}, None), g.Observation("established", ["x"], None)],
)
def test_malformed_observation_emits_no_record(harness, returned):
    out = harness.run(observe=lambda result: returned)
    assert (out.status, out.reason) == ("observation-failed", "observation_invalid")


def test_oversized_transcript_fails_finalization_and_keeps_the_authorization():
    h = Harness(max_transcript_bytes=64)
    out = h.run()
    assert (out.status, out.reason) == ("adapter-error", "finalization_failed")
    assert out.tool_entered and out.authorization is not None and out.record_artifacts is None


def test_record_issued_before_the_authorization_is_refused():
    h = Harness(clock=seq_clock([NOW, NOW, NOW - 1]))
    out = h.run()
    assert (out.status, out.reason) == ("adapter-error", "finalization_failed")
    assert out.record_artifacts is None


def test_observation_dated_after_the_record_is_refused():
    h = Harness()
    out = h.run(observe=make_observe("r1", observed_at=NOW + 10))
    assert (out.status, out.reason) == ("adapter-error", "finalization_failed")


def test_response_projection_without_a_canonical_form_fails_finalization(harness):
    def observe(result):
        document = make_observe("r1")(result).document
        return g.Observation("established", document, object())

    out = harness.run(observe=observe)
    assert (out.status, out.reason) == ("adapter-error", "finalization_failed")


# --- The emitted record -----------------------------------------------------

def test_record_is_schema_valid_signed_and_bound_to_the_bridge(trusted_run):
    artifacts = trusted_run.outcome.record_artifacts
    record = artifacts.record
    bridge = artifacts.authorization.bridge
    authorization_id = bridge["authorization"]["authorization_id"]

    validate_json(record)
    verify_record(record, trusted_run.guard.record_jwk, now=NOW, max_age_seconds=None)
    assert record["origin"] == {
        "kind": "third-party-control-plane", "producer": HARNESS, "source_event_id": authorization_id,
    }
    assert record["runtime"]["platform"] == "software-only"
    assert record["appraisal"]["status"] == "none"
    assert record["policy"]["enforcement_mode"] == "enforce"
    assert record["references"] == [{
        "rel": "authorized-intent", "id": authorization_id,
        "resolver": ARTIFACT_STORE, "digest": v.digest_jcs(bridge),
    }]
    assert record["subject"] == g.did_key(RECORD_KEY)
    assert v.did_key_public_bytes(record["subject"]) == raw_public(RECORD_KEY)
    assert record["cnf"]["jwk"] == key_to_jwk(RECORD_KEY)
    assert record["tool_transcript"] == {
        "hash": v.sha256_prefixed(v.canonical_bytes(artifacts.transcript)), "call_count": 1,
    }
    assert authorization_id.startswith("urn:sha256:")


def test_record_policy_hash_and_measurement_commit_to_the_exact_policy_bytes(trusted_run):
    record = trusted_run.outcome.record_artifacts.record
    assert record["policy"]["bundle_hash"] == v.sha256_prefixed(POLICY_BYTES)
    assert record["runtime"]["measurement"] == software_measurement(
        HARNESS, record["subject"], record["policy"]["bundle_hash"],
    )


def test_changing_one_policy_byte_changes_the_hash_and_the_measurement(trusted_run):
    mutated_bytes = POLICY_BYTES.replace(b"read_config", b"read_confiG")
    assert len(mutated_bytes) == len(POLICY_BYTES) and mutated_bytes != POLICY_BYTES
    h = Harness(policy_bundle=mutated_bytes)
    mutated = Run(h, h.run())
    original = trusted_run.outcome.record_artifacts.record
    changed = mutated.outcome.record_artifacts.record
    assert changed["policy"]["bundle_hash"] != original["policy"]["bundle_hash"]
    assert changed["runtime"]["measurement"] != original["runtime"]["measurement"]
    with pytest.raises(v.CtaVerifyError, match="bundle_hash"):
        verify_all(mutated)  # the verifier holds the original bytes


def test_all_artifact_checks_pass_for_a_trusted_run(trusted_run):
    checked = verify_all(trusted_run)
    assert set(checked) == {
        "bridge_signature", "authorization_id_bound_to_decision", "declaration_bound", "tool_call_bound",
        "record_signature", "reference_matches_supplied_bridge", "subject_binds_cnf_jwk",
        "policy_bytes_bound", "transcript_bound_and_hashed",
    }
    assert all(checked.values())


def test_default_real_time_clock_emits_a_record():
    guard = g.CtaGuard(make_config())
    out = guard.run(
        session_id="s", request_id="r", tool_name=TOOL, tool_fn=lambda **kw: {"ok": True},
        arguments=ARGS, observe=make_observe("r", observed_at="now"),
    )
    assert out.status == "record-emitted"
    assert abs(out.record_artifacts.record["iat"] - time.time()) < 60


def test_public_keys_are_returned_as_copies(harness):
    jwk = harness.guard.authorizer_jwk
    assert jwk["kid"] == v.key_id(raw_public(BRIDGE_KEY))
    jwk["x"] = "tampered"
    assert harness.guard.authorizer_jwk["x"] != "tampered"
    record_jwk = harness.guard.record_jwk
    record_jwk.clear()
    assert harness.guard.record_jwk == key_to_jwk(RECORD_KEY)


# --- Policy bundle ----------------------------------------------------------

@pytest.mark.parametrize(
    "bundle, fragment",
    [
        (b"", "non-empty bytes"),
        ("{}", "non-empty bytes"),
        (b"\xff\xfe", "not valid UTF-8"),
        (b'{"profile": "a", "profile": "b"}', "duplicate key"),
        (b'{"x": NaN}', "non-finite"),
        (b"[]", "exactly the fields"),
        (policy_bytes(profile="other/v9"), "unknown policy profile"),
        (policy_bytes(step_up_key_id="sha256:xyz"), "step_up_key_id"),
        (policy_bytes(tools=[]), "tools must be an object"),
        (policy_bytes(extra=1), "exactly the fields"),
        (policy_bytes(tools={"bad name": {"effect_class": "READ_ONLY", "output_trust": "trusted"}}), "tool name"),
        (policy_bytes(tools={TOOL: {"effect_class": "PRIVILEGED_ACTUATE", "output_trust": "trusted"}}), "effect_class"),
        (policy_bytes(tools={TOOL: {"effect_class": "READ_ONLY", "output_trust": "maybe"}}), "output_trust"),
        (policy_bytes(tools={TOOL: {"effect_class": "READ_ONLY"}}), "exactly the fields"),
    ],
)
def test_policy_bundle_is_parsed_strictly(bundle, fragment):
    with pytest.raises(g.CtaGuardError, match=re.escape(fragment)):
        g.load_policy(bundle)


def test_policy_bundle_with_no_tools_is_valid_and_every_tool_is_unknown():
    policy = g.load_policy(policy_bytes(tools={}))
    assert policy.tools == {}
    h = Harness(policy_bundle=policy_bytes(tools={}))
    assert h.guard.declaration_for(TOOL).effect_class == v.STATE_MUTATING


def test_loaded_policy_matches_the_bundle():
    policy = g.load_policy(POLICY_BYTES)
    assert policy.step_up_key_id == POLICY["step_up_key_id"]
    assert policy.tools[READ_TOOL] == g.ToolDeclaration(READ_TOOL, v.READ_ONLY, "untrusted")
    assert policy.tools[TOOL].to_dict() == {
        "profile": "cta-tool-declaration/v1", "tool": TOOL, "effect_class": "STATE_MUTATING",
        "output_trust": "trusted",
    }


# --- Configuration ----------------------------------------------------------

def test_config_rejects_a_private_policy_engine_jwk():
    with pytest.raises(g.CtaGuardError, match="private"):
        g.CtaGuard(make_config(policy_engine_jwk={**key_to_jwk(POLICY_KEY), "d": "AAAA"}))


def test_config_rejects_a_policy_engine_key_the_policy_does_not_pin():
    with pytest.raises(g.CtaGuardError, match="step_up_key_id"):
        g.CtaGuard(make_config(policy_engine_jwk=key_to_jwk(OTHER_KEY)))


@pytest.mark.parametrize("field", ["bridge_key", "record_key"])
def test_config_rejects_reusing_a_key_across_roles(field):
    other = RECORD_KEY if field == "bridge_key" else BRIDGE_KEY
    with pytest.raises(g.CtaGuardError, match="pairwise distinct"):
        g.CtaGuard(make_config(**{field: other}))


@pytest.mark.parametrize("field", ["bridge_key", "record_key"])
def test_config_rejects_non_ed25519_keys(field):
    with pytest.raises(g.CtaGuardError, match="Ed25519PrivateKey"):
        g.CtaGuard(make_config(**{field: "not a key"}))


@pytest.mark.parametrize(
    "field, value",
    [
        ("bridge_validity_seconds", 0), ("bridge_validity_seconds", True),
        ("max_transcript_bytes", -1), ("tombstone_capacity", 1.5),
    ],
)
def test_config_rejects_non_positive_integers(field, value):
    with pytest.raises(g.CtaGuardError, match=field):
        g.CtaGuard(make_config(**{field: value}))


@pytest.mark.parametrize(
    "field, value",
    [
        ("model_provider", " "), ("model_id", ""), ("data_class", None),
        ("authorizer", "has space"), ("resolver", ""), ("workload_digest", "sha256:abc"),
    ],
)
def test_config_rejects_blank_or_malformed_provenance_inputs(field, value):
    with pytest.raises(g.CtaGuardError, match=field):
        g.CtaGuard(make_config(**{field: value}))


def test_policy_key_is_pinned_by_the_policy_bytes_not_by_the_caller():
    other_policy = policy_bytes(step_up_key_id=v.key_id(raw_public(OTHER_KEY)))
    h = Harness(policy_bundle=other_policy, policy_engine_jwk=key_to_jwk(OTHER_KEY))
    h.guard.ingest_untrusted("s1")
    out = h.run(receipt=h.receipt())  # signed by POLICY_KEY, which this policy does not trust
    assert out.reason == "step_up_receipt_invalid"
    assert h.calls == []
