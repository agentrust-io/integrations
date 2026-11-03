"""Coordinator lifecycle, fail-closed classification, and strict input/clock handling."""

from __future__ import annotations

import dataclasses
import threading
import time

import pytest

import pic_trace_guard as g
from conftest import IMPACT, MARKER, TOOL, make_config


def _seq_clock(values):
    it = iter(values)
    last = {"v": values[-1]}

    def _clock():
        try:
            last["v"] = next(it)
        except StopIteration:
            pass
        return last["v"]

    return _clock


# --- Lifecycle -------------------------------------------------------------

def test_hook_failure_before_bridge_is_allowed_no_dispatch(coordinator, runner, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("sign failed")

    monkeypatch.setattr(g, "sign_bridge", boom)
    outcome, info = runner(coordinator, rid="hook-fail")
    assert outcome.status == "post-allow-error"
    assert outcome.pic_decision == "allowed"
    assert outcome.absence["reason"] == "hook_failed_before_bridge"
    assert outcome.record_artifacts is None and outcome.authorization is None
    assert info["count"] == 0  # tool never dispatched
    assert coordinator._store.peek("hook-fail") == {}


def test_store_transition_failure_still_classified_allowed(runner):
    class _FailOnTransition(g.InMemoryContextStore):
        def transition(self, *a, **k):
            raise g.AdapterError("transition unavailable")

    coordinator = g.PicTraceCoordinator(make_config(), store=_FailOnTransition())
    outcome, info = runner(coordinator, rid="store-fail")
    # The store write is where hook-entry proof could be lost; the Event must prevent
    # this being read as a PIC block.
    assert outcome.pic_decision == "allowed"
    assert outcome.status == "post-allow-error"
    assert outcome.absence["reason"] == "hook_failed_before_bridge"
    assert outcome.authorization is None
    assert outcome.record_artifacts is None
    assert info["count"] == 0
    assert coordinator._store.peek("store-fail") == {}


def test_tool_raises_after_bridge_preserves_authorization(coordinator, runner):
    def raising_tool(path, sb, info):
        raise RuntimeError("tool boom")

    outcome, info = runner(coordinator, rid="tool-raise", tool_behavior=raising_tool)
    assert outcome.status == "post-allow-error"
    assert outcome.pic_decision == "allowed"
    assert outcome.absence["reason"] == "tool_error_after_allow"
    assert outcome.authorization is not None
    assert outcome.record_artifacts is None
    assert info["count"] == 1 and info["bridge_state_at_entry"] == "bridged"
    assert coordinator._store.peek("tool-raise") == {}


def test_observation_raises_preserves_authorization_and_envelope(coordinator, runner):
    def raising_observe(envelope, sb, info):
        raise RuntimeError("observe boom")

    outcome, _ = runner(coordinator, rid="obs-raise", observe_behavior=raising_observe)
    assert outcome.status == "post-allow-error"
    assert outcome.pic_decision == "allowed"
    assert outcome.authorization is not None
    assert outcome.envelope == {"isError": False, "result": {"deleted": True}}
    assert outcome.record_artifacts is None
    assert coordinator._store.peek("obs-raise") == {}


def test_finalization_failure_preserves_authorization(coordinator, runner, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("build_record failed")

    monkeypatch.setattr(g, "build_record", boom)
    outcome, _ = runner(coordinator, rid="final-fail")
    assert outcome.status == "post-allow-error"
    assert outcome.pic_decision == "allowed"
    assert outcome.absence["reason"] == "finalization_failed"
    assert outcome.authorization is not None
    assert outcome.record_artifacts is None
    assert outcome.envelope == {"isError": False, "result": {"deleted": True}}
    assert coordinator._store.peek("final-fail") == {}


def test_non_json_tool_result_with_canonicalizable_projection(coordinator, runner):
    class Weird:
        pass

    weird = Weird()

    def tool(path, sb, info):
        (sb / MARKER).unlink()
        return weird

    def observe(envelope, sb, info):
        return g.Observation(verdict="established", document={"ok": True}, response_projection={"projection": "redacted"})

    outcome, _ = runner(coordinator, rid="nonjson", tool_behavior=tool, observe_behavior=observe)
    assert outcome.status == "record-emitted"
    assert outcome.envelope["result"] is weird  # runtime value preserved, never canonicalized
    assert outcome.record_artifacts is not None
    assert outcome.record_artifacts.transcript["tool_response"] == {"projection": "redacted"}


def test_success_envelope_without_hook_entry_is_adapter_error(coordinator, runner, monkeypatch):
    def fake_guard(tool_name, tool_fn, **kwargs):
        def guarded(**call_kwargs):
            return {"isError": False, "result": {"ok": True}}
        return guarded

    monkeypatch.setattr(g, "guard_mcp_tool", fake_guard)
    outcome, _ = runner(coordinator, rid="no-hook")
    assert outcome.status == "adapter-error"
    assert outcome.pic_decision == "not-evaluated"
    assert outcome.absence["reason"] == "no_hook_entry"
    assert coordinator._store.peek("no-hook") == {}


def test_keyboardinterrupt_escapes_but_context_is_cleaned(coordinator, runner):
    def ki(envelope, sb, info):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        runner(coordinator, rid="ki-1", observe_behavior=ki)
    assert coordinator._store.peek("ki-1") == {}  # finally ran despite BaseException


@pytest.mark.parametrize("rid,kwargs", [
    ("na-block", {"tamper": True}),
    ("na-tool", {"tool_behavior": lambda p, sb, i: (_ for _ in ()).throw(RuntimeError("x"))}),
    ("na-obs", {"observe_behavior": lambda e, sb, i: (_ for _ in ()).throw(RuntimeError("x"))}),
    ("na-done", {}),  # success path also leaves no active context
])
def test_no_active_context_after_any_path(coordinator, runner, rid, kwargs):
    runner(coordinator, rid=rid, **kwargs)
    assert coordinator._store.peek(rid) == {}


# --- Observation verdict + callback contract -------------------------------

@pytest.mark.parametrize("verdict", ["contradicted", "not-established"])
def test_non_established_observation_preserves_authorization(coordinator, runner, verdict):
    outcome, _ = runner(coordinator, rid=f"obs-{verdict}", verdict=verdict)
    assert outcome.status == "observation-failed"
    assert outcome.pic_decision == "allowed"
    assert outcome.authorization is not None
    assert outcome.record_artifacts is None
    assert outcome.absence["reason"] == f"observation_{verdict}"
    assert coordinator._store.peek(f"obs-{verdict}") == {}


@pytest.mark.parametrize("make_obs,label", [
    (lambda: (lambda e, sb, i: {"not": "observation"}), "not-observation"),
    (lambda: (lambda e, sb, i: None), "none"),
    (lambda: (lambda e, sb, i: g.Observation("bogus", {"a": 1}, {})), "bad-verdict"),
    (lambda: (lambda e, sb, i: g.Observation("established", ["not-a-mapping"], {})), "doc-not-mapping"),
])
def test_invalid_observation_contract_is_adapter_error(coordinator, runner, make_obs, label):
    outcome, _ = runner(coordinator, rid="bad-obs", observe_behavior=make_obs())
    assert outcome.status == "post-allow-error"
    assert outcome.pic_decision == "allowed"
    assert outcome.authorization is not None
    assert outcome.record_artifacts is None
    assert outcome.absence["reason"] == "adapter_error"
    assert coordinator._store.peek("bad-obs") == {}


# --- Preconditions (before any store) --------------------------------------

@pytest.mark.parametrize("kwargs,reason", [
    ({"path": MARKER}, "no_proposal"),
    ({"path": MARKER, "__pic": None, "__pic_request_id": "x"}, "no_proposal"),
    ({"path": MARKER, "__pic": {"x": 1}}, "bad_request_id"),
    ({"path": MARKER, "__pic": {"x": 1}, "request_id": "business-only"}, "bad_request_id"),
    ({"path": MARKER, "__pic": {"x": 1}, "__pic_request_id": ""}, "bad_request_id"),
    ({"path": MARKER, "__pic": {"x": 1}, "__pic_request_id": " x"}, "bad_request_id"),
    ({"path": MARKER, "__pic": {"x": 1}, "__pic_request_id": "x "}, "bad_request_id"),
])
def test_preconditions_fail_before_guard(kwargs, reason):
    coordinator = g.PicTraceCoordinator(make_config())
    outcome = coordinator.run(
        tool_name=TOOL, tool_fn=lambda *a, **k: {"deleted": True}, kwargs=kwargs, observe=lambda e: None,
    )
    assert outcome.status == "precondition-failed"
    assert outcome.pic_decision == "not-evaluated"
    assert outcome.absence["reason"] == reason


def test_overlong_request_id_rejected_before_store():
    class _SpyStore(g.InMemoryContextStore):
        def __init__(self):
            super().__init__()
            self.reserve_calls = 0

        def reserve(self, request_id):
            self.reserve_calls += 1
            super().reserve(request_id)

    spy = _SpyStore()
    coordinator = g.PicTraceCoordinator(make_config(), store=spy)
    overlong = "a" * (make_config().max_request_id_len + 1)
    outcome = coordinator.run(
        tool_name=TOOL, tool_fn=lambda *a, **k: {"deleted": True},
        kwargs={"path": MARKER, "__pic": {"x": 1}, "__pic_request_id": overlong}, observe=lambda e: None,
    )
    assert outcome.status == "precondition-failed"
    assert outcome.absence["reason"] == "bad_request_id"
    assert spy.reserve_calls == 0  # length gate precedes every store implementation


# --- Argument-binding block (real PIC 0.9.1 behaviour) ---------------------

def test_argument_binding_mismatch_blocks(coordinator, runner):
    outcome, info = runner(coordinator, rid="arg-mismatch", live_path="other.txt")
    assert outcome.status == "pic-blocked"
    assert outcome.pic_decision == "blocked"
    assert outcome.absence["error_code"] == "PIC_ARG_BINDING_MISMATCH"
    assert info["count"] == 0
    assert outcome.authorization is None and outcome.record_artifacts is None


# --- Defense-in-depth hook invariant (unreachable via run()) ---------------

def test_hook_refuses_non_proposal_backed_allow_sets_entry():
    class FakeDecision:
        proposal_present = False
        intent_digest = None
        args_digest = None
        request_id = "rid"
        tool = TOOL
        impact = IMPACT

        def to_audit_bytes(self):
            return b"{}"

    coordinator = g.PicTraceCoordinator(make_config())
    event = threading.Event()
    hook = coordinator._make_hook("rid", event)
    with pytest.raises(g.AdapterError):
        hook(FakeDecision(), object())
    assert event.is_set()  # hook entry recorded before the proposal-backed refusal


# --- Strict policy-bundle inputs (construction fails closed) ---------------

@pytest.mark.parametrize("policy_bytes,label", [
    (b"\xff\xfe", "malformed-utf8"),
    (b"{not json", "malformed-json"),
    (b'{"x": NaN}', "nan"),
    (b'{"x": Infinity}', "infinity"),
    (b'{"a": {"b": 1, "b": 2}}', "nested-duplicate-keys"),
    (b'{"a": 1, "a": 2}', "top-level-duplicate-keys"),
    (b"[1, 2, 3]", "non-object"),
    (b'{"require_pic_for_impacts": 123}', "structurally-invalid-policy"),
])
def test_policy_bundle_strict_parse(policy_bytes, label):
    with pytest.raises(g.AdapterError):
        g.PicTraceCoordinator(make_config(policy_bytes=policy_bytes))


def test_policy_bundle_must_be_bytes():
    with pytest.raises(g.AdapterError):
        g.PicTraceCoordinator(dataclasses.replace(make_config(), policy_bundle="not-bytes"))


# --- Integer settings reject bool/float/non-positive -----------------------

@pytest.mark.parametrize("field", ["bridge_validity_seconds", "max_transcript_bytes", "max_request_id_len"])
@pytest.mark.parametrize("bad", [True, 0.5, 0, -1])
def test_integer_settings_reject_bad_scalars(field, bad):
    with pytest.raises(g.AdapterError):
        g.PicTraceCoordinator(dataclasses.replace(make_config(), **{field: bad}))


# --- Clock validation ------------------------------------------------------

@pytest.mark.parametrize("bad", [-1, True, 1.5, 2**53])
def test_safe_timestamp_rejects_bad_clock(bad):
    coordinator = g.PicTraceCoordinator(make_config(), clock=lambda: bad)
    with pytest.raises(g.AdapterError):
        coordinator._safe_timestamp()


def test_expiry_overflow_fails_closed(runner):
    coordinator = g.PicTraceCoordinator(make_config(), clock=lambda: g._SAFE_INT_MAX)
    outcome, info = runner(coordinator, rid="expiry-overflow")
    assert outcome.status == "post-allow-error"
    assert outcome.pic_decision == "allowed"
    assert outcome.absence["reason"] == "hook_failed_before_bridge"
    assert info["count"] == 0
    assert coordinator._store.peek("expiry-overflow") == {}


def test_record_iat_preceding_authorization_fails_closed(runner):
    now = int(time.time())
    coordinator = g.PicTraceCoordinator(make_config(), clock=_seq_clock([now, now - 100]))
    outcome, _ = runner(coordinator, rid="iat-backwards")
    assert outcome.status == "post-allow-error"
    assert outcome.absence["reason"] == "finalization_failed"
    assert outcome.authorization is not None
    assert coordinator._store.peek("iat-backwards") == {}


# --- Transcript / observation canonicalization -----------------------------

def test_oversized_transcript_fails_closed(runner):
    coordinator = g.PicTraceCoordinator(dataclasses.replace(make_config(), max_transcript_bytes=1))
    outcome, _ = runner(coordinator, rid="big-transcript")
    assert outcome.status == "post-allow-error"
    assert outcome.absence["reason"] == "finalization_failed"
    assert outcome.authorization is not None
    assert coordinator._store.peek("big-transcript") == {}


def test_noncanonicalizable_observation_document_fails_closed(coordinator, runner):
    def observe(envelope, sb, info):
        return g.Observation(verdict="established", document={"bad": object()}, response_projection={"ok": 1})

    outcome, _ = runner(coordinator, rid="bad-doc", observe_behavior=observe)
    assert outcome.status == "post-allow-error"
    assert outcome.absence["reason"] == "finalization_failed"
    assert outcome.authorization is not None
    assert coordinator._store.peek("bad-doc") == {}


def test_noncanonicalizable_response_projection_fails_closed(coordinator, runner):
    def observe(envelope, sb, info):
        return g.Observation(verdict="established", document={"ok": 1}, response_projection=object())

    outcome, _ = runner(coordinator, rid="bad-proj", observe_behavior=observe)
    assert outcome.status == "post-allow-error"
    assert outcome.absence["reason"] == "finalization_failed"
    assert outcome.authorization is not None
    assert coordinator._store.peek("bad-proj") == {}
