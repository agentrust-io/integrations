"""Tests for replay_pic_verification: sanitized args, reserved-key rejection, exact
policy bytes, full control forwarding, request-id validation, allow/block, and
current-re-evaluation semantics."""

from __future__ import annotations

import pytest
from pic_standard.errors import PICError

import pic_trace_guard as g
from conftest import MARKER, POLICY_BYTES, TOOL, build_proposal


def _pic_code(exc):
    code = getattr(exc, "code", "")
    return str(getattr(code, "value", code)) + "|" + str(exc)


def test_replay_valid_current_reevaluation(fixtures_dir):
    result = g.replay_pic_verification(
        proposal=build_proposal(), policy_bundle=POLICY_BYTES, tool_args={"path": MARKER},
        verify_evidence=True, proposal_base_dir=fixtures_dir, strict_trust=True,
    )
    assert isinstance(result, tuple) and len(result) == 2
    action_proposal, _ = result
    assert action_proposal is not None  # allowed re-evaluation


def test_replay_tampered_evidence_raises_evidence_failed(fixtures_dir):
    with pytest.raises(PICError) as ei:
        g.replay_pic_verification(
            proposal=build_proposal(tamper=True), policy_bundle=POLICY_BYTES, tool_args={"path": MARKER},
            verify_evidence=True, proposal_base_dir=fixtures_dir, strict_trust=True,
        )
    assert "PIC_EVIDENCE_FAILED" in _pic_code(ei.value)


def test_replay_argument_binding_mismatch(fixtures_dir):
    with pytest.raises(PICError) as ei:
        g.replay_pic_verification(
            proposal=build_proposal(), policy_bundle=POLICY_BYTES, tool_args={"path": "other.txt"},
            verify_evidence=True, proposal_base_dir=fixtures_dir, strict_trust=True,
        )
    assert "PIC_ARG_BINDING_MISMATCH" in _pic_code(ei.value)


@pytest.mark.parametrize("bad_key", ["__pic", "__pic_request_id"])
def test_replay_rejects_reserved_keys_in_tool_args(bad_key):
    with pytest.raises(g.AdapterError):
        g.replay_pic_verification(
            proposal={"action": {"tool": TOOL}}, policy_bundle=POLICY_BYTES, tool_args={bad_key: "x"},
        )


@pytest.mark.parametrize("bad_rid", ["", " x", "x ", "a" * (g._DEFAULT_MAX_REQUEST_ID_LEN + 1), 123])
def test_replay_rejects_invalid_request_id(bad_rid):
    with pytest.raises(g.AdapterError):
        g.replay_pic_verification(
            proposal={"action": {"tool": TOOL}}, policy_bundle=POLICY_BYTES,
            tool_args={"path": MARKER}, request_id=bad_rid,
        )


@pytest.mark.parametrize("policy_bytes", [
    b"\xff\xfe", b"{not json", b'{"x": NaN}', b'{"x": Infinity}',
    b'{"a": 1, "a": 2}', b"[1, 2, 3]", b'{"require_pic_for_impacts": 123}',
])
def test_replay_parses_supplied_policy_strictly(policy_bytes):
    # Proves replay parses the EXACT supplied bytes through the shared strict loader.
    with pytest.raises(g.AdapterError):
        g.replay_pic_verification(
            proposal={"action": {"tool": TOOL}}, policy_bundle=policy_bytes, tool_args={"path": MARKER},
        )


def test_replay_forwards_all_controls_and_inserts_request_id(monkeypatch):
    captured = {}

    def spy(**kwargs):
        captured.update(kwargs)
        return ("action_proposal", "tool_args")

    monkeypatch.setattr(g, "evaluate_pic_for_tool_call", spy)
    s_limits, s_pbd, s_erd, s_kr = object(), object(), object(), object()
    g.replay_pic_verification(
        proposal={"action": {"tool": TOOL}}, policy_bundle=POLICY_BYTES, tool_args={"path": MARKER},
        limits=s_limits, verify_evidence=False, proposal_base_dir=s_pbd, evidence_root_dir=s_erd,
        key_resolver=s_kr, strict_trust=False, request_id="rid-1",
    )
    assert captured["tool_name"] == TOOL
    assert captured["limits"] is s_limits
    assert captured["verify_evidence"] is False
    assert captured["proposal_base_dir"] is s_pbd
    assert captured["evidence_root_dir"] is s_erd
    assert captured["key_resolver"] is s_kr
    assert captured["strict_trust"] is False
    assert captured["policy"] is not None
    assert captured["tool_args"]["path"] == MARKER
    assert captured["tool_args"]["__pic"] == {"action": {"tool": TOOL}}
    assert captured["tool_args"]["__pic_request_id"] == "rid-1"


def test_replay_omits_request_id_when_not_supplied(monkeypatch):
    captured = {}

    def spy(**kwargs):
        captured.update(kwargs)
        return ("action_proposal", "tool_args")

    monkeypatch.setattr(g, "evaluate_pic_for_tool_call", spy)
    g.replay_pic_verification(
        proposal={"action": {"tool": TOOL}}, policy_bundle=POLICY_BYTES, tool_args={"path": MARKER},
    )
    assert "__pic_request_id" not in captured["tool_args"]


def test_replay_delegates_to_live_pipeline(monkeypatch):
    # Current re-evaluation (not a cached/historical artifact): it calls the live pipeline.
    calls = {"n": 0}

    def spy(**kwargs):
        calls["n"] += 1
        return ("action_proposal", "tool_args")

    monkeypatch.setattr(g, "evaluate_pic_for_tool_call", spy)
    g.replay_pic_verification(proposal={"action": {"tool": TOOL}}, policy_bundle=POLICY_BYTES, tool_args={"path": MARKER})
    assert calls["n"] == 1
