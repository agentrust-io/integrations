"""Tests for the AgenTrust Claude Code capture engine.

Covers the stdlib-only path (snapshot / diff / observed-category scoping) with no
network or signing dependencies, so it runs in CI without the crypto packages.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

import capture  # noqa: E402


def _base(**over):
    snap = {
        "observed": ["skills", "policy", "prompt", "mcp", "tools"],
        "skills": {"trace": "sha256:" + "a" * 64},
        "mcp_servers": ["Slack"],
        "tools": ["Bash", "mcp:Slack"],
        "hashes": {"system_prompt": "sha256:" + "1" * 64, "policy_bundle": "sha256:" + "2" * 64},
    }
    snap.update(over)
    return snap


def test_identical_snapshots_have_no_diff():
    assert capture.diff(_base(), _base()) == []


def test_added_skill_is_detected():
    cur = _base(skills={"trace": "sha256:" + "a" * 64, "rogue": "sha256:" + "b" * 64})
    out = capture.diff(_base(), cur)
    assert {"change": "added", "what": "skill", "detail": "rogue"} in out


def test_changed_permissions_detected():
    cur = _base(hashes={"system_prompt": "sha256:" + "1" * 64, "policy_bundle": "sha256:" + "9" * 64})
    out = capture.diff(_base(), cur)
    assert any(c["what"] == "permissions" and c["change"] == "changed" for c in out)


def test_added_mcp_server_detected():
    cur = _base(mcp_servers=["Slack", "ShadowExfil"], tools=["Bash", "mcp:Slack", "mcp:ShadowExfil"])
    out = capture.diff(_base(), cur)
    assert {"change": "added", "what": "MCP server", "detail": "ShadowExfil"} in out


def test_disk_only_snapshot_does_not_flag_unobserved_live_roster():
    """A hook snapshot (no tools/mcp observed) must not report the baseline's
    live roster as removed -- only skills/policy/prompt are comparable."""
    baseline = _base()  # observed everything, has tools + mcp
    hook_snap = {
        "observed": ["skills", "policy", "prompt"],
        "skills": {"trace": "sha256:" + "a" * 64},
        "mcp_servers": [],
        "tools": [],
        "hashes": {"system_prompt": "sha256:" + "1" * 64, "policy_bundle": "sha256:" + "2" * 64},
    }
    assert capture.diff(baseline, hook_snap) == []


def test_snapshot_shape_from_real_home(tmp_path, monkeypatch):
    """snapshot() runs and returns the documented keys."""
    snap = capture.snapshot({"model_id": "claude-x", "builtin_tools": ["Bash"], "mcp_servers": ["Slack"]})
    for key in ("agent_id", "observed", "skills", "hashes", "tools", "model"):
        assert key in snap
    assert "tools" in snap["observed"] and "mcp" in snap["observed"]
    assert snap["hashes"]["tool_catalog"].startswith("sha256:")


def _isolate_state(tmp_path, monkeypatch):
    """Point the engine's baseline/latest state at a temp dir."""
    state = tmp_path / "agentrust"
    monkeypatch.setattr(capture, "STATE_DIR", state)
    monkeypatch.setattr(capture, "BASELINE", state / "baseline.json")
    monkeypatch.setattr(capture, "LATEST", state / "session-latest.json")


class _Args:
    live_context = None
    out = "."
    json = False
    sign = False


def test_verify_detects_drift_introduced_after_baseline(tmp_path, monkeypatch, capsys):
    """verify must re-snapshot, not trust a stale session-latest.json.

    Regression: verify used `_load(LATEST) or snapshot(...)`, so drift added
    after session start (a rogue skill, a widened permission) was reported as
    "nothing added, nothing subtracted" against the cached snapshot.
    """
    _isolate_state(tmp_path, monkeypatch)

    renderable = {
        "captured_at": "2026-01-01T00:00:00Z",
        "agent_id": "spiffe://claude-code.local/dev/box",
        "model": {"provider": "anthropic", "model_id": "claude-x", "version": "1"},
        "allow_rules": [],
        "hashes": {
            "system_prompt": "sha256:" + "1" * 64, "policy_bundle": "sha256:" + "2" * 64,
            "skills_set": "sha256:" + "3" * 64, "tool_catalog": "sha256:" + "4" * 64,
        },
    }
    clean = _base(skills={"deploy": "sha256:" + "a" * 64}, **renderable)
    capture._save(capture.BASELINE, clean)
    # A stale latest from an earlier, clean point in the session.
    capture._save(capture.LATEST, clean)

    # The agent has since drifted: a rogue skill appeared on disk.
    drifted = _base(skills={"deploy": "sha256:" + "a" * 64, "exfil": "sha256:" + "b" * 64}, **renderable)
    monkeypatch.setattr(capture, "snapshot", lambda live=None: drifted)

    assert capture.cmd_verify(_Args()) == 0
    out = capsys.readouterr().out
    assert "ADDED skill: exfil" in out
    assert "1 change(s) since baseline" in out
    # the success line must NOT appear when drift is present
    assert "Verified: nothing added, nothing subtracted" not in out
