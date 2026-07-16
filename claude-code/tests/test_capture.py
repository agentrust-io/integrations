"""Tests for the AgenTrust Claude Code capture engine.

Covers the stdlib-only path (snapshot / diff / observed-category scoping) with no
network or signing dependencies, so it runs in CI without the crypto packages.
"""
from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# Robustness: a SessionStart hook must never crash on malformed input.
# ---------------------------------------------------------------------------
def _setup_home(tmp_path, monkeypatch):
    """Point CLAUDE_HOME and ~ expansion at an isolated temp home."""
    home = tmp_path / "home"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    monkeypatch.setattr(capture, "CLAUDE_HOME", claude)
    monkeypatch.setattr(capture.os.path, "expanduser", lambda p: str(home))
    return home, claude


def test_policy_tolerates_malformed_settings_json(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    (claude / "settings.json").write_text("{ not valid json ", encoding="utf-8")
    policy_hash, allow = capture._policy()
    # No exception; empty allow-list; hash still reflects the real (broken) bytes
    # so a hand-edit is detected as drift rather than silently ignored.
    assert allow == []
    assert policy_hash.startswith("sha256:")
    assert policy_hash != capture._sha_bytes(b"{}")


def test_policy_tolerates_nondict_permissions(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    (claude / "settings.json").write_text('{"permissions": "all"}', encoding="utf-8")
    _hash, allow = capture._policy()
    assert allow == []


def test_mcp_tolerates_malformed_and_misshaped_config(tmp_path, monkeypatch):
    home, _claude = _setup_home(tmp_path, monkeypatch)
    (home / ".claude.json").write_text('{"mcpServers": ["a", "b"]}', encoding="utf-8")
    assert capture._mcp_from_config() == []
    (home / ".claude.json").write_text("NOT JSON {", encoding="utf-8")
    assert capture._mcp_from_config() == []


def test_skills_tolerates_file_where_dir_expected(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    (claude / "skills").write_text("i am a file, not a dir", encoding="utf-8")
    assert capture._skills() == {}


def test_load_returns_none_on_corrupt_state(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text('{ "captured_at": "2026"  ', encoding="utf-8")  # truncated
    assert capture._load(p) is None  # treated as absent -> next run re-establishes


def test_hook_never_crashes_and_exits_zero(tmp_path, monkeypatch, capsys):
    """Any failure inside the hook still yields valid SessionStart output and 0."""
    _isolate_state(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("simulated failure deep in snapshot")

    monkeypatch.setattr(capture, "snapshot", boom)
    monkeypatch.setattr(capture.sys.stdin, "isatty", lambda: True)

    assert capture.cmd_hook(_Args()) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert "integrity check skipped" in payload["hookSpecificOutput"]["additionalContext"]
