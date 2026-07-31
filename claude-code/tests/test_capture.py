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
        "observed": ["skills", "policy", "prompt", "mcp", "tools"],
        "skills": {"trace": "sha256:" + "a" * 64},
        "mcp_servers": ["Slack"],
        "tools": ["Bash", "mcp:Slack"],
        "hashes": {"system_prompt": "sha256:" + "1" * 64, "policy_bundle": "sha256:" + "2" * 64},
    }
    snap.update(over)
    return snap


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


# ---------------------------------------------------------------------------
# Baseline integrity: the baseline is what every comparison is made against, so
# a baseline that can be rewritten unnoticed makes the drift check pass forever.
# ---------------------------------------------------------------------------
def _isolate_tagging(tmp_path, monkeypatch):
    """Point baseline, latest and the tag secret at a temp dir."""
    state = tmp_path / "agentrust"
    monkeypatch.setattr(capture, "STATE_DIR", state)
    monkeypatch.setattr(capture, "BASELINE", state / "baseline.json")
    monkeypatch.setattr(capture, "LATEST", state / "session-latest.json")
    monkeypatch.setattr(capture, "BASELINE_TAG_KEY", state / "baseline_tag_key")
    return state


class TestBaselineIntegrity:
    def test_a_freshly_written_baseline_verifies(self, tmp_path, monkeypatch):
        _isolate_tagging(tmp_path, monkeypatch)
        written = capture._save_baseline(_base())
        assert capture.check_integrity(written) == capture.INTEGRITY_OK
        assert capture.check_integrity(capture._load(capture.BASELINE)) == capture.INTEGRITY_OK

    def test_editing_the_baseline_is_detected(self, tmp_path, monkeypatch):
        """The whole point: a rewritten baseline must not read as intact."""
        _isolate_tagging(tmp_path, monkeypatch)
        capture._save_baseline(_base())
        tampered = capture._load(capture.BASELINE)
        # An attacker adds their skill to the approved set so drift goes quiet.
        tampered["skills"]["exfil"] = "sha256:" + "e" * 64
        capture._save(capture.BASELINE, tampered)
        assert capture.check_integrity(capture._load(capture.BASELINE)) == capture.INTEGRITY_BROKEN

    def test_stripping_the_tag_reads_as_untagged_not_intact(self, tmp_path, monkeypatch):
        _isolate_tagging(tmp_path, monkeypatch)
        capture._save_baseline(_base())
        stripped = capture._load(capture.BASELINE)
        del stripped["integrity"]
        capture._save(capture.BASELINE, stripped)
        assert capture.check_integrity(capture._load(capture.BASELINE)) == capture.INTEGRITY_UNTAGGED

    def test_a_forged_tag_is_detected(self, tmp_path, monkeypatch):
        _isolate_tagging(tmp_path, monkeypatch)
        capture._save_baseline(_base())
        forged = capture._load(capture.BASELINE)
        forged["skills"]["exfil"] = "sha256:" + "e" * 64
        forged["integrity"]["tag"] = "0" * 64
        capture._save(capture.BASELINE, forged)
        assert capture.check_integrity(capture._load(capture.BASELINE)) == capture.INTEGRITY_BROKEN

    def test_older_untagged_baseline_is_not_reported_as_tampering(self, tmp_path, monkeypatch):
        """A baseline predating tagging is benign. Crying tamper over it would
        teach the user to dismiss the real alarm."""
        _isolate_tagging(tmp_path, monkeypatch)
        capture._save(capture.BASELINE, _base())  # untagged, as an old version wrote it
        assert capture.check_integrity(capture._load(capture.BASELINE)) == capture.INTEGRITY_UNTAGGED

    def test_missing_secret_reads_as_untagged_not_broken(self, tmp_path, monkeypatch):
        """A deleted secret is not evidence of tampering."""
        state = _isolate_tagging(tmp_path, monkeypatch)
        capture._save_baseline(_base())
        loaded = capture._load(capture.BASELINE)
        (state / "baseline_tag_key").unlink()
        assert capture.check_integrity(loaded) == capture.INTEGRITY_UNTAGGED

    def test_none_reads_as_untagged(self):
        assert capture.check_integrity(None) == capture.INTEGRITY_UNTAGGED

    def test_digest_ignores_the_integrity_block(self, tmp_path, monkeypatch):
        """Otherwise the digest would have to cover a tag computed over itself."""
        _isolate_tagging(tmp_path, monkeypatch)
        snap = _base()
        assert capture.state_digest(capture.attach_integrity(snap)) == capture.state_digest(snap)

    def test_digest_changes_when_content_changes(self, tmp_path, monkeypatch):
        _isolate_tagging(tmp_path, monkeypatch)
        assert capture.state_digest(_base()) != capture.state_digest(
            _base(skills={"other": "sha256:" + "d" * 64})
        )

    def test_tag_secret_is_not_the_manifest_signing_key(self):
        """The hook is stdlib-only, so the tag must be checkable without the
        crypto packages the Ed25519 signing key needs."""
        assert capture.BASELINE_TAG_KEY != capture.SIGNING_KEY


class TestIntegrityIsSurfacedBeforeDrift:
    """A broken baseline makes the drift comparison meaningless, so it is stated
    first rather than buried under a reassuring result."""

    def _snap(self):
        return _report_snap(["skills", "policy", "prompt", "mcp", "tools"])

    def test_broken_baseline_is_called_out_before_the_drift_section(self):
        out = capture.render_report(self._snap(), [], False,
                                    integrity=capture.INTEGRITY_BROKEN)
        assert "FAILED its integrity check" in out
        assert out.index("FAILED its integrity check") < out.index("NOTHING ADDED")

    def test_clean_verdict_still_prints_but_is_qualified(self):
        out = capture.render_report(self._snap(), [], False,
                                    integrity=capture.INTEGRITY_BROKEN)
        assert "nothing added, nothing subtracted" in out
        assert "unreliable" in out

    def test_untagged_baseline_prompts_a_re_approve(self):
        out = capture.render_report(self._snap(), [], False,
                                    integrity=capture.INTEGRITY_UNTAGGED)
        assert "no integrity tag" in out
        assert "FAILED" not in out

    def test_verified_tag_is_reported_together_with_its_limit(self):
        out = capture.render_report(self._snap(), [], False, integrity=capture.INTEGRITY_OK,
                                    baseline_digest="sha256:" + "a" * 64)
        assert "integrity tag verified" in out
        # The limit must travel with the claim, or the claim is theatre.
        assert "not someone who can" in out
        assert "sha256:" + "a" * 64 in out

    def test_section_is_omitted_when_integrity_was_not_checked(self):
        assert "BASELINE ITSELF INTACT" not in capture.render_report(self._snap(), None, False)
