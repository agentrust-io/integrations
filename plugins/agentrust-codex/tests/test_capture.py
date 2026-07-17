"""Tests for the AgenTrust Codex capture engine."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import capture  # noqa: E402


def _isolated_layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    codex_home = home / ".codex"
    state = codex_home / "agentrust"
    workspace = tmp_path / "work"
    (workspace / ".git").mkdir(parents=True)
    codex_home.mkdir(parents=True)

    monkeypatch.setattr(capture, "HOME", home)
    monkeypatch.setattr(capture, "CODEX_HOME", codex_home)
    monkeypatch.setattr(capture, "STATE_DIR", state)
    monkeypatch.setattr(capture, "SIGNING_KEY", state / "signing_key.json")
    monkeypatch.setenv("USER", "tester")
    monkeypatch.setenv("HOSTNAME", "test-host")
    return home, codex_home, state, workspace


def _write_plugin(codex_home: Path, marketplace="local", name="demo", version="1.0.0"):
    root = codex_home / "plugins" / "cache" / marketplace / name / version
    (root / ".codex-plugin").mkdir(parents=True)
    (root / ".codex-plugin" / "plugin.json").write_text(
        json.dumps({"name": name, "version": version}), encoding="utf-8"
    )
    (root / "skills" / "review").mkdir(parents=True)
    (root / "skills" / "review" / "SKILL.md").write_text(
        "---\nname: review\ndescription: Review code.\n---\n", encoding="utf-8"
    )
    return root


def _write_config(codex_home: Path):
    (codex_home / "config.toml").write_text(
        """
approval_policy = "never"
sandbox_mode = "workspace-write"

[mcp_servers.github]
url = "https://example.invalid/mcp"
secret = "must-not-appear"

[plugins."demo@local"]
enabled = true
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _live(workspace: Path, **overrides):
    value = {
        "cwd": str(workspace),
        "model_id": "gpt-test",
        "model_provider": "openai",
        "model_version": "gpt-test",
        "permission_mode": "dontAsk",
    }
    value.update(overrides)
    return value


def test_snapshot_captures_names_and_hashes_without_config_values(
    tmp_path, monkeypatch
):
    home, codex_home, _state, workspace = _isolated_layout(tmp_path, monkeypatch)
    _write_config(codex_home)
    _write_plugin(codex_home)
    (workspace / "AGENTS.md").write_text("Follow repository rules.\n", encoding="utf-8")
    skill = home / ".agents" / "skills" / "local-check"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: local-check\ndescription: Check locally.\n---\n", encoding="utf-8"
    )

    current = capture.snapshot(_live(workspace))
    encoded = json.dumps(current, sort_keys=True)

    assert current["model"]["model_id"] == "gpt-test"
    assert current["permission_mode"] == "dontAsk"
    assert current["configured_mcp_servers"] == ["github"]
    assert list(current["plugins"]) == ["demo@local"]
    assert any(name.endswith("local-check") for name in current["skills"])
    assert any(name.endswith("AGENTS.md") for name in current["instructions"])
    assert "must-not-appear" not in encoded
    assert "https://example.invalid/mcp" not in encoded
    assert all(value.startswith("sha256:") for value in current["hashes"].values())


def test_disabled_plugin_is_not_fingerprinted(tmp_path, monkeypatch):
    _home, codex_home, _state, workspace = _isolated_layout(tmp_path, monkeypatch)
    _write_plugin(codex_home)
    (codex_home / "config.toml").write_text(
        '[plugins."demo@local"]\nenabled = false\n', encoding="utf-8"
    )

    current = capture.snapshot(_live(workspace))
    assert current["plugins"] == {}
    assert "plugin:demo@local" not in current["tools"]


def test_fallback_parser_honors_disabled_plugins(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        """
approval_policy = "never"
[mcp_servers.github]
url = "stdio"
[plugins."off@local"]
enabled = false
[plugins."on@local"]
enabled = true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    mcp, plugins, scope = capture._fallback_toml_state(config)
    assert mcp == {"github"}
    assert plugins == {"on@local"}
    assert scope == {"approval_policy": "never"}


def test_diff_reports_specific_composition_changes():
    base = {
        "observed": [
            "instructions",
            "mcp_config",
            "model",
            "permission",
            "plugins",
            "policy",
            "skills",
        ],
        "instructions": {"workspace:AGENTS.md": "sha256:" + "1" * 64},
        "policy_files": {"user:config.toml": "sha256:" + "2" * 64},
        "policy_scope": {"approval_policy": "never"},
        "skills": {"user:review": "sha256:" + "3" * 64},
        "plugins": {"demo@local": "sha256:" + "4" * 64},
        "configured_mcp_servers": ["github"],
        "model": {"model_id": "gpt-a"},
        "permission_mode": "default",
    }
    current = json.loads(json.dumps(base))
    current["skills"]["user:exfil"] = "sha256:" + "5" * 64
    current["plugins"]["demo@local"] = "sha256:" + "6" * 64
    current["configured_mcp_servers"].append("shadow")
    current["model"] = {"model_id": "gpt-b"}
    current["permission_mode"] = "bypassPermissions"

    changes = capture.diff(base, current)
    assert {"change": "added", "what": "skill", "detail": "user:exfil"} in changes
    assert {"change": "changed", "what": "plugin", "detail": "demo@local"} in changes
    assert {
        "change": "added",
        "what": "configured MCP server",
        "detail": "shadow",
    } in changes
    assert any(item["what"] == "model" for item in changes)
    assert any(item["what"] == "permission mode" for item in changes)


def test_workspace_baselines_are_isolated(tmp_path, monkeypatch):
    _home, _codex_home, state, first = _isolated_layout(tmp_path, monkeypatch)
    second = tmp_path / "second"
    (second / ".git").mkdir(parents=True)

    first_snapshot = capture.snapshot(_live(first))
    second_snapshot = capture.snapshot(_live(second))
    first_path, _ = capture._workspace_state(first_snapshot["workspace_id"])
    second_path, _ = capture._workspace_state(second_snapshot["workspace_id"])

    assert first_snapshot["workspace_id"] != second_snapshot["workspace_id"]
    assert first_path != second_path
    assert state in first_path.parents
    assert state in second_path.parents


def _run_hook(payload, monkeypatch):
    monkeypatch.setattr(capture.sys, "stdin", io.StringIO(json.dumps(payload)))
    args = type("Args", (), {})()
    return capture.cmd_hook(args)


def test_hook_establishes_baseline_stays_quiet_then_warns(
    tmp_path, monkeypatch, capsys
):
    _home, codex_home, _state, workspace = _isolated_layout(tmp_path, monkeypatch)
    _write_config(codex_home)
    _write_plugin(codex_home)
    agents = workspace / "AGENTS.md"
    agents.write_text("Initial instructions.\n", encoding="utf-8")
    payload = {
        "cwd": str(workspace),
        "model": "gpt-test",
        "permission_mode": "default",
        "session_id": "session-secret",
    }

    assert _run_hook(payload, monkeypatch) == 0
    first = json.loads(capsys.readouterr().out)
    assert "established a baseline" in first["hookSpecificOutput"]["additionalContext"]
    baseline_id = capture.snapshot(_live(workspace))["workspace_id"]
    baseline_path, _ = capture._workspace_state(baseline_id)
    stored = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert stored["runtime_context"]["session_id_hash"].startswith("sha256:")
    assert "session-secret" not in baseline_path.read_text(encoding="utf-8")

    assert _run_hook(payload, monkeypatch) == 0
    assert capsys.readouterr().out == ""

    agents.write_text("Changed instructions.\n", encoding="utf-8")
    assert _run_hook(payload, monkeypatch) == 0
    warning = json.loads(capsys.readouterr().out)
    assert "AgenTrust WARNING" in warning["systemMessage"]
    assert "changed instruction" in warning["systemMessage"]


def test_corrupt_baseline_is_never_replaced(tmp_path, monkeypatch, capsys):
    _home, _codex_home, _state, workspace = _isolated_layout(tmp_path, monkeypatch)
    current = capture.snapshot(_live(workspace))
    baseline_path, _ = capture._workspace_state(current["workspace_id"])
    baseline_path.parent.mkdir(parents=True)
    baseline_path.write_text("{broken", encoding="utf-8")

    payload = {
        "cwd": str(workspace),
        "model": "gpt-test",
        "permission_mode": "default",
    }
    assert _run_hook(payload, monkeypatch) == 0
    warning = json.loads(capsys.readouterr().out)
    assert "was not replaced" in warning["systemMessage"]
    assert baseline_path.read_text(encoding="utf-8") == "{broken"


def test_hook_never_crashes(tmp_path, monkeypatch, capsys):
    _isolated_layout(tmp_path, monkeypatch)

    def fail(_live=None):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(capture, "snapshot", fail)
    monkeypatch.setattr(capture.sys, "stdin", io.StringIO("not-json"))
    args = type("Args", (), {})()
    assert capture.cmd_hook(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["continue"] is True
    assert "skipped the integrity check" in output["systemMessage"]


def test_verify_resnapshots_instead_of_trusting_latest(tmp_path, monkeypatch, capsys):
    _home, _codex_home, _state, workspace = _isolated_layout(tmp_path, monkeypatch)
    agents = workspace / "AGENTS.md"
    agents.write_text("Approved.\n", encoding="utf-8")
    approved = capture.snapshot(_live(workspace))
    baseline_path, latest_path = capture._workspace_state(approved["workspace_id"])
    capture._save(baseline_path, approved)
    capture._save(latest_path, approved)
    agents.write_text("Drifted.\n", encoding="utf-8")

    args = type(
        "Args",
        (),
        {
            "cwd": str(workspace),
            "live_context": None,
            "model": None,
            "permission_mode": None,
            "tool": None,
            "mcp_server": None,
            "data_class": None,
        },
    )()
    assert capture.cmd_verify(args) == 0
    output = capsys.readouterr().out
    assert "CHANGED instruction" in output
    assert "Verified: no composition changes." not in output


def _signable_snapshot(tmp_path, monkeypatch):
    _home, codex_home, _state, workspace = _isolated_layout(tmp_path, monkeypatch)
    _write_config(codex_home)
    _write_plugin(codex_home)
    return capture.snapshot(
        _live(
            workspace,
            builtin_tools=["exec_command"],
            permission_mode="bypassPermissions",
        )
    )


def test_signing_key_is_stable_and_owner_only(tmp_path, monkeypatch):
    pytest.importorskip("agent_manifest")
    pytest.importorskip("cryptography")
    _isolated_layout(tmp_path, monkeypatch)

    first = capture._load_or_create_manifest_keypair()
    second = capture._load_or_create_manifest_keypair()
    assert first.key_id == second.key_id
    if os.name == "posix":
        assert stat_mode(capture.SIGNING_KEY) == 0o600


def stat_mode(path: Path):
    return path.stat().st_mode & 0o777


def test_corrupt_signing_key_does_not_mint_a_new_identity(tmp_path, monkeypatch):
    pytest.importorskip("agent_manifest")
    pytest.importorskip("cryptography")
    _isolated_layout(tmp_path, monkeypatch)
    capture.SIGNING_KEY.parent.mkdir(parents=True)
    capture.SIGNING_KEY.write_text("{broken", encoding="utf-8")

    with pytest.raises(SystemExit, match="signing key is unreadable"):
        capture._load_or_create_manifest_keypair()
    assert capture.SIGNING_KEY.read_text(encoding="utf-8") == "{broken"


def test_signed_outputs_verify_and_pass_trace_level_zero(tmp_path, monkeypatch):
    pytest.importorskip("agent_manifest")
    pytest.importorskip("agentrust_trace")
    pytest.importorskip("trace_tests")
    from agent_manifest import RevocationStore, VerificationContext, verify_manifest

    current = _signable_snapshot(tmp_path, monkeypatch)
    out = tmp_path / "records"
    manifest, _trace = capture.sign_all(current, out)
    assert manifest["artifacts"]["policy_bundle"]["enforcement_mode"] == "audit-only"
    assert _trace["policy"]["enforcement_mode"] == "silent"
    verification_key = json.loads(
        (out / "verification_key.json").read_text(encoding="utf-8")
    )
    context = VerificationContext(
        trusted_keys={verification_key["key_id"]: verification_key["public_key_b64url"]}
    )
    good = verify_manifest(manifest, context, RevocationStore())
    assert good.signature_verified is True
    if os.name == "posix":
        for name in ("manifest.json", "trace.json", "verification_key.json"):
            assert stat_mode(out / name) == 0o600

    tampered = json.loads(json.dumps(manifest))
    tampered["artifacts"]["policy_bundle"]["hash"] = "sha256:" + "0" * 64
    bad = verify_manifest(tampered, context, RevocationStore())
    assert bad.signature_verified is False

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "trace_tests.cli",
            "verify",
            "--record",
            str(out / "trace.json"),
            "--level",
            "0",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
