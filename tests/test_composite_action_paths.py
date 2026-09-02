from __future__ import annotations

import shlex
import shutil
from pathlib import Path

import pytest
import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ACTION_NAMES = ("copilot", "cursor", "gemini-cli", "windsurf")
CAPTURE_CORE = Path("packages/agentrust-capture-core")


@pytest.mark.parametrize("action_name", ACTION_NAMES)
def test_capture_core_is_resolved_from_the_action_checkout(
    action_name: str, tmp_path: Path
) -> None:
    """A reusable action must not resolve its code from the caller's checkout."""
    action_store = tmp_path / "_actions" / "agentrust-io" / "integrations" / "ref"
    action_path = action_store / action_name
    consumer_workspace = tmp_path / "consumer"
    action_core = action_store / CAPTURE_CORE
    consumer_core = consumer_workspace / CAPTURE_CORE

    # Model a remote action checkout and the consumer repository as separate
    # trees. A local ``uses: ./<action>`` smoke test puts both under
    # GITHUB_WORKSPACE and therefore cannot catch this boundary error.
    action_path.mkdir(parents=True)
    shutil.copytree(REPOSITORY_ROOT / CAPTURE_CORE, action_core)
    consumer_core.mkdir(parents=True)

    document = yaml.safe_load(
        (REPOSITORY_ROOT / action_name / "action.yml").read_text(encoding="utf-8")
    )
    install_commands = [
        step["run"]
        for step in document["runs"]["steps"]
        if "agentrust-capture-core" in step.get("run", "")
    ]

    assert len(install_commands) == 1
    command = install_commands[0]
    assert "$GITHUB_WORKSPACE" not in command

    rendered = command.replace("${{ github.action_path }}", str(action_path))
    arguments = shlex.split(rendered)

    assert arguments[:3] == ["pip", "install", "--quiet"]
    assert len(arguments) == 4
    resolved_core = Path(arguments[3]).resolve()
    assert resolved_core == action_core.resolve()
    assert resolved_core != consumer_core.resolve()
    assert (resolved_core / "pyproject.toml").is_file()
