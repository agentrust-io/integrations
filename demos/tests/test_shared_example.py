"""The browser console must work from the combined checkout without Git fetches."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "demos" / "web-console"
EXAMPLE = ROOT / "examples" / "financial-services"


def load_console(filename):
    spec = importlib.util.spec_from_file_location("consolidated_" + filename[:-3], CONSOLE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(CONSOLE))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


@pytest.mark.parametrize("filename", ["run.py", "webserver.py", "policy_variants.py"])
def test_console_uses_the_shared_example(filename):
    module = load_console(filename)
    assert module.EXAMPLE == EXAMPLE
    for asset in ["agent/credit_risk_agent.py", "server/mock_mcp_server.py", "catalog.json", "policy/allow.cedar"]:
        assert (module.EXAMPLE / asset).is_file(), asset


def test_missing_example_fails_without_fetching(monkeypatch, tmp_path):
    module = load_console("run.py")
    monkeypatch.setattr(module, "EXAMPLE", tmp_path)
    fetch = Mock(side_effect=AssertionError("the combined checkout must not fetch a submodule"))
    monkeypatch.setattr(module.subprocess, "run", fetch)
    with pytest.raises(SystemExit, match="shared example missing"):
        module._ensure_example()
    fetch.assert_not_called()


def test_launcher_hides_children_and_can_skip_browser(monkeypatch, tmp_path):
    module = load_console("run.py")
    monkeypatch.setattr(module, "HERE", tmp_path)
    monkeypatch.setattr(module, "CHILD_FLAGS", 0x08000000)
    monkeypatch.setattr(module, "_assert_port_free", lambda *args: None)
    monkeypatch.setattr(module, "_wait_for_port", lambda *args: None)
    monkeypatch.setattr(module, "_write_gateway_config", lambda: None)
    monkeypatch.setattr(module, "_find_cmcp", lambda: "cmcp")
    monkeypatch.setattr(sys, "argv", ["run.py", "--no-browser"])
    child = Mock()
    child.poll.return_value = 0
    spawn = Mock(return_value=child)
    browser = Mock()
    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    monkeypatch.setattr(module.webbrowser, "open", browser)
    module.main()
    assert spawn.call_count == 3
    assert all(call.kwargs["creationflags"] == 0x08000000 for call in spawn.call_args_list)
    browser.assert_not_called()


def test_policy_variants_use_the_shared_bundle(monkeypatch, tmp_path):
    module = load_console("policy_variants.py")
    monkeypatch.setattr(module, "TAMPERED_DIR", tmp_path / "tampered")
    tampered, edits = module.build_tampered()
    assert edits
    assert module.bundle_hash(module.APPROVED_DIR) != module.bundle_hash(tampered)
