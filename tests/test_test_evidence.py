"""Receipts distinguish execution, consistency and missing evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

spec = importlib.util.spec_from_file_location("test_evidence", Path(__file__).parents[1] / "scripts/test_evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    directory = root / "integrations/demo"
    directory.mkdir(parents=True)
    (directory / "integration.yaml").write_text(
        f"tested_against:\n  pytest: '{evidence.importlib.metadata.version('pytest')}'\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "fixture"], cwd=root, check=True)
    return root, tmp_path / "receipt"


def run(checkout, code="print('executed')", timeout=600):
    root, output = checkout
    return evidence.capture(root, "integrations/demo", output,
                            [sys.executable, "-c", code], "synthetic", timeout)


def test_success_and_log_binding(checkout):
    run(checkout)
    root, output = checkout
    assert evidence.validate(root, output) == []
    (output / "output.log").write_text("substituted")
    assert "log digest mismatch" in evidence.validate(root, output)


@pytest.mark.parametrize("code", ["raise SystemExit(7)", "import time; time.sleep(5)"])
def test_failure_and_timeout_retained(checkout, code):
    receipt = run(checkout, code, timeout=1)
    assert receipt["returncode"] != 0
    assert "command did not pass" in evidence.validate(*checkout)


@pytest.mark.parametrize("field,value,error", [
    ("revision", "0" * 40, "source revision mismatch"),
    ("dirty", True, "dirty source snapshot"),
    ("observed_packages", {}, "installed versions differ"),
    ("returncode", None, "command did not pass"),
])
def test_mismatch(checkout, field, value, error):
    receipt = run(checkout)
    receipt[field] = value
    (checkout[1] / "receipt.json").write_text(json.dumps(receipt))
    assert error in evidence.validate(*checkout)


def test_missing_and_changed_manifest(checkout):
    assert evidence.validate(*checkout)
    run(checkout)
    (checkout[0] / "integrations/demo/integration.yaml").write_text("tested_against: {}")
    assert "manifest changed" in evidence.validate(*checkout)


def test_reject_foreign_interpreter_and_path(checkout):
    root, output = checkout
    with pytest.raises(ValueError):
        evidence.capture(root, "integrations/demo", output, ["sh", "-c", "true"], "synthetic")
    with pytest.raises(ValueError):
        evidence.capture(root, "../outside", output, [sys.executable, "-c", "pass"], "synthetic")
