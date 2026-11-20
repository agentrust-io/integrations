"""Contract checks: released-package floors, the external TRACE Level 0 CLI, and the README skeleton."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tomllib
from importlib.metadata import version

import cta_trace_guard as g
import pytest
from conftest import ARGS, TOOL, make_config, make_observe
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

INTEGRATION_DIR = pathlib.Path(__file__).resolve().parent.parent


def test_declared_dependency_floors_are_satisfied_by_the_installed_releases():
    data = tomllib.loads((INTEGRATION_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    specs = list(data["project"]["dependencies"])
    for extra in data["project"]["optional-dependencies"].values():
        specs.extend(extra)
    requirements = {canonicalize_name(Requirement(spec).name): Requirement(spec) for spec in specs}
    assert {"agentrust-trace", "agentrust-trace-adapters", "agentrust-trace-tests", "rfc8785", "cryptography"} <= requirements.keys()
    for package in ("agentrust-trace", "agentrust-trace-adapters", "agentrust-trace-tests", "cryptography", "rfc8785"):
        requirement = requirements[package]
        assert requirement.specifier, f"{package} has no declared version floor"
        installed = version(requirement.name)
        assert requirement.specifier.contains(installed, prereleases=True), f"{package} {installed} vs {requirement.specifier}"


def test_manifest_declares_a_level_0_record_producer():
    text = (INTEGRATION_DIR / "integration.yaml").read_text(encoding="utf-8")
    lines = [line.rstrip() for line in text.splitlines()]
    assert "integrates_with:" in lines and "  - trace" in lines
    assert "trace_roles:" in lines and "  - record-producer" in lines
    assert "trace_conformance_level: 0" in lines
    assert "tier: community" in lines
    assert '  agentrust-trace: "0.11.0"' in lines
    assert '  agentrust-trace-tests: "0.6.2"' in lines


def test_trace_tests_level_0_passes_on_an_emitted_record(tmp_path):
    guard = g.CtaGuard(make_config())  # real clock: trace-tests checks iat freshness
    out = guard.run(
        session_id="s", request_id="r", tool_name=TOOL, tool_fn=lambda **kw: {"ok": True},
        arguments=ARGS, observe=make_observe("r", observed_at="now"),
    )
    assert out.status == "record-emitted"
    record_path = tmp_path / "trust-record.json"
    record_path.write_text(json.dumps(out.record_artifacts.record, ensure_ascii=False), encoding="utf-8")
    exe = pathlib.Path(sys.executable).with_name("trace-tests.exe" if os.name == "nt" else "trace-tests")
    proc = subprocess.run(
        [str(exe), "verify", "--record", str(record_path), "--level", "0"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    "heading",
    [
        "## Run it",
        "## Before vs. After verification summary",
        "## What is verified",
        "## What it does NOT claim",
    ],
)
def test_readme_has_the_required_sections(heading):
    readme = (INTEGRATION_DIR / "README.md").read_text(encoding="utf-8")
    assert heading in readme.splitlines()
