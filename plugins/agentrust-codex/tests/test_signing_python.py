"""Tests for the pinned signing-environment bootstrap."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "signing-python.py"
SPEC = importlib.util.spec_from_file_location("agentrust_signing_python", SCRIPT)
assert SPEC and SPEC.loader
signing_python = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signing_python)


def test_signing_bootstrap_requires_python_311():
    with pytest.raises(SystemExit, match="Python 3.11 or newer"):
        signing_python._require_supported_python((3, 10))

    signing_python._require_supported_python((3, 11))
