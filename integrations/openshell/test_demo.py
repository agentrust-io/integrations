from __future__ import annotations

import importlib.util
from pathlib import Path

from agentrust_trace.models import TrustRecord

DEMO = Path(__file__).parent / "demo" / "build_signed_record.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("openshell_demo", DEMO)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_builds_signed_released_model_record() -> None:
    record = _load_demo().build_signed_demo_record()
    parsed = TrustRecord.model_validate(record)
    assert parsed.origin.producer == "nvidia-openshell/0.0.105"
    assert parsed.runtime.platform == "software-only"
    assert parsed.appraisal.status == "none"
    assert parsed.policy.enforcement_mode == "enforce"
