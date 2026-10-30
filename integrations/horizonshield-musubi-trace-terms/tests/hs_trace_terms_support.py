"""Load the vendored evaluator against the released packages (shared by the tests).

trace_terms_v0.py imports contract_v0 and agreement_verify by bare name, and
nenrin_verify.trace as a package module. nenrin-verify ships all three byte for
byte from horizon-shield; nenrin_verify.musubi.load puts the directories of the
first two on sys.path.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from nenrin_verify import musubi

ENTRY = Path(__file__).resolve().parents[1]
VENDOR = ENTRY / "vendor" / "trace-terms-v0"
VECTORS_PATH = VENDOR / "vectors" / "vectors.json"

musubi.load("contract_v0")


def _load_evaluator():
    if "trace_terms_v0" in sys.modules:
        return sys.modules["trace_terms_v0"]
    spec = importlib.util.spec_from_file_location("trace_terms_v0", VENDOR / "trace_terms_v0.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["trace_terms_v0"] = module
    spec.loader.exec_module(module)
    return module


evaluator = _load_evaluator()
_DOC = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
VECTORS = {v["id"]: v for v in _DOC["vectors"]}
MUSUBI_DIRS = [musubi.MUSUBI_DIR, musubi.AGREEMENT_DIR]


def evaluate(vector_id: str) -> dict:
    return evaluator.evaluate(VECTORS[vector_id]["bundle"])


def signature(vector_id: str) -> dict:
    """What the evaluator's own --selftest compares: verdict, refusals, and per act index, status, codes."""
    return evaluator._signature(evaluate(vector_id))


def acts(vector_id: str) -> list[tuple[str, list[str]]]:
    return [(a["status"], a["codes"]) for a in signature(vector_id)["acts"]]
