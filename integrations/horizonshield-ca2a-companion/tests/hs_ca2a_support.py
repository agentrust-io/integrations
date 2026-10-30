"""Load the vendored companion against the released packages (shared by the tests).

companion_v0.py imports settle_v1_1 by bare name for the Bitcoin header view
and the anchor proof. nenrin-verify ships that file byte for byte from
horizon-shield; nenrin_verify.musubi.load puts its directory on sys.path and
imports it, so the companion's own import finds it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from nenrin_verify import musubi

ENTRY = Path(__file__).resolve().parents[1]
VENDOR = ENTRY / "vendor" / "ca2a-companion-v0"
VECTORS_PATH = VENDOR / "vectors" / "vectors.json"

musubi.load("settle_v1_1")


def _load_companion():
    if "companion_v0" in sys.modules:
        return sys.modules["companion_v0"]
    spec = importlib.util.spec_from_file_location("companion_v0", VENDOR / "companion_v0.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["companion_v0"] = module
    spec.loader.exec_module(module)
    return module


companion = _load_companion()
_DOC = json.loads(VECTORS_PATH.read_bytes())
SETTLEMENT_VECTORS = {v["id"]: v for v in _DOC["vectors"]}
EVIDENCE_VECTORS = {v["id"]: v for v in _DOC["evidence"]}


def settle(vector_id: str) -> dict:
    """The settlement exactly as the companion's own --selftest compares it."""
    vector = SETTLEMENT_VECTORS[vector_id]
    return json.loads(companion.jcs(companion.settle(vector["bundle"])))


def evidence(vector_id: str) -> dict:
    vector = EVIDENCE_VECTORS[vector_id]
    fn = {"compare_checkpoints": companion.compare_checkpoints,
          "check_promise": companion.check_promise}[vector["fn"]]
    return json.loads(companion.jcs(fn(*vector["args"])))


MUSUBI_DIRS = [musubi.MUSUBI_DIR, musubi.AGREEMENT_DIR]
