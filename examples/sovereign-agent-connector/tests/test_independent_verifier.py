from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "vectors" / "french-healthcare" / "cmcp-live-bundle.json"
ANCHORS = ROOT / "vectors" / "french-healthcare" / "cmcp-live-trust-anchors.json"
SPEC = importlib.util.spec_from_file_location(
    "independent_verify", ROOT / "tools" / "independent_verify.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def load_bundle() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def load_anchors() -> dict:
    return json.loads(ANCHORS.read_text(encoding="utf-8"))


def test_independent_verifier_reproduces_mve1() -> None:
    verdict = MODULE.verify_live(load_bundle(), load_anchors())
    assert verdict.allowed_actions == ("urn:uuid:action-allowed-001",)
    assert verdict.denied_actions == ("urn:uuid:action-denied-001",)
    assert verdict.platform == "software-only"
    assert verdict.hardware_attested is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["base_bundle"]["agreement"]["odrl"]["permission"][0]["constraints"].update(
            {"jurisdictions": ["FR", "US"]}
        ),
        lambda b: b["base_bundle"]["delegation_chain"][1]["scope"].append("patient:export"),
        lambda b: b["base_bundle"]["placement_assertion"].update({"jurisdiction": "US"}),
        lambda b: b["base_bundle"]["registry"]["proofs"][0].update(
            {"audit_path": ["sha256:" + "00" * 32]}
        ),
        lambda b: b["cmcp_audit_entries"][2]["detail"].update({"dispatch_state": "dispatched"}),
        lambda b: b["cmcp_trace"]["gateway"]["call_summary"].update({"tool_calls_denied": 0}),
        lambda b: b["adapter_bindings"].pop(),
    ],
)
def test_independent_verifier_fails_closed(mutate) -> None:
    bundle = copy.deepcopy(load_bundle())
    mutate(bundle)
    with pytest.raises(MODULE.VerificationError):
        MODULE.verify_live(bundle, load_anchors())


def test_independent_verifier_rejects_bundle_selected_trust_domain() -> None:
    anchors = load_anchors()
    anchors["base"]["owner"] = "00" * 32

    with pytest.raises(MODULE.VerificationError, match="out-of-band trust anchors"):
        MODULE.verify_live(load_bundle(), anchors)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["base_bundle"]["receipts"].__setitem__(0, "not-a-receipt"),
        lambda b: b["base_bundle"]["registry"]["proofs"][0]["audit_path"].__setitem__(0, "zz"),
    ],
)
def test_independent_verifier_cli_reports_malformed_bundle_as_fail(
    tmp_path, capsys, mutate
) -> None:
    bundle = copy.deepcopy(load_bundle())
    mutate(bundle)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    code = MODULE.main([str(bundle_path), "--trust-anchors", str(ANCHORS)])

    assert code == 1
    assert capsys.readouterr().err.startswith("FAIL:")
