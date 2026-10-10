"""Re-check the Parmana fixtures offline, without running Parmana.

The fixtures are the records one run of Parmana's refund evaluation wrote
(report.json names the commit). These tests check every signature, that a
changed record no longer verifies, that the approval is the one the Trust
Record was signed over, and that references.json is exactly what the
records produce, with no `observed-effect` entry.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from agentrust_trace import Reference

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import parmana_evidence as pe  # noqa: E402

FIXTURES = ROOT / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


TRUST_RECORD = load("01-valid-approval.execution-trust-record.json")
REFUSALS = {
    "refusal": load("02-refusal.refusal-record.json"),
    "replay": load("03-replay.refusal-record.json"),
}
APPROVAL = load("approval.json")
REPORT = load("report.json")
REFERENCES = load("references.json")
_signing = load("parmana-signing-key.json")
PARMANA_KEYS = {_signing["keyId"]: _signing["pem"]}
_approver = load("approver-key.json")
APPROVER_KEYS = {_approver["keyId"]: _approver["publicKeyPem"]}


def test_trust_record_verifies():
    assert pe.verify_trust_record(TRUST_RECORD, PARMANA_KEYS).valid


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_refusal_record_verifies(case):
    assert pe.verify_refusal_record(REFUSALS[case], PARMANA_KEYS).valid


def test_approval_verifies_under_the_approver_key():
    assert pe.verify_approval(APPROVAL, APPROVER_KEYS).valid


def test_approval_is_the_one_the_trust_record_was_signed_over():
    assert TRUST_RECORD["transaction"]["signals"]["approvalArtifact"] == APPROVAL


def test_changed_amount_fails_the_trust_record():
    changed = copy.deepcopy(TRUST_RECORD)
    changed["transaction"]["intent"]["parameters"]["amount"] = 50000
    assert not pe.verify_trust_record(changed, PARMANA_KEYS).valid


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_changed_outcome_fails_a_refusal_record(case):
    changed = copy.deepcopy(REFUSALS[case])
    changed["decision"]["outcome"] = "APPROVED"
    assert not pe.verify_refusal_record(changed, PARMANA_KEYS).valid


def test_raised_limit_fails_the_approval():
    changed = copy.deepcopy(APPROVAL)
    changed["payload"]["scope"]["value"] = 500000
    assert not pe.verify_approval(changed, APPROVER_KEYS).valid


def test_another_key_fails_every_record():
    other = {"default": _approver["publicKeyPem"]}
    assert not pe.verify_trust_record(TRUST_RECORD, other).valid
    for record in REFUSALS.values():
        assert not pe.verify_refusal_record(record, other).valid


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_refusals_are_refusals(case):
    assert REFUSALS[case]["decision"]["outcome"] == "REJECTED"


def test_every_decision_is_under_the_same_policy_content():
    content_hash = TRUST_RECORD["transaction"]["policy"]["contentHash"]
    assert {r["policyContentHash"] for r in REFUSALS.values()} == {content_hash}


def test_references_are_what_the_records_produce():
    resolver = REFERENCES["valid-approval"][0]["resolver"]
    retention = REFERENCES["valid-approval"][0].get("retention")
    assert REFERENCES == {
        "valid-approval": pe.references_for(TRUST_RECORD, resolver, retention),
        **{c: pe.references_for(r, resolver, retention) for c, r in REFUSALS.items()},
    }


def test_references_are_trace_references():
    for entries in REFERENCES.values():
        for entry in entries:
            Reference(**entry)


def test_relations():
    assert [e["rel"] for e in REFERENCES["valid-approval"]] == [
        "authorized-intent",
        "approval-outcome",
    ]
    for case in REFUSALS:
        assert [e["rel"] for e in REFERENCES[case]] == ["authorized-intent"]


def test_no_reference_claims_an_observed_effect():
    rels = {e["rel"] for entries in REFERENCES.values() for e in entries}
    assert "observed-effect" not in rels


def test_the_connector_result_is_labelled_a_mock():
    cases = {c["case"]: c for c in REPORT["cases"]}
    assert "mock" in cases["valid-approval"]["connectorResult"]
    assert cases["refusal"]["connectorInvocations"] == 0
    assert cases["replay"]["connectorInvocations"] == 0
    assert REPORT["totalConnectorInvocations"] == 1
