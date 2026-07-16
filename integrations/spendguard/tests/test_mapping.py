"""SpendGuard evidence bundle -> TRACE Trust Record mapping tests."""

import json
from pathlib import Path

import agentrust_trace
import pytest

from spendguard_trace import build_trace_record

BUNDLE = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "allow"
IAT = 1782864000


@pytest.fixture(scope="module")
def key():
    return agentrust_trace.generate_key()


@pytest.fixture(scope="module")
def record(key):
    return build_trace_record(BUNDLE, iat=IAT, jwk=agentrust_trace.key_to_jwk(key))


def test_fields_map_from_signed_decision(record):
    decision = json.loads((BUNDLE / "decision.json").read_text())
    bundle = json.loads((BUNDLE / "bundle.json").read_text())
    ce = decision["cloudevent"]
    sg = ce["data_json"]["spendguard"]

    assert record["policy"]["bundle_hash"] == sg["policy_bundle_hash"]
    assert record["tool_transcript"]["hash"] == sg["tool_catalog_hash"]
    assert record["runtime"]["measurement"] == bundle["evidence_bundle_hash"]
    assert record["subject"] == (
        f"spiffe://spendguard.local/tenant/{ce['tenant_id']}/run/{ce['run_id']}"
    )
    assert record["model"] == ce["data_json"]["model"]
    # allow bundle has an outcome event -> one reserved call
    assert record["tool_transcript"]["call_count"] == 1


def test_record_has_no_cmcp_envelope_markers(record):
    # trace-tests 0.1.0 rejects plain records carrying any of these keys
    assert not {"signature", "trace", "gateway"} & record.keys()


def test_sign_verify_roundtrip(record, key):
    signed = agentrust_trace.sign_record(dict(record), key)
    agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)


def test_tampered_record_fails_verification(record, key):
    signed = agentrust_trace.sign_record(dict(record), key)
    signed["policy"]["bundle_hash"] = "sha256:" + "f" * 64
    with pytest.raises(Exception):
        agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)
