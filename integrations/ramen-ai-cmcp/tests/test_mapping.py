"""ramen-ai TRACE record mapping tests.

Verifies that build_trace_record correctly maps the committed V5 fixture
receipt onto TRACE Trust Record fields, and that the sign/verify round-trip
and tamper probe work as expected.

No network access or credentials required.
"""
from __future__ import annotations

import json
from pathlib import Path

import agentrust_trace
import pytest

from ramen_ai_trace import build_trace_record, _validate_receipt

FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "fixtures"
BUNDLE = FIXTURES / "vector1_allowed.json"
IAT = 1_800_000_000


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _dummy_jwk() -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}


@pytest.fixture(scope="module")
def key():
    return agentrust_trace.generate_key()


@pytest.fixture(scope="module")
def record():
    f = _load("vector1_allowed.json")
    return build_trace_record(f["receipt"], iat=IAT, jwk=_dummy_jwk())


# ── field mapping ───────────────────────────────────────────────────────────

def test_eat_profile(record):
    assert record["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"


def test_subject_is_spiffe_uri(record):
    assert record["subject"].startswith("spiffe://ramenai.dev/evaluation/")


def test_policy_bundle_hash_has_sha256_prefix(record):
    assert record["policy"]["bundle_hash"].startswith("sha256:")


def test_policy_enforcement_mode(record):
    assert record["policy"]["enforcement_mode"] == "enforce"


def test_runtime_platform(record):
    assert record["runtime"]["platform"] == "software-only"


def test_tool_transcript_call_count(record):
    assert record["tool_transcript"]["call_count"] == 1


def test_tool_transcript_hash_has_sha256_prefix(record):
    assert record["tool_transcript"]["hash"].startswith("sha256:")


def test_appraisal_status_affirming_for_allowed(record):
    assert record["appraisal"]["status"] == "affirming"


def test_no_cmcp_envelope_markers(record):
    assert not {"signature", "trace", "gateway"} & record.keys()


def test_fields_map_from_fixture(record):
    f = _load("vector1_allowed.json")
    payload = json.loads(f["receipt"]["canonical_payload"])
    assert record["policy"]["bundle_hash"] == f"sha256:{payload['payload_hash']}"
    assert record["runtime"]["measurement"] == f["receipt"]["id"]
    assert record["tool_transcript"]["hash"] == f"sha256:{payload['payload_hash']}"
    assert payload["policy_ids"][0] in record["appraisal"]["policy_ref"]


# ── sign/verify round-trip ───────────────────────────────────────────────────

def test_sign_verify_roundtrip(record):
    k = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), k)
    agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)


def test_tampered_record_fails_verification(record):
    k = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), k)
    signed["policy"]["bundle_hash"] = "sha256:" + "f" * 64
    with pytest.raises(Exception):
        agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)


# ── _validate_receipt guards ─────────────────────────────────────────────────

def test_missing_field_raises():
    with pytest.raises(ValueError, match="missing required fields"):
        _validate_receipt({"id": "x", "schema_version": "5.0", "kid": "k"})


def test_wrong_schema_version_raises():
    f = _load("vector1_allowed.json")
    with pytest.raises(ValueError, match="schema_version"):
        _validate_receipt(dict(f["receipt"], schema_version="4.0"))
