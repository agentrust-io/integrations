"""Tests for V5 receipt verification and TRACE v0.2 record export."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import agentrust_trace
import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from trace_tests.result import Status
from trace_tests.runner import run as run_trace_tests

from _receipt_verify import CONFORMANCE_PUBLIC_KEYS, verify_v5_receipt
from ramen_ai_trace import (
    EAT_PROFILE,
    SOFTWARE_MEASUREMENT,
    _validate_receipt,
    build_trace_record,
)

FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "fixtures"
POLICY_BUNDLE_HASH = "sha256:" + hashlib.sha256(b"test-policy-bundle").hexdigest()
BUILD_DIGEST = "sha256:" + hashlib.sha256(b"ramen-cmcp-adapter-test-artifact").hexdigest()
MODEL = {"provider": "test-provider", "model_id": "test-evaluator", "version": "1"}
BUILD_PROVENANCE = {
    "slsa_level": 0,
    "builder": "https://github.com/ramen-ai-dev/ramen-ai-integrations",
    "digest": BUILD_DIGEST,
}
APPRAISAL_VERIFIER = "https://ramenai.dev/trace/software-only"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _private_key_pem(key: object) -> str:
    return key.private_bytes(  # type: ignore[union-attr]
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")


@pytest.fixture
def trace_key(monkeypatch: pytest.MonkeyPatch):
    key = agentrust_trace.generate_key()
    monkeypatch.setenv("TRACE_PRIVATE_KEY_PEM", _private_key_pem(key))
    return key


def _build(fixture: dict, *, iat: int) -> dict:
    return build_trace_record(
        fixture["receipt"],
        original_input=fixture["input"],
        iat=iat,
        model=MODEL,
        data_class="internal",
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        build_provenance=BUILD_PROVENANCE,
        appraisal_verifier=APPRAISAL_VERIFIER,
        receipt_public_keys=CONFORMANCE_PUBLIC_KEYS,
    )


class TestVerifyV5Receipt:
    def test_conformance_key_is_not_trusted_by_default(self):
        fixture = _load("vector1_allowed.json")
        valid, reason = verify_v5_receipt(fixture["receipt"], fixture["input"])
        assert valid is False
        assert "Unknown kid" in (reason or "")

    def test_vector1_allowed_valid_with_explicit_conformance_key(self):
        fixture = _load("vector1_allowed.json")
        assert verify_v5_receipt(
            fixture["receipt"],
            fixture["input"],
            extra_keys=CONFORMANCE_PUBLIC_KEYS,
        ) == (True, None)

    def test_vector2_blocked_valid_with_explicit_conformance_key(self):
        fixture = _load("vector2_blocked.json")
        assert verify_v5_receipt(
            fixture["receipt"],
            fixture["input"],
            extra_keys=CONFORMANCE_PUBLIC_KEYS,
        ) == (True, None)

    def test_payload_hashes_bind_original_inputs(self):
        for name in ("vector1_allowed.json", "vector2_blocked.json"):
            fixture = _load(name)
            payload = json.loads(fixture["receipt"]["canonical_payload"])
            assert payload["payload_hash"] == hashlib.sha256(
                fixture["input"].encode("utf-8")
            ).hexdigest()

    def test_tampered_signature_fails(self):
        fixture = _load("vector_n1_bad_sig.json")
        valid, reason = verify_v5_receipt(
            fixture["receipt"],
            fixture["input"],
            extra_keys=CONFORMANCE_PUBLIC_KEYS,
        )
        assert valid is False
        assert "signature" in (reason or "").lower()

    def test_wrong_input_fails_binding(self):
        fixture = _load("vector1_allowed.json")
        valid, reason = verify_v5_receipt(
            fixture["receipt"],
            fixture["input"] + " ",
            extra_keys=CONFORMANCE_PUBLIC_KEYS,
        )
        assert valid is False
        assert "payload_hash" in (reason or "")

    def test_unknown_kid_fails(self):
        fixture = _load("vector1_allowed.json")
        receipt = dict(fixture["receipt"], kid="ramen_pk_unknown_xyz")
        valid, reason = verify_v5_receipt(
            receipt,
            fixture["input"],
            extra_keys=CONFORMANCE_PUBLIC_KEYS,
        )
        assert valid is False
        assert "Unknown kid" in (reason or "")


class TestBuildTraceRecord:
    @pytest.fixture
    def allowed_record(self, trace_key):
        return _build(_load("vector1_allowed.json"), iat=1_800_000_000)

    @pytest.fixture
    def blocked_record(self, trace_key):
        return _build(_load("vector2_blocked.json"), iat=1_800_000_001)

    def test_v02_profile_and_complete_required_claims(self, allowed_record):
        assert allowed_record["eat_profile"] == EAT_PROFILE
        assert allowed_record["model"] == MODEL
        assert allowed_record["data_class"] == "internal"
        assert allowed_record["build_provenance"] == BUILD_PROVENANCE
        assert allowed_record["policy"]["bundle_hash"] == POLICY_BUNDLE_HASH

    def test_strict_software_only_semantics(self, allowed_record):
        assert allowed_record["runtime"] == {
            "platform": "software-only",
            "measurement": SOFTWARE_MEASUREMENT,
        }
        assert allowed_record["appraisal"] == {
            "status": "none",
            "verifier": APPRAISAL_VERIFIER,
            "timestamp": 1_800_000_000,
        }
        assert "transparency" not in allowed_record

    def test_subject_binds_receipt_without_false_transcript_claim(self, allowed_record):
        receipt = _load("vector1_allowed.json")["receipt"]
        assert allowed_record["subject"] == (
            f"spiffe://ramenai.dev/evaluation/{receipt['id']}"
        )
        assert "tool_transcript" not in allowed_record

    def test_native_signature_uses_dedicated_trace_key(self, allowed_record, trace_key):
        expected_jwk = agentrust_trace.key_to_jwk(trace_key)
        assert allowed_record["cnf"]["jwk"] == expected_jwk
        assert allowed_record["signature"]
        assert "=" not in allowed_record["signature"]
        agentrust_trace.verify_record(allowed_record, expected_jwk, max_age_seconds=None)

    def test_blocked_receipt_does_not_claim_hardware_appraisal(self, blocked_record):
        assert blocked_record["appraisal"]["status"] == "none"
        assert blocked_record["runtime"]["platform"] == "software-only"

    def test_forged_receipt_is_never_trace_signed(self, trace_key):
        with pytest.raises(ValueError, match="V5 receipt verification failed"):
            _build(_load("vector_n1_bad_sig.json"), iat=1_800_000_000)

    def test_wrong_original_input_is_never_trace_signed(self, trace_key):
        fixture = _load("vector1_allowed.json")
        fixture["input"] += " "
        with pytest.raises(ValueError, match="V5 receipt verification failed"):
            _build(fixture, iat=1_800_000_000)

    def test_missing_trace_private_key_fails_closed(self, monkeypatch):
        monkeypatch.delenv("TRACE_PRIVATE_KEY_PEM", raising=False)
        with pytest.raises(RuntimeError, match="TRACE_PRIVATE_KEY_PEM is required"):
            _build(_load("vector1_allowed.json"), iat=1_800_000_000)

    def test_invalid_trace_private_key_is_rejected(self, monkeypatch):
        monkeypatch.setenv(
            "TRACE_PRIVATE_KEY_PEM",
            "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
        )
        with pytest.raises(ValueError, match="not a valid private key"):
            _build(_load("vector1_allowed.json"), iat=1_800_000_000)

    def test_required_caller_evidence_is_validated(self, trace_key):
        fixture = _load("vector1_allowed.json")
        with pytest.raises(ValueError, match="policy_bundle_hash"):
            build_trace_record(
                fixture["receipt"],
                original_input=fixture["input"],
                iat=1_800_000_000,
                model=MODEL,
                data_class="internal",
                policy_bundle_hash="not-a-digest",
                build_provenance=BUILD_PROVENANCE,
                appraisal_verifier=APPRAISAL_VERIFIER,
                receipt_public_keys=CONFORMANCE_PUBLIC_KEYS,
            )

    def test_receipt_identity_must_match_signed_payload(self, trace_key):
        fixture = _load("vector1_allowed.json")
        fixture["receipt"] = dict(
            fixture["receipt"], id="00000000-0000-0000-0000-000000000000"
        )
        with pytest.raises(ValueError, match="does not match canonical_payload"):
            _build(fixture, iat=1_800_000_000)

    def test_missing_receipt_field_raises(self):
        with pytest.raises(ValueError, match="missing required fields"):
            _validate_receipt({"id": "x", "schema_version": "5.0", "kid": "k"})

    def test_wrong_receipt_schema_version_raises(self):
        fixture = _load("vector1_allowed.json")
        receipt = dict(fixture["receipt"], schema_version="4.0")
        with pytest.raises(ValueError, match="schema_version"):
            _validate_receipt(receipt)

    def test_invalid_canonical_payload_json_raises(self):
        fixture = _load("vector1_allowed.json")
        receipt = dict(fixture["receipt"], canonical_payload="{not json}")
        with pytest.raises(ValueError, match="canonical_payload"):
            _validate_receipt(receipt)


class TestTraceConformance:
    def test_signed_software_record_passes_level_0(self, trace_key):
        record = _build(_load("vector1_allowed.json"), iat=int(time.time()))
        results = run_trace_tests(record, "trace", level=0)
        findings = [finding for group in results.values() for finding in group]
        assert len(findings) == 8
        assert all(finding.status is Status.PASS for finding in findings)
        assert [
            finding.status for finding in findings if finding.code == "TR-SIG-005"
        ] == [Status.PASS]

    def test_signed_software_record_fails_only_level_1_runtime_rule(self, trace_key):
        record = _build(_load("vector1_allowed.json"), iat=int(time.time()))
        results = run_trace_tests(record, "trace", level=1)
        failures = [
            finding
            for findings in results.values()
            for finding in findings
            if finding.status is Status.FAIL
        ]
        assert [(finding.code, finding.message) for finding in failures] == [
            (
                "TR-RTE-001",
                "TR-RTE-001: runtime.platform 'software-only' is development-mode "
                "and not acceptable for hardware-attested levels (Level 1 requires "
                "a hardware TEE platform)",
            )
        ]
