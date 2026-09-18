from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ontoguard_trace as og

FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "fixtures"
FIXED_VERIFICATION_TIME = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _project(fixture: dict, **kwargs):
    kwargs.setdefault("verification_time_utc", FIXED_VERIFICATION_TIME)
    return og.project(
        fixture["authorization_result"],
        signature_b64url=fixture["authorization_signature"],
        public_jwk=fixture["authorization_public_jwk"],
        claimed_digest=fixture["authorization_result_bytes_sha256"],
        result_bytes=fixture["authorization_result_exact"].encode("utf-8"),
        execution_receipt=fixture.get("execution_receipt"),
        allow_test_keys=True,
        **kwargs,
    )


@pytest.mark.parametrize(
    "name,expected",
    [
        ("block_no_execution.json", "BLOCK_NO_EXECUTION"),
        ("escalate_no_execution.json", "ESCALATE_NO_EXECUTION"),
        ("allow_no_execution_yet.json", "ALLOW_NO_EXECUTION_YET"),
    ],
)
def test_non_execution_states(name: str, expected: str) -> None:
    fixture = _load(name)
    assert (
        og.classify(
            fixture["authorization_result"],
            fixture.get("execution_receipt"),
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )
        == expected
    )
    result = _project(fixture)
    assert result["trace_record_emitted"] is False
    assert result["trace_record"] is None


def test_exact_signed_bytes_are_required_and_not_reconstructed() -> None:
    fixture = _load("allow_execution_proven.json")
    raw = fixture["authorization_result_exact"].encode("utf-8")
    parsed = og.parse_signed_json_object(raw, "test")
    assert parsed == fixture["authorization_result"]
    with pytest.raises(og.AdapterError, match="does not match exact signed bytes"):
        og.project(
            {**fixture["authorization_result"], "trace_id": "other"},
            signature_b64url=fixture["authorization_signature"],
            public_jwk=fixture["authorization_public_jwk"],
            result_bytes=raw,
            allow_test_keys=True,
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_executed_path_emits_string_subject_and_registered_rel() -> None:
    fixture = _load("allow_execution_proven.json")
    result = _project(fixture)
    assert result["trace_record_emitted"] is False
    record = result["trace_claim_candidate"]
    assert isinstance(record["subject"], str)
    assert record["subject"].startswith(("spiffe://","did:"))
    assert record["references"][0]["rel"] == "authorized-intent"
    assert record["references"][0]["id"] == fixture["authorization_result"]["handoff_hash"]
    assert record["references"][0]["digest"] == fixture["authorization_result_bytes_sha256"]
    assert record["references"][0]["digest"] == result["authorization"]["result_digest"]
    assert record["origin"]["source_event_id"] == fixture["execution_receipt"]["execution_event_id"]
    assert record["origin"]["producer"] == fixture["execution_receipt"]["execution_producer"]
    assert record["origin"]["source_event_id"] != fixture["authorization_result"]["trace_id"]


def test_digest_is_recomputed_not_trusted() -> None:
    fixture = _load("allow_execution_proven.json")
    with pytest.raises(og.AdapterError, match="digest mismatch"):
        og.project(
            fixture["authorization_result"],
            signature_b64url=fixture["authorization_signature"],
            public_jwk=fixture["authorization_public_jwk"],
            claimed_digest="sha256:" + "00" * 32,
            result_bytes=fixture["authorization_result_exact"].encode("utf-8"),
            execution_receipt=fixture["execution_receipt"],
            allow_test_keys=True,
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_tampered_result_bytes_fail_signature() -> None:
    fixture = _load("allow_execution_proven.json")
    tampered = deepcopy(fixture["authorization_result"])
    tampered["trace_id"] = "tampered-trace"
    with pytest.raises(og.AdapterError, match="signature verification failed"):
        og.project(
            tampered,
            signature_b64url=fixture["authorization_signature"],
            public_jwk=fixture["authorization_public_jwk"],
            result_bytes=json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode(),
            execution_receipt=fixture["execution_receipt"],
            allow_test_keys=True,
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_stale_handoff_on_execution_receipt() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["authorized_handoff_hash"] = "sha256:" + "00" * 32
    with pytest.raises(og.AdapterError, match="does not match exact signed bytes"):
        _project({**fixture, "execution_receipt": receipt})


def test_stale_result_digest_on_execution_receipt() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["authorized_result_digest"] = "sha256:" + "00" * 32
    with pytest.raises(og.AdapterError, match="does not match exact signed bytes"):
        _project({**fixture, "execution_receipt": receipt})


def test_mismatched_decision_binding_on_execution_receipt() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["authorized_decision_binding_hash"] = "sha256:" + "00" * 32
    with pytest.raises(og.AdapterError, match="does not match exact signed bytes"):
        _project({**fixture, "execution_receipt": receipt})


def test_block_with_executed_receipt_is_rejected() -> None:
    fixture = _load("block_no_execution.json")
    receipt = {
        "executed": True,
        "protected_effect_formed": True,
        "authorized_handoff_hash": fixture["authorization_result"]["handoff_hash"],
        "authorized_result_digest": fixture["authorization_result_bytes_sha256"],
        "subject": "spiffe://example.ontoguard.ai/workload/x",
        "policy": {"bundle_hash": "sha256:" + "dd" * 32, "enforcement_mode": "enforce"},
        "build_provenance": {"digest": "sha256:" + "ee" * 32, "slsa_level": 0},
    }
    with pytest.raises(og.AdapterError, match="cannot be paired with executed=true"):
        og.classify(
            fixture["authorization_result"],
            receipt,
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_allow_does_not_prove_execution_without_receipt() -> None:
    fixture = _load("allow_execution_proven.json")
    result = og.project(
        fixture["authorization_result"],
        signature_b64url=fixture["authorization_signature"],
        public_jwk=fixture["authorization_public_jwk"],
        claimed_digest=fixture["authorization_result_bytes_sha256"],
        result_bytes=fixture["authorization_result_exact"].encode("utf-8"),
        execution_receipt=None,
        allow_test_keys=True,
        verification_time_utc=FIXED_VERIFICATION_TIME,
    )
    assert result["state"] == "ALLOW_NO_EXECUTION_YET"
    assert result["trace_record_emitted"] is False


def test_subject_object_is_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["subject"] = {"id": "spiffe://example.ontoguard.ai/workload/payments-release"}
    with pytest.raises(og.AdapterError, match="SPIFFE or DID string"):
        _project({**fixture, "execution_receipt": receipt})


def test_untrusted_authorization_jwk_is_rejected() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    fixture = _load("allow_execution_proven.json")
    rogue = Ed25519PrivateKey.generate()
    x = og._b64url_encode(rogue.public_key().public_bytes_raw())
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    with pytest.raises(og.AdapterError, match="not in the trusted allowlist"):
        og.project(
            fixture["authorization_result"],
            signature_b64url=fixture["authorization_signature"],
            public_jwk=jwk,
            result_bytes=fixture["authorization_result_exact"].encode("utf-8"),
            allow_test_keys=True,
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_allow_without_release_authorized_cannot_emit() -> None:
    fixture = _load("allow_no_execution_yet.json")
    result = dict(fixture["authorization_result"])
    result["release_authorized"] = False
    with pytest.raises(og.AdapterError, match="release_authorized"):
        og.classify(
            result,
            fixture["execution_receipt"] or {"executed": True},
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_unsigned_output_is_not_a_trace_record() -> None:
    fixture = _load("allow_execution_proven.json")
    result = _project(fixture, sign_trace=False)
    assert result["trace_record_emitted"] is False
    assert result["trace_record"] is None
    assert result["trace_claim_candidate"]["subject"].startswith(("spiffe://","did:"))


def test_missing_slsa_level_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["build_provenance"] = dict(receipt["build_provenance"])
    del receipt["build_provenance"]["slsa_level"]
    with pytest.raises(og.AdapterError, match="slsa_level"):
        _project({**fixture, "execution_receipt": receipt})


def test_missing_model_is_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["model"] = {"provider": "example"}
    with pytest.raises(og.AdapterError, match="model.model_id"):
        _project({**fixture, "execution_receipt": receipt})


def test_missing_data_class_is_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    del receipt["data_class"]
    with pytest.raises(og.AdapterError, match="data_class"):
        _project({**fixture, "execution_receipt": receipt})


def test_movement_hash_mismatch_is_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["executed_movement_hash"] = "sha256:" + "00" * 32
    with pytest.raises(og.AdapterError, match="executed_movement_hash"):
        _project({**fixture, "execution_receipt": receipt})


def test_expired_authorization_is_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    result = dict(fixture["authorization_result"])
    result["expires_at_utc"] = "2000-01-01T00:00:00Z"
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(og.AdapterError, match="expired"):
        og.project(
            result,
            signature_b64url=fixture["authorization_signature"],
            public_jwk=fixture["authorization_public_jwk"],
            result_bytes=raw,
            allow_test_keys=True,
            verification_time_utc=FIXED_VERIFICATION_TIME,
        )


def test_action_binding_mismatch_is_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    receipt["executed_action_binding_digest"] = "sha256:" + "00" * 32
    with pytest.raises(og.AdapterError, match="executed_action_binding_digest"):
        _project({**fixture, "execution_receipt": receipt})


def test_omitted_action_binding_fields_are_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    del receipt["authorized_action_binding_digest"]
    del receipt["executed_action_binding_digest"]
    with pytest.raises(og.AdapterError, match="missing required authorization bindings"):
        _project({**fixture, "execution_receipt": receipt})


def test_omitted_trace_and_decision_bindings_are_rejected() -> None:
    fixture = _load("allow_execution_proven.json")
    receipt = deepcopy(fixture["execution_receipt"])
    del receipt["authorized_trace_id"]
    del receipt["authorized_decision_binding_hash"]
    with pytest.raises(og.AdapterError, match="missing required authorization bindings"):
        _project({**fixture, "execution_receipt": receipt})
