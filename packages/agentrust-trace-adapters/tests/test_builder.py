"""What these tests are for.

Every one of them pins a way the adapter could produce a record that validates
and is not true. The list is not hypothetical: five of the seven validation
failures in the adapter that existed before this package were a placeholder in a
required-shaped field.
"""

from __future__ import annotations

import pytest

from agentrust_trace_adapters import (
    MissingEvidence,
    PolicyEvidence,
    SourceSystem,
    build_record,
    digest_bytes,
    software_measurement,
)

JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
DIGEST = "sha256:" + "b" * 64


def _kwargs(**overrides):
    base = dict(
        source=SourceSystem(producer="vendor-gateway/2.1", source_event_id="evt-1"),
        subject="spiffe://example.org/agent/imported",
        model_provider="anthropic",
        model_id="claude-sonnet-4-6",
        policy=PolicyEvidence(bundle=b'{"rules": []}'),
        data_class="internal",
        jwk=JWK,
        workload_digest=DIGEST,
    )
    base.update(overrides)
    return base


# --- the three things an adapter may not decide ---------------------------


def test_platform_is_always_software_only() -> None:
    rec = build_record(**_kwargs())
    assert rec["runtime"]["platform"] == "software-only"


def test_appraisal_is_none_and_names_the_producer() -> None:
    """Transcribing is not appraising, and the verifier is never us."""
    rec = build_record(**_kwargs())
    assert rec["appraisal"]["status"] == "none"
    assert rec["appraisal"]["verifier"] == "vendor-gateway/2.1"


def test_slsa_level_is_zero() -> None:
    assert build_record(**_kwargs())["build_provenance"]["slsa_level"] == 0


def test_origin_block_is_present_and_not_self() -> None:
    rec = build_record(**_kwargs())
    assert rec["origin"]["kind"] == "third-party-control-plane"
    assert rec["origin"]["producer"] == "vendor-gateway/2.1"
    assert rec["origin"]["source_event_id"] == "evt-1"


def test_self_origin_is_refused() -> None:
    with pytest.raises(ValueError, match="self"):
        SourceSystem(producer="cmcp/0.4.0", kind="self")


# --- placeholders, one test per historical failure ------------------------


def test_policy_needs_real_bundle_bytes() -> None:
    with pytest.raises(MissingEvidence, match="policy bundle bytes"):
        PolicyEvidence(bundle=b"")


def test_policy_bundle_hash_is_over_the_bundle() -> None:
    policy = PolicyEvidence(bundle=b'{"rules": []}')
    assert policy.bundle_hash == digest_bytes(b'{"rules": []}')


def test_workload_digest_is_required_and_not_defaulted() -> None:
    with pytest.raises(MissingEvidence, match="build_provenance.digest"):
        build_record(**_kwargs(workload_digest=None))


def test_workload_digest_must_be_a_digest() -> None:
    with pytest.raises(ValueError, match="not a sha256"):
        build_record(**_kwargs(workload_digest="sha256:placeholder"))


def test_weights_digest_placeholder_is_refused_not_passed_through() -> None:
    with pytest.raises(ValueError, match="Omit it instead"):
        build_record(**_kwargs(model_weights_digest="sha256:placeholder-no-model"))


def test_weights_digest_is_omitted_when_unknown() -> None:
    """Absence is the truth. The field is optional precisely so this is expressible."""
    assert "weights_digest" not in build_record(**_kwargs())["model"]


def test_model_identity_is_required() -> None:
    with pytest.raises(MissingEvidence, match="model_provider"):
        build_record(**_kwargs(model_id=""))


def test_subject_must_be_spiffe_or_did() -> None:
    with pytest.raises(ValueError, match="SPIFFE"):
        build_record(**_kwargs(subject="vendor-session-1234"))


def test_digest_of_empty_input_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="digest of nothing"):
        digest_bytes(b"")


def test_digest_requires_bytes_not_a_description_of_bytes() -> None:
    with pytest.raises(TypeError):
        digest_bytes("policy-v1.2")  # type: ignore[arg-type]


# --- transcript: absent is not empty --------------------------------------


def test_transcript_omitted_when_there_is_none() -> None:
    assert "tool_transcript" not in build_record(**_kwargs())


def test_transcript_hash_is_over_supplied_bytes() -> None:
    rec = build_record(**_kwargs(transcript_bytes=b"[]", tool_call_count=0))
    assert rec["tool_transcript"]["hash"] == digest_bytes(b"[]")
    assert rec["tool_transcript"]["call_count"] == 0


def test_call_count_without_transcript_is_refused() -> None:
    """A count with no hash binding it is an unbound assertion."""
    with pytest.raises(MissingEvidence, match="transcript bytes"):
        build_record(**_kwargs(tool_call_count=7))


# --- other honesty rules ---------------------------------------------------


def test_transparency_is_omitted_not_empty() -> None:
    assert "transparency" not in build_record(**_kwargs())


def test_measurement_is_deterministic_over_its_inputs() -> None:
    a = build_record(**_kwargs())["runtime"]["measurement"]
    b = build_record(**_kwargs())["runtime"]["measurement"]
    assert a == b
    c = build_record(**_kwargs(policy=PolicyEvidence(bundle=b'{"rules": [1]}')))
    assert c["runtime"]["measurement"] != a


def test_software_measurement_refuses_empty_inputs() -> None:
    with pytest.raises(MissingEvidence):
        software_measurement("")


def test_producer_is_required() -> None:
    with pytest.raises(MissingEvidence, match="producer is required"):
        SourceSystem(producer="  ")


def test_ingested_at_rejects_milliseconds() -> None:
    with pytest.raises(ValueError, match="plausible Unix seconds"):
        SourceSystem(producer="x/1.0", ingested_at=1_700_000_000_000)


def test_enforcement_mode_is_closed() -> None:
    with pytest.raises(ValueError, match="enforcement_mode"):
        PolicyEvidence(bundle=b"{}", enforcement_mode="monitor")


# --- the test the previous adapter did not have ---------------------------


def test_record_validates_against_the_released_model() -> None:
    """The whole failure this package exists to prevent, checked directly.

    The adapter that preceded it emitted records that failed TrustRecord
    validation on seven counts and nothing in its repository noticed.
    """
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    record = build_record(**_kwargs(transcript_bytes=b'[{"tool":"search"}]', tool_call_count=1))
    parsed = TrustRecord.model_validate(record)
    assert parsed.origin is not None
    assert parsed.origin.kind == "third-party-control-plane"
    assert parsed.runtime.platform == "software-only"


def test_model_rejects_a_hardware_platform_on_an_imported_record() -> None:
    """The cross-field rule in TRACE 0.7.0, exercised from the adapter side.

    A future refactor that let ``platform`` become a parameter would be caught
    here rather than in production.
    """
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    ValidationError = pytest.importorskip("pydantic").ValidationError
    record = build_record(**_kwargs())
    record["runtime"]["platform"] = "intel-tdx"
    with pytest.raises(ValidationError, match="software-only"):
        TrustRecord.model_validate(record)
