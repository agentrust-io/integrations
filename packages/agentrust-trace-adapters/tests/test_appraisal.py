import pytest

from agentrust_trace_adapters import AppraisalEvidence, MissingEvidence, appraisal_from_evidence


def test_verified_evidence_maps_to_appraisal() -> None:
    evidence = AppraisalEvidence(
        verifier="https://verifier.example",
        status="affirming",
        policy_ref="urn:policy:sha256:abc",
        signature_verified=True,
        timestamp=1_800_000_000,
    )
    assert appraisal_from_evidence(evidence) == {
        "status": "affirming",
        "verifier": "https://verifier.example",
        "policy_ref": "urn:policy:sha256:abc",
        "timestamp": 1_800_000_000,
    }


def test_unsigned_vendor_verdict_is_not_an_appraisal() -> None:
    with pytest.raises(MissingEvidence, match="signature is verified"):
        AppraisalEvidence(
            verifier="vendor", status="affirming", policy_ref="urn:policy:1",
            signature_verified=False,
        )


@pytest.mark.parametrize("missing", ["verifier", "policy_ref"])
def test_appraisal_requires_identity_and_policy(missing: str) -> None:
    kwargs = {"verifier": "vendor", "status": "warning", "policy_ref": "urn:policy:1", "signature_verified": True}
    kwargs[missing] = ""
    with pytest.raises(MissingEvidence):
        AppraisalEvidence(**kwargs)


def test_appraisal_source_system_and_builder_validate_types_and_reject_private_jwk() -> None:
    from agentrust_trace_adapters import PolicyEvidence, SourceSystem, build_record

    for bad_verified in ("true", 1, None):
        with pytest.raises(MissingEvidence):
            AppraisalEvidence(
                verifier="https://verifier.example/v1",
                status="affirming",
                policy_ref="https://policy.example/v1",
                signature_verified=bad_verified,  # type: ignore[arg-type]
            )
    for bad_ts in (True, False, 0, -5, 1.5, 2**53):
        with pytest.raises(ValueError):
            AppraisalEvidence(
                verifier="https://verifier.example/v1",
                status="affirming",
                policy_ref="https://policy.example/v1",
                signature_verified=True,
                timestamp=bad_ts,  # type: ignore[arg-type]
            )
    with pytest.raises(ValueError):
        SourceSystem(producer="https://producer.example/v1", ingested_at=1_700_000_000.5)  # type: ignore[arg-type]

    src = SourceSystem(producer="https://producer.example/v1")
    pol = PolicyEvidence(bundle=b"policy-bytes", enforcement_mode="enforce")
    base_kwargs = dict(
        source=src,
        subject="spiffe://example/agent",
        model_provider="p",
        model_id="m",
        policy=pol,
        data_class="internal",
        jwk={"kty": "OKP", "crv": "Ed25519", "x": "a" * 43},
        workload_digest="sha256:" + "a" * 64,
    )
    for valid_iat in (1_700_000_000, 9_007_199_254_740_991):
        rec = build_record(**base_kwargs, iat=valid_iat)
        assert rec["iat"] == valid_iat
    for bad_iat in (True, False, 0, -1, 1, 1_699_999_999, 1.5, 9_007_199_254_740_992):
        with pytest.raises(ValueError):
            build_record(**base_kwargs, iat=bad_iat)  # type: ignore[arg-type]
    for bad_count in (True, False, -1, 1.5, 2**53):
        with pytest.raises(ValueError):
            build_record(
                **base_kwargs,
                transcript_bytes=b"transcript",
                tool_call_count=bad_count,  # type: ignore[arg-type]
            )
    with pytest.raises(ValueError):
        build_record(
            **{
                **base_kwargs,
                "jwk": {"kty": "OKP", "crv": "Ed25519", "x": "a" * 43, "d": "secret"},
            }
        )


def test_appraisal_from_evidence_integrates_into_trust_record() -> None:
    from agentrust_trace.models import TrustRecord
    from agentrust_trace_adapters import PolicyEvidence, SourceSystem, build_record

    record = build_record(
        source=SourceSystem(producer="https://producer.example/v1"),
        subject="spiffe://example/agent",
        model_provider="provider",
        model_id="model-1",
        policy=PolicyEvidence(bundle=b"policy-bytes", enforcement_mode="enforce"),
        data_class="internal",
        jwk={"kty": "OKP", "crv": "Ed25519", "x": "a" * 43},
        workload_digest="sha256:" + "a" * 64,
        iat=1_700_000_000,
    )
    record["appraisal"] = appraisal_from_evidence(
        AppraisalEvidence(
            verifier="https://verifier.example/v1",
            status="affirming",
            policy_ref="https://policy.example/v1",
            signature_verified=True,
            timestamp=1_800_000_000,
        )
    )
    validated = TrustRecord.model_validate(record)
    assert validated.iat == 1_700_000_000
    assert validated.appraisal.verifier == "https://verifier.example/v1"
    assert validated.appraisal.policy_ref == "https://policy.example/v1"
