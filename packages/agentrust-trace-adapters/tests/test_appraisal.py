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
