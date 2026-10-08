from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest
from cmcp_runtime.tee.base import SoftwareOnlyProvider, make_nonce
from cmcp_runtime.tee.nras import AppraisalResult

from agentrust_auc import (
    AppraisalPolicy,
    BundleError,
    create_attestation_result,
    make_azure_placement_assertion,
    make_gcp_placement_assertion,
    make_placement_assertion,
    verify_attestation_result,
)
from agentrust_auc.core import new_keypair

NOW = datetime(2026, 8, 14, tzinfo=UTC)


def _inputs():
    verifier_key, verifier_public = new_keypair()
    placement_key, placement_public = new_keypair()
    workload_key = "ab" * 32
    report = SoftwareOnlyProvider().get_attestation_report(
        make_nonce(bytes.fromhex(workload_key), b"\x00" * 32)
    )
    report.attestation_generated_at = NOW
    appraisal = AppraisalResult(
        status="warning",
        verifier="local-software-appraiser",
        timestamp=NOW.isoformat(),
        ear_raw={"status": "warning", "reason": "software-only"},
    )
    placement = make_placement_assertion(
        workload_key=workload_key,
        jurisdiction="FR",
        operator="synthetic-operator",
        issued_at=NOW,
        validity_seconds=300,
        signing_key=placement_key,
    )
    return (
        verifier_key,
        verifier_public,
        placement_public,
        workload_key,
        report,
        appraisal,
        placement,
    )


def test_real_cmcp_software_provider_is_normalized_without_hardware_claim() -> None:
    verifier_key, verifier_public, placement_public, workload_key, report, appraisal, placement = (
        _inputs()
    )
    result = create_attestation_result(
        report=report,
        appraisal=appraisal,
        workload_key=workload_key,
        placement_assertion=placement,
        placement_trust_key=placement_public,
        policy=AppraisalPolicy("urn:auc:appraisal-policy:software-mve"),
        verifier_signing_key=verifier_key,
        now=NOW,
    )
    assert result["hardware_attested"] is False
    assert result["placement_evidence_basis"] == "operator-asserted-placement"
    verify_attestation_result(
        result,
        verifier_trust_key=verifier_public,
        placement_assertion=placement,
        placement_trust_key=placement_public,
        workload_key=workload_key,
        now=NOW,
    )


def test_hardware_required_policy_rejects_software_provider() -> None:
    verifier_key, _, placement_public, workload_key, report, appraisal, placement = _inputs()
    with pytest.raises(BundleError, match="requires hardware-attested"):
        create_attestation_result(
            report=report,
            appraisal=appraisal,
            workload_key=workload_key,
            placement_assertion=placement,
            placement_trust_key=placement_public,
            policy=AppraisalPolicy("urn:policy:hardware", require_hardware=True),
            verifier_signing_key=verifier_key,
            now=NOW,
        )


def test_stale_report_fails_closed() -> None:
    verifier_key, _, placement_public, workload_key, report, appraisal, placement = _inputs()
    report.attestation_generated_at = NOW - timedelta(seconds=301)
    with pytest.raises(BundleError, match="stale"):
        create_attestation_result(
            report=report,
            appraisal=appraisal,
            workload_key=workload_key,
            placement_assertion=placement,
            placement_trust_key=placement_public,
            policy=AppraisalPolicy("urn:policy:fresh", max_age_seconds=300),
            verifier_signing_key=verifier_key,
            now=NOW,
        )


def test_placement_substitution_fails_closed() -> None:
    verifier_key, verifier_public, placement_public, workload_key, report, appraisal, placement = (
        _inputs()
    )
    result = create_attestation_result(
        report=report,
        appraisal=appraisal,
        workload_key=workload_key,
        placement_assertion=placement,
        placement_trust_key=placement_public,
        policy=AppraisalPolicy("urn:policy:test"),
        verifier_signing_key=verifier_key,
        now=NOW,
    )
    substituted = copy.deepcopy(placement)
    substituted["jurisdiction"] = "US"
    with pytest.raises(BundleError, match="signature"):
        verify_attestation_result(
            result,
            verifier_trust_key=verifier_public,
            placement_assertion=substituted,
            placement_trust_key=placement_public,
            workload_key=workload_key,
            now=NOW,
        )


def test_hardware_label_without_raw_evidence_fails_closed() -> None:
    verifier_key, _, placement_public, workload_key, report, appraisal, placement = _inputs()
    report.provider = "tdx"
    appraisal.status = "affirming"
    with pytest.raises(BundleError, match="raw evidence"):
        create_attestation_result(
            report=report,
            appraisal=appraisal,
            workload_key=workload_key,
            placement_assertion=placement,
            placement_trust_key=placement_public,
            policy=AppraisalPolicy("urn:policy:hardware"),
            verifier_signing_key=verifier_key,
            now=NOW,
        )


def _azure_inputs() -> tuple[dict, dict]:
    imds = {
        "nonce": "1234567890",
        "subscriptionId": "11111111-2222-3333-4444-555555555555",
        "vmId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "timeStamp": {
            "createdOn": "08/13/26 23:59:55 +0000",
            "expiresOn": "08/14/26 00:05:00 +0000",
        },
    }
    arm = {
        "id": (
            "/subscriptions/11111111-2222-3333-4444-555555555555/"
            "resourceGroups/auc/providers/Microsoft.Compute/virtualMachines/auc-cvm"
        ),
        "location": "francecentral",
        "type": "Microsoft.Compute/virtualMachines",
        "properties": {"vmId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
    }
    return imds, arm


def test_azure_placement_joins_attested_identity_and_derives_jurisdiction() -> None:
    signing_key, public_key = new_keypair()
    imds, arm = _azure_inputs()
    assertion = make_azure_placement_assertion(
        workload_key="ab" * 32,
        imds_document=imds,
        arm_resource=arm,
        region_jurisdictions={"francecentral": "FR"},
        observed_at=NOW,
        validity_seconds=300,
        signing_key=signing_key,
    )
    assert assertion["jurisdiction"] == "FR"
    assert assertion["azure_region"] == "francecentral"
    assert assertion["evidence_basis"] == "azure-attested-imds+arm-control-plane"
    assert assertion["expires_at"] == int((NOW + timedelta(seconds=300)).timestamp())
    from agentrust_auc.core import _verify_signed

    _verify_signed(assertion, public_key)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda i, a: a["properties"].update({"vmId": "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"}),
            "VM ID",
        ),
        (lambda i, a: a.update({"location": "eastus"}), "jurisdiction mapping"),
        (lambda i, a: i.update({"nonce": "not-a-challenge"}), "challenge"),
        (
            lambda i, a: i["timeStamp"].update({"expiresOn": "08/13/26 23:59:59 +0000"}),
            "stale",
        ),
    ],
)
def test_azure_placement_fails_closed(mutation, message: str) -> None:
    signing_key, _ = new_keypair()
    imds, arm = _azure_inputs()
    mutation(imds, arm)
    with pytest.raises(BundleError, match=message):
        make_azure_placement_assertion(
            workload_key="ab" * 32,
            imds_document=imds,
            arm_resource=arm,
            region_jurisdictions={"francecentral": "FR"},
            observed_at=NOW,
            validity_seconds=300,
            signing_key=signing_key,
        )


def _gcp_claims() -> dict:
    return {
        "swname": "CONFIDENTIAL_SPACE",
        "hwmodel": "GCP_INTEL_TDX",
        "secboot": True,
        "dbgstat": "disabled-since-boot",
        "iat": int(NOW.timestamp()) - 1,
        "exp": int(NOW.timestamp()) + 300,
        "submods": {
            "gce": {"zone": "europe-west9-a", "project_id": "example-project", "instance_id": "7"},
            "container": {"image_digest": "sha256:" + "12" * 32},
        },
    }


def test_gcp_placement_derives_fr_without_claiming_hardware_geography() -> None:
    signing_key, public_key = new_keypair()
    assertion = make_gcp_placement_assertion(
        workload_key="ab" * 32,
        token="signed.jwt.token",
        verified_claims=_gcp_claims(),
        zone_jurisdictions={"europe-west9-a": "FR"},
        observed_at=NOW,
        validity_seconds=300,
        signing_key=signing_key,
    )
    assert assertion["jurisdiction"] == "FR"
    assert assertion["evidence_basis"] == "gcp-confidential-space-attested-zone"
    assert not assertion["evidence_basis"].startswith("hardware")
    from agentrust_auc.core import _verify_signed

    _verify_signed(assertion, public_key)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda c: c["submods"]["gce"].update({"zone": "us-central1-a"}), "mapping"),
        (lambda c: c.update({"hwmodel": "GCP_AMD_SEV"}), "Intel TDX"),
        (lambda c: c.update({"dbgstat": "enabled"}), "debug mode"),
        (lambda c: c.update({"secboot": False}), "Secure Boot"),
    ],
)
def test_gcp_placement_fails_closed(mutation, message: str) -> None:
    claims = _gcp_claims()
    mutation(claims)
    signing_key, _ = new_keypair()
    with pytest.raises(BundleError, match=message):
        make_gcp_placement_assertion(
            workload_key="ab" * 32,
            token="signed.jwt.token",
            verified_claims=claims,
            zone_jurisdictions={"europe-west9-a": "FR"},
            observed_at=NOW,
            validity_seconds=300,
            signing_key=signing_key,
        )
