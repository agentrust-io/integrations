"""Tests for the WCM -> Azure Secure Key Release translation.

The theme is refusing to produce a policy that cannot work. A release policy
comparing a 64-hex WCM measurement against a 96-hex SNP launch measurement never
matches, and the engineer debugging it concludes the CVM is broken. Every such
case fails at generation time with a message naming the real problem.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import Challenge, WeightCustodyManifest  # noqa: E402

from wcm_azure_skr import (  # noqa: E402
    ATTESTATION_TYPE_BY_PLATFORM,
    MAA_CLAIMS,
    SKR_POLICY_VERSION,
    SkrPolicyError,
    build_release_policy,
    evidence_from_maa_claims,
    main,
)

AUTHORITY = "https://sharedeus.eus.attest.azure.net"
SERVING = "sha256:" + "5e2d" * 16
RETIRING = "sha256:" + "6f3e" * 16
REVOKED = "sha256:" + "70af" * 16
WEIGHTS = "sha256:" + "4a1c" * 16


def make_manifest(**policy_overrides: object) -> WeightCustodyManifest:
    release_policy: dict = {
        "required_assurance_tier": "hardware-attested",
        "physical_hardening": "not-required",
        "trusted_time_source": "secure-tsc",
        "memory_fingerprint_challenge": "not-required",
        "required_hw_platform": ["amd-sev-snp"],
        "tenancy": "shared",
        "required_serving_image": {
            "signer": "ed25519:builder-key",
            "release_rule": "prefer-current",
            "accepted_measurements": [
                {"measurement": SERVING, "status": "current"},
                {"measurement": RETIRING, "status": "retiring", "retire_after": "2026-12-01T00:00:00Z"},
                {"measurement": REVOKED, "status": "revoked"},
            ],
        },
        "key_release_mode": "attestation-gated",
        "replay_protection": "kbs-nonce-required",
        "revocation_authority": "builder-and-opaque-joint",
    }
    release_policy.update(policy_overrides)
    return WeightCustodyManifest.model_validate(
        {
            "manifest_version": "0.1",
            "weights_hash": WEIGHTS,
            "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
            "release_terms": {
                "license": "customer-deployment-agreement-ref:CDA-2026-0091",
                "permitted_derivatives": "fine-tune-only",
                "permitted_environments": ["attested-enclave"],
            },
            "release_policy": release_policy,
            "custody": {
                "custodian": "example-custodian",
                "custodian_type": "opaque-hosted",
                "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
                "enclave_id": "did:example:enclave-04",
                "attestation_cadence": "24h",
            },
            "signatures": [],
        }
    )


def challenge() -> Challenge:
    now = dt.datetime(2026, 8, 27, tzinfo=dt.timezone.utc)
    return Challenge(nonce="a" * 64, issued_at=now, expires_at=now + dt.timedelta(minutes=5))


def good_claims(**overrides: object) -> dict:
    claims = {
        "x-ms-attestation-type": "sevsnpvm",
        "x-ms-compliance-status": "azure-compliant-cvm",
        "x-ms-sevsnpvm-is-debuggable": "false",
        "x-ms-sevsnpvm-idkeydigest": "cd" * 48,
    }
    claims.update(overrides)
    return claims


def policy(**kwargs: object) -> dict:
    base = dict(
        authority=AUTHORITY, measurement_claim="x-ms-sevsnpvm-hostdata"
    )
    base.update(kwargs)
    return build_release_policy(make_manifest(), **base)  # type: ignore[arg-type]


def test_measurement_claim_cannot_be_inferred() -> None:
    """The central refusal: WCM is 256-bit, SNP launch measurement is 384-bit."""
    with pytest.raises(SkrPolicyError, match="256-bit"):
        build_release_policy(make_manifest(), authority=AUTHORITY)


def test_width_mismatch_fails_at_generation_not_in_production() -> None:
    with pytest.raises(SkrPolicyError, match="different chains"):
        policy(measurement_claim="x-ms-sevsnpvm-launchmeasurement")


def test_error_names_the_azure_pcr_path_so_the_fix_is_findable() -> None:
    with pytest.raises(SkrPolicyError, match="PCR 23"):
        policy(measurement_claim="x-ms-sevsnpvm-launchmeasurement")


def test_matching_width_claim_is_accepted() -> None:
    result = policy()

    assert result["version"] == SKR_POLICY_VERSION
    conditions = result["anyOf"][0]["allOf"]
    assert {"claim": "x-ms-sevsnpvm-hostdata", "equals": "5e2d" * 16} in conditions


def test_undocumented_claim_is_refused() -> None:
    with pytest.raises(SkrPolicyError, match="MAA_CLAIMS"):
        policy(measurement_claim="x-ms-invented-claim")


def test_revoked_measurements_are_excluded() -> None:
    rendered = json.dumps(policy())

    assert "70af" * 16 not in rendered


def test_retiring_measurements_are_included() -> None:
    """Dropping them would take a fleet offline mid-rollover, which is not the intent."""
    rendered = json.dumps(policy())

    assert "6f3e" * 16 in rendered


def test_one_branch_per_measurement_because_skr_has_no_disjunction_on_a_claim() -> None:
    result = policy()

    assert len(result["anyOf"]) == 2
    values = {
        condition["equals"]
        for branch in result["anyOf"]
        for condition in branch["allOf"]
        if condition["claim"] == "x-ms-sevsnpvm-hostdata"
    }
    assert values == {"5e2d" * 16, "6f3e" * 16}


def test_every_branch_pins_the_authority() -> None:
    for branch in policy()["anyOf"]:
        assert branch["authority"] == AUTHORITY


def test_missing_authority_is_refused() -> None:
    with pytest.raises(SkrPolicyError, match="pinned authority"):
        policy(authority="sharedeus.eus.attest.azure.net")


def test_hardware_attested_tier_requires_azure_compliance() -> None:
    conditions = policy()["anyOf"][0]["allOf"]

    assert {"claim": "x-ms-compliance-status", "equals": "azure-compliant-cvm"} in conditions


def test_debuggable_guests_are_excluded_by_default() -> None:
    conditions = policy()["anyOf"][0]["allOf"]

    assert {"claim": "x-ms-sevsnpvm-is-debuggable", "equals": "false"} in conditions


def test_debuggable_condition_can_be_dropped_deliberately() -> None:
    conditions = policy(require_not_debuggable=False)["anyOf"][0]["allOf"]

    assert all(c["claim"] != "x-ms-sevsnpvm-is-debuggable" for c in conditions)


def test_tdx_maps_to_tdxvm_and_omits_snp_only_claims() -> None:
    result = build_release_policy(
        make_manifest(required_hw_platform=["intel-tdx"]),
        authority=AUTHORITY,
        allow_unbound_workload=True,
    )

    conditions = result["anyOf"][0]["allOf"]
    assert {"claim": "x-ms-attestation-type", "equals": "tdxvm"} in conditions
    assert all("sevsnpvm" not in c["claim"] for c in conditions)


def test_gpu_only_requirement_has_no_attestation_type() -> None:
    with pytest.raises(SkrPolicyError, match="no attestation-type"):
        build_release_policy(
            make_manifest(required_hw_platform=["nvidia-cc-gpu"]),
            authority=AUTHORITY,
            allow_unbound_workload=True,
        )


def test_unbound_policy_is_labelled_as_binding_nothing() -> None:
    result = build_release_policy(
        make_manifest(), authority=AUTHORITY, allow_unbound_workload=True
    )

    assert "NOT enforced here" in result["x-wcm-note"]
    assert len(result["anyOf"]) == 1


def test_bound_policy_carries_no_note() -> None:
    assert "x-wcm-note" not in policy()


def test_platform_map_has_no_gpu_entry() -> None:
    assert "nvidia-cc-gpu" not in ATTESTATION_TYPE_BY_PLATFORM
    assert ATTESTATION_TYPE_BY_PLATFORM["amd-sev-snp"] == "sevsnpvm"


def test_evidence_requires_a_known_attestation_type() -> None:
    with pytest.raises(SkrPolicyError, match="does not map to a WCM platform"):
        evidence_from_maa_claims(
            good_claims(**{"x-ms-attestation-type": "somethingelse"}),
            challenge(),
            serving_image_measurement=SERVING,
        )


def test_evidence_requires_azure_compliance() -> None:
    with pytest.raises(SkrPolicyError, match="azure-compliant-cvm"):
        evidence_from_maa_claims(
            good_claims(**{"x-ms-compliance-status": "not-compliant"}),
            challenge(),
            serving_image_measurement=SERVING,
        )


def test_debuggable_guest_cannot_produce_hardware_attested_evidence() -> None:
    with pytest.raises(SkrPolicyError, match="debuggable"):
        evidence_from_maa_claims(
            good_claims(**{"x-ms-sevsnpvm-is-debuggable": "true"}),
            challenge(),
            serving_image_measurement=SERVING,
        )


def test_evidence_binds_the_challenge_nonce() -> None:
    evidence = evidence_from_maa_claims(
        good_claims(), challenge(), serving_image_measurement=SERVING
    )

    assert evidence.cpu.nonce_echo == "a" * 64
    assert evidence.cpu.platform == "amd-sev-snp"
    assert evidence.cpu.serving_image_measurement == SERVING


def test_evidence_carries_the_transport_key_when_channel_binding_is_used() -> None:
    evidence = evidence_from_maa_claims(
        good_claims(), challenge(), serving_image_measurement=SERVING, transport_public_key="ab" * 32
    )

    assert evidence.cpu.transport_public_key == "ab" * 32


def test_every_claim_the_module_uses_is_documented() -> None:
    rendered = json.dumps(policy())

    for claim in json.loads(rendered)["anyOf"][0]["allOf"]:
        assert claim["claim"] in MAA_CLAIMS


def test_cli_refuses_without_a_measurement_claim(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--authority", AUTHORITY]) == 1
    assert "256-bit" in capsys.readouterr().err


def test_cli_warns_loudly_when_the_workload_is_unbound(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--authority", AUTHORITY, "--allow-unbound-workload"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["version"] == SKR_POLICY_VERSION
    assert "Any compliant CVM" in captured.err


def test_cli_describes_claims(capsys) -> None:
    assert main(["ignored", "--authority", AUTHORITY, "--describe-claims"]) == 0
    assert "x-ms-compliance-status" in capsys.readouterr().out
