"""Tests for the WCM -> Confidential Space attribute condition.

The interesting property here is the opposite of the Azure case: an OCI image
digest and a WCM HashValue are the same shape, so the comparison is meaningful.
The tests pin that, and pin the refusals for when a manifest was built some other
way.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import Challenge, WeightCustodyManifest  # noqa: E402

from wcm_gcp_cs import (  # noqa: E402
    HWMODEL_BY_PLATFORM,
    IMAGE_DIGEST_CLAIM,
    SUPPORT_ATTRIBUTES,
    ConfidentialSpaceError,
    build_attribute_condition,
    build_provider_command,
    evidence_from_cs_claims,
    main,
)

WEIGHTS = "sha256:" + "4a1c" * 16
IMAGE = "sha256:" + "5e2d" * 16
RETIRING = "sha256:" + "6f3e" * 16
REVOKED = "sha256:" + "70af" * 16


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
                {"measurement": IMAGE, "status": "current"},
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
                "custodian_type": "customer-self-custody",
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


def cs_claims(**overrides: object) -> dict:
    claims = {
        "swname": "CONFIDENTIAL_SPACE",
        "hwmodel": "GCP_AMD_SEV_SNP",
        "dbgstat": "disabled-since-boot",
        "iss": "https://confidentialcomputing.googleapis.com/",
        "submods": {"container": {"image_digest": IMAGE}},
    }
    claims.update(overrides)
    return claims


def test_condition_compares_image_digests_like_with_like() -> None:
    """The point of this integration: the two values are the same shape."""
    condition = build_attribute_condition(make_manifest())

    assert f"assertion.{IMAGE_DIGEST_CLAIM} == d" in condition
    assert json.dumps(IMAGE) in condition


def test_non_digest_measurement_is_refused_with_the_reason() -> None:
    manifest = make_manifest(
        required_serving_image={
            "signer": "ed25519:builder-key",
            "release_rule": "prefer-current",
            "accepted_measurements": [
                {"measurement": "shake256:" + "ab" * 32, "status": "current"}
            ],
        }
    )

    with pytest.raises(ConfidentialSpaceError, match="OCI image digest"):
        build_attribute_condition(manifest)


def test_confidential_space_software_name_is_pinned() -> None:
    assert 'assertion.swname == "CONFIDENTIAL_SPACE"' in build_attribute_condition(make_manifest())


def test_hardware_model_comes_from_the_platform() -> None:
    condition = build_attribute_condition(make_manifest(required_hw_platform=["intel-tdx"]))

    assert "GCP_INTEL_TDX" in condition
    assert "GCP_AMD_SEV_SNP" not in condition


def test_gpu_only_requirement_has_no_hwmodel() -> None:
    with pytest.raises(ConfidentialSpaceError, match="no hwmodel"):
        build_attribute_condition(make_manifest(required_hw_platform=["nvidia-cc-gpu"]))


def test_stable_support_attribute_is_the_default() -> None:
    assert '"STABLE" in assertion.submods.confidential_space.support_attributes' in (
        build_attribute_condition(make_manifest())
    )


def test_support_attribute_must_be_a_known_value() -> None:
    with pytest.raises(ConfidentialSpaceError, match="STABLE"):
        build_attribute_condition(make_manifest(), support_attribute="EXPERIMENTAL")


def test_support_attributes_are_ordered_strongest_first() -> None:
    assert SUPPORT_ATTRIBUTES[0] == "STABLE"


def test_debug_must_have_been_disabled_since_boot() -> None:
    assert 'assertion.dbgstat == "disabled-since-boot"' in build_attribute_condition(make_manifest())


def test_debug_clause_can_be_dropped_deliberately() -> None:
    condition = build_attribute_condition(make_manifest(), require_debug_disabled=False)

    assert "dbgstat" not in condition


def test_revoked_measurements_are_excluded() -> None:
    assert "70af" * 16 not in build_attribute_condition(make_manifest())


def test_retiring_measurements_are_kept() -> None:
    assert "6f3e" * 16 in build_attribute_condition(make_manifest())


def test_all_revoked_is_refused() -> None:
    manifest = make_manifest(
        required_serving_image={
            "signer": "ed25519:builder-key",
            "release_rule": "prefer-current",
            "accepted_measurements": [{"measurement": IMAGE, "status": "revoked"}],
        }
    )

    with pytest.raises(ConfidentialSpaceError, match="every accepted measurement is revoked"):
        build_attribute_condition(manifest)


def test_unbound_condition_omits_the_measurement_clause() -> None:
    condition = build_attribute_condition(make_manifest(), allow_unbound_workload=True)

    assert IMAGE_DIGEST_CLAIM not in condition
    assert "CONFIDENTIAL_SPACE" in condition


def test_claim_path_must_be_a_dotted_identifier() -> None:
    for hostile in ('a" || true || "', "submods[0]", "", "a..b"):
        with pytest.raises(ConfidentialSpaceError, match="dotted identifier"):
            build_attribute_condition(make_manifest(), measurement_claim=hostile)


def test_project_number_must_be_numeric() -> None:
    with pytest.raises(ConfidentialSpaceError, match="numeric project number"):
        build_provider_command(
            make_manifest(),
            project_number="my-project-id",
            pool="wcm-pool",
            provider="confidential-space",
            condition="true",
        )


def test_resource_ids_are_validated() -> None:
    with pytest.raises(ConfidentialSpaceError, match="valid resource id"):
        build_provider_command(
            make_manifest(),
            project_number="123456789012",
            pool="P",
            provider="confidential-space",
            condition="true",
        )


def test_command_states_the_image_digest_assumption() -> None:
    command = build_provider_command(
        make_manifest(),
        project_number="123456789012",
        pool="wcm-pool",
        provider="confidential-space",
        condition=build_attribute_condition(make_manifest()),
    )

    assert "an OCI image digest" in command
    assert "never matches" in command


def test_command_warns_when_the_workload_is_unbound() -> None:
    command = build_provider_command(
        make_manifest(),
        project_number="123456789012",
        pool="wcm-pool",
        provider="confidential-space",
        condition=build_attribute_condition(make_manifest(), allow_unbound_workload=True),
    )

    assert "WARNING" in command


def test_condition_is_json_quoted_in_the_command() -> None:
    condition = build_attribute_condition(make_manifest())
    command = build_provider_command(
        make_manifest(),
        project_number="123456789012",
        pool="wcm-pool",
        provider="confidential-space",
        condition=condition,
    )

    assert json.dumps(condition) in command


def test_evidence_requires_confidential_space() -> None:
    with pytest.raises(ConfidentialSpaceError, match="CONFIDENTIAL_SPACE"):
        evidence_from_cs_claims(cs_claims(swname="GCE"), challenge())


def test_evidence_requires_a_known_hwmodel() -> None:
    with pytest.raises(ConfidentialSpaceError, match="does not map to a WCM platform"):
        evidence_from_cs_claims(cs_claims(hwmodel="GCP_SOMETHING_NEW"), challenge())


def test_evidence_requires_debug_disabled_since_boot() -> None:
    with pytest.raises(ConfidentialSpaceError, match="debuggable at any"):
        evidence_from_cs_claims(cs_claims(dbgstat="enabled"), challenge())


def test_evidence_defaults_the_measurement_to_the_token_image_digest() -> None:
    evidence = evidence_from_cs_claims(cs_claims(), challenge())

    assert evidence.cpu.serving_image_measurement == IMAGE
    assert evidence.cpu.platform == "amd-sev-snp"
    assert evidence.cpu.nonce_echo == "a" * 64


def test_evidence_measurement_can_be_supplied_when_the_manifest_binds_otherwise() -> None:
    other = "sha256:" + "1122" * 16

    evidence = evidence_from_cs_claims(
        cs_claims(), challenge(), serving_image_measurement=other
    )

    assert evidence.cpu.serving_image_measurement == other


def test_evidence_refuses_a_token_with_no_image_digest() -> None:
    with pytest.raises(ConfidentialSpaceError, match="absent or"):
        evidence_from_cs_claims(cs_claims(submods={}), challenge())


def test_hwmodel_map_has_no_gpu_entry() -> None:
    assert "nvidia-cc-gpu" not in HWMODEL_BY_PLATFORM


def test_cli_emits_a_condition(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--condition-only"]) == 0
    assert "CONFIDENTIAL_SPACE" in capsys.readouterr().out


def test_cli_emits_the_gcloud_command(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert (
        main(
            [
                str(path),
                "--project-number",
                "123456789012",
                "--pool",
                "wcm-pool",
                "--provider",
                "confidential-space",
            ]
        )
        == 0
    )
    assert "workload-identity-pools providers update-oidc" in capsys.readouterr().out


def test_cli_requires_the_resource_identifiers(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path)]) == 1
    assert "--project-number" in capsys.readouterr().err


def test_cli_prints_claims_for_confirming_hwmodel(tmp_path: pathlib.Path, capsys) -> None:
    token = tmp_path / "token.json"
    token.write_text(json.dumps(cs_claims()), encoding="utf-8")

    assert main(["ignored", "--print-claims", str(token)]) == 0
    assert "GCP_AMD_SEV_SNP" in capsys.readouterr().out
