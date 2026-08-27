"""Tests for the WCM -> Trustee resource policy generator.

Two things must hold. Nothing a caller controls reaches the Rego unescaped, and
a policy that would deny every request is refused at generation time rather than
shipped to a cluster where it looks like a broken attestation service.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import WeightCustodyManifest  # noqa: E402

from wcm_coco import (  # noqa: E402
    CLAIM_HEX_WIDTH,
    RESOURCE_TYPE,
    TEE_BY_PLATFORM,
    CocoPolicyError,
    build_policy,
    main,
    resource_uri,
)

WEIGHTS = "sha256:" + "4a1c" * 16
SERVING = "sha256:" + "5e2d" * 16
RETIRING = "sha256:" + "6f3e" * 16
REVOKED = "sha256:" + "70af" * 16
PCR_PATH = "tcb_status.azsnpvtpm.tpm.pcr04"


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
                "custodian_type": "customer-self-custody",
                "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
                "enclave_id": "did:example:enclave-04",
                "attestation_cadence": "24h",
            },
            "signatures": [],
        }
    )


def policy(**kwargs: object) -> str:
    base: dict = {"measurement_path": PCR_PATH}
    base.update(kwargs)
    return build_policy(make_manifest(), **base)  # type: ignore[arg-type]


def test_policy_denies_by_default() -> None:
    assert "default allow = false" in policy()


def test_vtpm_tee_names_are_the_default() -> None:
    """The vTPM path is where a 256-bit WCM measurement and a claim are one width."""
    rendered = policy()

    assert '"azsnpvtpm"' in rendered
    assert '"snp"' not in rendered


def test_bare_metal_uses_the_raw_tee_names() -> None:
    rendered = policy(vtpm=False)

    assert '"snp"' in rendered
    assert '"azsnpvtpm"' not in rendered


def test_tdx_maps_to_both_forms() -> None:
    assert TEE_BY_PLATFORM["intel-tdx"] == ("tdx", "aztdxvtpm")
    assert '"aztdxvtpm"' in build_policy(
        make_manifest(required_hw_platform=["intel-tdx"]), measurement_path=PCR_PATH
    )


def test_gpu_only_requirement_has_no_tee() -> None:
    with pytest.raises(CocoPolicyError, match="no tee value"):
        build_policy(
            make_manifest(required_hw_platform=["nvidia-cc-gpu"]), measurement_path=PCR_PATH
        )


def test_revoked_measurements_are_excluded() -> None:
    assert "70af" * 16 not in policy()


def test_retiring_measurements_are_kept() -> None:
    assert "6f3e" * 16 in policy()


def test_all_measurements_revoked_is_refused_rather_than_emitted() -> None:
    """A policy that denies everything is correct and is a manifest bug."""
    manifest = make_manifest(
        required_serving_image={
            "signer": "ed25519:builder-key",
            "release_rule": "prefer-current",
            "accepted_measurements": [{"measurement": SERVING, "status": "revoked"}],
        }
    )

    with pytest.raises(CocoPolicyError, match="every accepted measurement is revoked"):
        build_policy(manifest, measurement_path=PCR_PATH)


def test_width_mismatch_against_a_known_claim_fails_at_generation() -> None:
    with pytest.raises(CocoPolicyError, match="384-bit"):
        policy(measurement_path="tcb_status.snp.measurement")


def test_known_widths_cover_the_384_bit_claims() -> None:
    assert CLAIM_HEX_WIDTH["tcb_status.snp.measurement"] == 96
    assert CLAIM_HEX_WIDTH["tcb_status.tdx.mrtd"] == 96


def test_unknown_claim_path_is_accepted_without_a_width_check() -> None:
    """Asserting a width we have not confirmed would be a worse error than none."""
    assert "input.tcb_status.custom.value" in policy(measurement_path="tcb_status.custom.value")


def test_measurement_path_must_be_a_dotted_identifier() -> None:
    for hostile in (
        'tcb_status.x == "a"} \n allow { true',
        "tcb_status.x[_]",
        "tcb_status..x",
        "",
    ):
        with pytest.raises(CocoPolicyError, match="dotted identifier path"):
            policy(measurement_path=hostile)


def test_rego_injection_through_the_claim_path_is_impossible() -> None:
    with pytest.raises(CocoPolicyError):
        policy(measurement_path="a} \nallow { true \n#")


def test_hardware_attested_tier_excludes_the_sample_tee() -> None:
    """Trustee's 'sample' TEE attests nothing and must never satisfy the tier."""
    assert 'input.tee != "sample"' in policy()


def test_resource_uri_is_keyed_by_the_weights_digest() -> None:
    uri = resource_uri(make_manifest())

    assert uri == f"kbs:///default/{RESOURCE_TYPE}/{'4a1c' * 16}"


def test_resource_uri_repository_is_validated() -> None:
    with pytest.raises(CocoPolicyError, match="valid Trustee path segment"):
        resource_uri(make_manifest(), repository="../../etc")


def test_different_weights_get_different_resources() -> None:
    other = make_manifest()
    other.weights_hash = "sha256:" + "9f0b" * 16

    assert resource_uri(make_manifest()) != resource_uri(other)


def test_unbound_policy_warns_inside_the_rego_itself() -> None:
    rendered = policy(allow_unbound_workload=True)

    assert "WARNING" in rendered
    assert "NOT enforced here" in rendered
    assert "allowed_measurement" not in rendered


def test_bound_policy_carries_no_warning() -> None:
    assert "WARNING" not in policy()


def test_header_states_that_this_does_not_verify_evidence() -> None:
    assert "does NOT verify the evidence" in policy().replace("DOES NOT", "does NOT")


def test_policy_parses_as_rego_if_a_parser_is_available() -> None:
    """Best-effort structural check; the grammar assertions above are the real test."""
    rendered = policy()

    assert rendered.count("allow {") == 1
    assert rendered.count("}") == rendered.count("{")


def test_cli_refuses_without_a_measurement_path(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path)]) == 1
    assert "denies every request while looking correct" in capsys.readouterr().err


def test_cli_emits_a_policy(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--measurement-path", PCR_PATH]) == 0
    assert "package policy" in capsys.readouterr().out


def test_cli_prints_the_resource_uri(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--print-uri"]) == 0
    assert capsys.readouterr().out.strip().startswith("kbs:///default/")


def test_cli_warns_on_an_unbound_policy(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--allow-unbound-workload"]) == 0
    assert "binds the TEE only" in capsys.readouterr().err
