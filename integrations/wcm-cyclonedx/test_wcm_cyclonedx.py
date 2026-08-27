"""Tests for the WCM -> CycloneDX ML-BOM exporter.

The recurring risk is a BOM that reads as enforcement. Tests here check that
policy fields with no CycloneDX home stay out, that the output is reproducible,
and that a digest is never filed under an algorithm it is not.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import WeightCustodyManifest, canonical_hash  # noqa: E402

from wcm_cyclonedx import (  # noqa: E402
    PROPERTY_NAMESPACE,
    SPEC_VERSION,
    UNMAPPED_FIELDS,
    CycloneDxError,
    build_bom,
    build_component,
    main,
)

WEIGHTS = "sha256:" + "4a1c" * 16
PARENT_WEIGHTS = "sha256:" + "9f0b" * 16
SERVING = "sha256:" + "5e2d" * 16


def make_manifest(**overrides: object) -> WeightCustodyManifest:
    document: dict = {
        "manifest_version": "0.1",
        "weights_hash": WEIGHTS,
        "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
        "release_terms": {
            "license": "customer-deployment-agreement-ref:CDA-2026-0091",
            "permitted_derivatives": "fine-tune-only, no re-export of base weights",
            "permitted_environments": ["attested-enclave"],
            "jurisdiction_restriction": "US, EU",
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "physical_hardening": "not-required",
            "trusted_time_source": "secure-tsc",
            "memory_fingerprint_challenge": "not-required",
            "required_hw_platform": ["amd-sev-snp"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:golden-01"},
            "tenancy": "shared",
            "required_serving_image": {
                "signer": "ed25519:builder-key",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": SERVING, "status": "current"}],
            },
            "key_release_mode": "attestation-gated",
            "replay_protection": "kbs-nonce-required",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": "example-custodian",
            "custodian_type": "opaque-hosted",
            "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
            "enclave_id": "did:example:enclave-04",
            "attestation_cadence": "24h",
        },
        "signatures": [],
    }
    document.update(overrides)
    return WeightCustodyManifest.model_validate(document)


def component(**kwargs: object) -> dict:
    base: dict = {"name": "example-8b-instruct", "version": "2026-08"}
    base.update(kwargs)
    manifest = base.pop("manifest", None) or make_manifest()
    return build_component(manifest, **base)  # type: ignore[arg-type]


def properties(value: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in value["properties"]}


def test_component_is_a_machine_learning_model() -> None:
    value = component()

    assert value["type"] == "machine-learning-model"
    assert value["bom-ref"] == "wcm:" + "4a1c" * 16


def test_digest_is_recorded_as_a_sha256_hash() -> None:
    value = component()

    assert value["hashes"] == [{"alg": "SHA-256", "content": "4a1c" * 16}]


def test_shake256_is_refused_rather_than_filed_under_sha256() -> None:
    """CycloneDX hash algorithms are enumerated and have no shake256 member."""
    manifest = make_manifest(weights_hash="shake256:" + "ab" * 32)

    with pytest.raises(CycloneDxError, match="compare the wrong bytes"):
        component(manifest=manifest)


def test_licence_reaches_the_field_a_review_actually_reads() -> None:
    value = component()

    assert value["licenses"][0]["license"]["name"].startswith("customer-deployment-agreement")


def test_jurisdiction_and_derivative_terms_are_carried() -> None:
    props = properties(component())

    assert props[f"{PROPERTY_NAMESPACE}:jurisdiction-restriction"] == "US, EU"
    assert "no re-export" in props[f"{PROPERTY_NAMESPACE}:permitted-derivatives"]


def test_serving_measurements_stay_out_of_the_bom() -> None:
    """A property holding them would read as enforceable; a BOM enforces nothing."""
    rendered = json.dumps(component())

    assert SERVING not in rendered
    assert "release_policy.required_serving_image" in UNMAPPED_FIELDS


def test_gpu_measurement_stays_out() -> None:
    assert "nvidia-rim:golden-01" not in json.dumps(component())


def test_kbs_image_stays_out_because_it_describes_another_service() -> None:
    assert "ab12" * 16 not in json.dumps(component())


def test_every_property_is_namespaced() -> None:
    for name in properties(component()):
        assert name.startswith(f"{PROPERTY_NAMESPACE}:")


def test_external_reference_carries_the_manifest_hash() -> None:
    manifest = make_manifest()
    expected = canonical_hash(manifest.model_dump(mode="json", exclude_none=True))

    reference = component(manifest=manifest)["externalReferences"][0]

    assert expected in reference["comment"]
    assert "the authority for these terms" in reference["comment"]


def test_manifest_uri_is_used_when_supplied() -> None:
    value = component(manifest_uri="https://example.com/wcm/manifest.json")

    assert value["externalReferences"][0]["url"] == "https://example.com/wcm/manifest.json"


def test_signatures_are_not_carried_and_that_is_documented() -> None:
    """The word appears in the external-reference prose; the signature data must not."""
    rendered = json.dumps(component())

    assert "signature_value" not in rendered
    assert '"signatures":' not in rendered
    assert "signatures" in UNMAPPED_FIELDS


def test_name_and_version_are_required() -> None:
    with pytest.raises(CycloneDxError, match="nobody can find in a review"):
        build_component(make_manifest(), name="", version="1.0.0")


def test_sovereign_profile_is_reported_when_enabled() -> None:
    manifest = make_manifest()
    manifest.release_policy.sovereign_profile.enabled = True

    props = properties(component(manifest=manifest))

    assert props[f"{PROPERTY_NAMESPACE}:sovereign-profile"] == "enabled"


def test_sovereign_profile_is_absent_when_disabled() -> None:
    assert f"{PROPERTY_NAMESPACE}:sovereign-profile" not in properties(component())


def test_rights_holder_split_is_carried_for_a_derivative() -> None:
    manifest = make_manifest(
        derived_from=PARENT_WEIGHTS,
        rights_holder={"base": "example-labs", "derivative": "example-customer"},
    )

    props = properties(component(manifest=manifest))

    assert props[f"{PROPERTY_NAMESPACE}:rights-holder-derivative"] == "example-customer"
    assert props[f"{PROPERTY_NAMESPACE}:derived-from"] == PARENT_WEIGHTS


def test_bom_has_the_cyclonedx_envelope() -> None:
    bom = build_bom([(make_manifest(), {"name": "m", "version": "1"})])

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == SPEC_VERSION
    assert len(bom["components"]) == 1


def test_lineage_becomes_a_dependency_when_the_parent_is_present() -> None:
    parent = make_manifest(weights_hash=PARENT_WEIGHTS)
    child = make_manifest(derived_from=PARENT_WEIGHTS)

    bom = build_bom(
        [(parent, {"name": "base", "version": "1"}), (child, {"name": "tuned", "version": "1"})]
    )

    assert bom["dependencies"] == [
        {"ref": "wcm:" + "4a1c" * 16, "dependsOn": ["wcm:" + "9f0b" * 16]}
    ]


def test_lineage_without_the_parent_listed_emits_no_dangling_dependency() -> None:
    child = make_manifest(derived_from=PARENT_WEIGHTS)

    bom = build_bom([(child, {"name": "tuned", "version": "1"})])

    assert "dependencies" not in bom
    assert properties(bom["components"][0])[f"{PROPERTY_NAMESPACE}:derived-from"] == PARENT_WEIGHTS


def test_output_is_reproducible_without_an_injected_clock() -> None:
    """A tool stamping its own clock makes every rebuild look like a change."""
    entries = [(make_manifest(), {"name": "m", "version": "1"})]

    one = json.dumps(build_bom(entries), sort_keys=True)
    two = json.dumps(build_bom(entries), sort_keys=True)

    assert one == two
    assert "timestamp" not in json.loads(one)["metadata"]


def test_timestamp_and_serial_are_carried_when_supplied() -> None:
    bom = build_bom(
        [(make_manifest(), {"name": "m", "version": "1"})],
        timestamp="2026-08-27T00:00:00Z",
        serial_number="urn:uuid:00000000-0000-4000-8000-000000000000",
    )

    assert bom["metadata"]["timestamp"] == "2026-08-27T00:00:00Z"
    assert bom["serialNumber"].startswith("urn:uuid:")


def test_cli_emits_a_bom(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--name", "example-8b-instruct"]) == 0

    bom = json.loads(capsys.readouterr().out)
    assert bom["components"][0]["name"] == "example-8b-instruct"


def test_cli_describes_the_unmapped_fields(capsys) -> None:
    assert main(["ignored", "--name", "x", "--describe-unmapped"]) == 0
    assert "required_serving_image" in capsys.readouterr().out


def test_cli_reports_a_refusal(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    manifest = make_manifest(weights_hash="shake256:" + "ab" * 32)
    path.write_text(manifest.model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--name", "x"]) == 1
    assert "shake256" in capsys.readouterr().err
