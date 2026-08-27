"""Tests for the WCM OCI referrer artifact.

The central case is the digest-domain gap: an OCI subject digest and a WCM
weights_hash cover different bytes, and a referrer that looks verified while
nothing ties the custody manifest to actual weights is the failure this module
exists to make impossible to miss.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import (  # noqa: E402
    Ed25519Signer,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
)

from wcm_oci import (  # noqa: E402
    ARTIFACT_TYPE,
    EMPTY_DESCRIPTOR,
    MANIFEST_MEDIA_TYPE,
    OCI_MANIFEST_MEDIA_TYPE,
    WEIGHTS_HASH_ANNOTATION,
    OciError,
    WeightsBinding,
    build_referrer,
    descriptor_for,
    main,
    verify_referrer,
)

WEIGHTS = "sha256:" + "4a1c" * 16
SERVING = "sha256:" + "5e2d" * 16
SUBJECT = "sha256:" + "7b3f" * 16
OTHER_SUBJECT = "sha256:" + "1122" * 16


def manifest_document(**overrides: object) -> dict:
    document: dict = {
        "manifest_version": "0.1",
        "weights_hash": WEIGHTS,
        "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
        "release_terms": {
            "license": "customer-deployment-agreement-ref:CDA-2026-0091",
            "permitted_derivatives": "fine-tune-only",
            "permitted_environments": ["attested-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "physical_hardening": "not-required",
            "trusted_time_source": "secure-tsc",
            "memory_fingerprint_challenge": "not-required",
            "required_hw_platform": ["amd-sev-snp"],
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
    return document


def signed(**overrides: object) -> tuple[WeightCustodyManifest, VerificationContext]:
    document = manifest_document(**overrides)
    builder, custodian = generate_ed25519(), generate_ed25519()
    unsigned = WeightCustodyManifest.model_validate(document).unsigned_dict()
    document["signatures"] = [
        Ed25519Signer(builder).sign(unsigned, role="builder", signer="example-labs"),
        Ed25519Signer(custodian).sign(unsigned, role="custodian", signer="example-custodian"),
    ]
    context = VerificationContext()
    context.add_key(builder.public_bytes)
    context.add_key(custodian.public_bytes)
    return WeightCustodyManifest.model_validate(document), context


def referrer_for(**overrides: object):
    manifest, context = signed(**overrides)
    referrer, blob = build_referrer(manifest, subject_digest=SUBJECT, subject_size=1234)
    return manifest, context, referrer, blob


def test_referrer_has_the_oci_v1_1_shape() -> None:
    _, _, referrer, blob = referrer_for()

    assert referrer["schemaVersion"] == 2
    assert referrer["mediaType"] == OCI_MANIFEST_MEDIA_TYPE
    assert referrer["artifactType"] == ARTIFACT_TYPE
    assert referrer["config"] == EMPTY_DESCRIPTOR
    assert referrer["subject"] == {
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "digest": SUBJECT,
        "size": 1234,
    }
    assert referrer["layers"][0]["mediaType"] == MANIFEST_MEDIA_TYPE


def test_empty_config_descriptor_is_the_spec_blob_not_an_omitted_field() -> None:
    """image-spec v1.1 says a config-less artifact uses this exact descriptor."""
    assert EMPTY_DESCRIPTOR["digest"] == (
        "sha256:" + hashlib.sha256(b"{}").hexdigest()
    )
    assert EMPTY_DESCRIPTOR["size"] == 2


def test_layer_descriptor_is_computed_over_the_bytes_that_get_pushed() -> None:
    _, _, referrer, blob = referrer_for()

    assert referrer["layers"][0] == descriptor_for(blob, MANIFEST_MEDIA_TYPE)


def test_build_is_reproducible() -> None:
    """Two builds of the same manifest must be byte-identical; no injected clock."""
    manifest, _ = signed()

    one, blob_one = build_referrer(manifest, subject_digest=SUBJECT, subject_size=1234)
    two, blob_two = build_referrer(manifest, subject_digest=SUBJECT, subject_size=1234)

    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
    assert blob_one == blob_two


def test_created_is_carried_only_when_supplied() -> None:
    manifest, _ = signed()

    without, _ = build_referrer(manifest, subject_digest=SUBJECT, subject_size=1)
    with_time, _ = build_referrer(
        manifest, subject_digest=SUBJECT, subject_size=1, created="2026-08-27T00:00:00Z"
    )

    assert "org.opencontainers.image.created" not in without["annotations"]
    assert with_time["annotations"]["org.opencontainers.image.created"] == "2026-08-27T00:00:00Z"


def test_weights_hash_is_not_accepted_as_a_subject_digest() -> None:
    """The two cover different bytes; confusing them is the trap this format sets."""
    manifest, _ = signed()

    with pytest.raises(OciError, match="not the manifest's weights_hash"):
        build_referrer(manifest, subject_digest="notadigest", subject_size=1)


def test_layer_digest_binding_is_the_strong_case() -> None:
    manifest, context, referrer, blob = referrer_for()
    subject_layers = [{"digest": WEIGHTS, "mediaType": "application/octet-stream"}]

    outcome = verify_referrer(
        referrer, blob, context, expected_subject_digest=SUBJECT, subject_layers=subject_layers
    )

    assert outcome.weights_binding == WeightsBinding.LAYER_DIGEST
    assert outcome.trusted


def test_no_matching_layer_degrades_to_annotation_only_and_is_not_trusted() -> None:
    """A compressed or multi-layer artifact is the normal case, and not proof."""
    manifest, context, referrer, blob = referrer_for()
    subject_layers = [{"digest": "sha256:" + "00" * 32, "mediaType": "application/gzip"}]

    outcome = verify_referrer(
        referrer, blob, context, expected_subject_digest=SUBJECT, subject_layers=subject_layers
    )

    assert outcome.weights_binding == WeightsBinding.ANNOTATION_ONLY
    assert not outcome.trusted
    assert outcome.manifest_verified
    assert any("single uncompressed layer" in note for note in outcome.notes)


def test_absent_layers_are_annotation_only_and_say_why() -> None:
    manifest, context, referrer, blob = referrer_for()

    outcome = verify_referrer(referrer, blob, context, expected_subject_digest=SUBJECT)

    assert outcome.weights_binding == WeightsBinding.ANNOTATION_ONLY
    assert any("were not supplied" in note for note in outcome.notes)


def test_missing_annotation_and_no_layer_match_is_unbound() -> None:
    manifest, context, referrer, blob = referrer_for()
    del referrer["annotations"][WEIGHTS_HASH_ANNOTATION]

    outcome = verify_referrer(
        referrer,
        blob,
        context,
        expected_subject_digest=SUBJECT,
        subject_layers=[{"digest": "sha256:" + "00" * 32}],
    )

    assert outcome.weights_binding == WeightsBinding.UNBOUND
    assert not outcome.trusted


def test_binding_values_are_the_documented_set() -> None:
    manifest, context, referrer, blob = referrer_for()

    outcome = verify_referrer(referrer, blob, context, expected_subject_digest=SUBJECT)

    assert outcome.weights_binding in WeightsBinding.ALL


def test_annotation_disagreeing_with_the_document_is_noted_and_the_document_wins() -> None:
    manifest, context, referrer, blob = referrer_for()
    referrer["annotations"][WEIGHTS_HASH_ANNOTATION] = "sha256:" + "ff" * 32

    outcome = verify_referrer(
        referrer,
        blob,
        context,
        expected_subject_digest=SUBJECT,
        subject_layers=[{"digest": WEIGHTS}],
    )

    assert outcome.weights_binding == WeightsBinding.LAYER_DIGEST
    assert any("the manifest wins" in note for note in outcome.notes)


def test_wrong_subject_is_reported() -> None:
    manifest, context, referrer, blob = referrer_for()

    outcome = verify_referrer(
        referrer, blob, context, expected_subject_digest=OTHER_SUBJECT, subject_layers=[{"digest": WEIGHTS}]
    )

    assert not outcome.subject_matches
    assert not outcome.trusted
    assert OTHER_SUBJECT in (outcome.reason or "")


def test_omitting_the_expected_subject_is_a_failure_not_a_skip() -> None:
    manifest, context, referrer, blob = referrer_for()

    outcome = verify_referrer(referrer, blob, context, subject_layers=[{"digest": WEIGHTS}])

    assert not outcome.subject_matches
    assert "from somewhere" in (outcome.reason or "")


def test_blob_that_did_not_come_from_this_push_is_refused() -> None:
    manifest, context, referrer, blob = referrer_for()

    with pytest.raises(OciError, match="same push"):
        verify_referrer(referrer, blob + b" ", context, expected_subject_digest=SUBJECT)


def test_size_mismatch_is_refused_even_when_the_digest_is_patched() -> None:
    manifest, context, referrer, blob = referrer_for()
    referrer["layers"][0]["size"] = len(blob) + 1

    with pytest.raises(OciError, match="size does not match"):
        verify_referrer(referrer, blob, context, expected_subject_digest=SUBJECT)


def test_another_artifact_type_is_refused_rather_than_parsed() -> None:
    manifest, context, referrer, blob = referrer_for()
    referrer["artifactType"] = "application/vnd.dev.cosign.simplesigning.v1+json"

    with pytest.raises(OciError, match="artifactType"):
        verify_referrer(referrer, blob, context, expected_subject_digest=SUBJECT)


def test_multiple_layers_are_refused() -> None:
    manifest, context, referrer, blob = referrer_for()
    referrer["layers"].append(dict(referrer["layers"][0]))

    with pytest.raises(OciError, match="exactly one layer"):
        verify_referrer(referrer, blob, context, expected_subject_digest=SUBJECT)


def test_untrusted_signer_fails_even_with_a_layer_digest_binding() -> None:
    manifest, _, referrer, blob = referrer_for()

    outcome = verify_referrer(
        referrer,
        blob,
        VerificationContext(),
        expected_subject_digest=SUBJECT,
        subject_layers=[{"digest": WEIGHTS}],
    )

    assert outcome.weights_binding == WeightsBinding.LAYER_DIGEST
    assert not outcome.manifest_verified
    assert not outcome.trusted


def test_cli_build_then_verify(tmp_path: pathlib.Path, capsys) -> None:
    document = manifest_document()
    builder, custodian = generate_ed25519(), generate_ed25519()
    unsigned = WeightCustodyManifest.model_validate(document).unsigned_dict()
    document["signatures"] = [
        Ed25519Signer(builder).sign(unsigned, role="builder", signer="example-labs"),
        Ed25519Signer(custodian).sign(unsigned, role="custodian", signer="example-custodian"),
    ]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    out_dir = tmp_path / "referrer"

    assert (
        main(
            [
                "build",
                str(manifest_path),
                "--subject-digest",
                SUBJECT,
                "--subject-size",
                "1234",
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    capsys.readouterr()

    subject_manifest = tmp_path / "subject.json"
    subject_manifest.write_text(json.dumps({"layers": [{"digest": WEIGHTS}]}), encoding="utf-8")
    keys = []
    for index, keypair in enumerate((builder, custodian)):
        path = tmp_path / f"key{index}.pub"
        path.write_text(keypair.public_bytes.hex(), encoding="utf-8")
        keys += ["--public-key", str(path)]

    assert (
        main(
            [
                "verify",
                str(out_dir / "referrer.json"),
                "--blob",
                str(out_dir / "wcm.manifest.json"),
                "--expect-subject",
                SUBJECT,
                "--subject-manifest",
                str(subject_manifest),
                *keys,
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["trusted"] is True
    assert report["weights_binding"] == WeightsBinding.LAYER_DIGEST


def test_cli_verify_exits_nonzero_on_annotation_only(tmp_path: pathlib.Path, capsys) -> None:
    manifest, context, referrer, blob = referrer_for()
    referrer_path = tmp_path / "referrer.json"
    blob_path = tmp_path / "blob.json"
    referrer_path.write_text(json.dumps(referrer), encoding="utf-8")
    blob_path.write_bytes(blob)

    assert main(["verify", str(referrer_path), "--blob", str(blob_path), "--expect-subject", SUBJECT]) == 1
    assert json.loads(capsys.readouterr().out)["weights_binding"] == WeightsBinding.ANNOTATION_ONLY
