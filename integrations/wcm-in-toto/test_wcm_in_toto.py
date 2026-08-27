"""Tests for the WCM <-> in-toto Statement wrapper.

The theme: an in-toto envelope must not be able to launder custody. A statement
is trustworthy only when the embedded manifest verifies on its own joint
signatures *and* its weights_hash is the artifact the statement names.
"""

from __future__ import annotations

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

from wcm_in_toto import (  # noqa: E402
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    StatementError,
    build_statement,
    main,
    manifest_from_statement,
    verify_statement,
)

WEIGHTS = "sha256:" + "4a1c" * 16
OTHER_WEIGHTS = "sha256:" + "9f0b" * 16
SERVING = "sha256:" + "5e2d" * 16


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
            "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs-key"},
            "enclave_id": "did:example:enclave-04",
            "attestation_cadence": "24h",
        },
        "signatures": [],
    }
    document.update(overrides)
    return document


def signed_manifest(**overrides: object) -> tuple[WeightCustodyManifest, VerificationContext]:
    """A jointly signed manifest plus a context trusting both signers."""
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


def test_statement_has_the_in_toto_shape() -> None:
    manifest, _ = signed_manifest()

    statement = build_statement(manifest, name="example-8b")

    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    assert statement["subject"] == [{"name": "example-8b", "digest": {"sha256": "4a1c" * 16}}]


def test_subject_digest_is_the_bare_hex_not_the_prefixed_form() -> None:
    """in-toto keys digests by algorithm, so the 'sha256:' prefix must come off."""
    manifest, _ = signed_manifest()

    digest = build_statement(manifest, name="m")["subject"][0]["digest"]["sha256"]

    assert ":" not in digest
    assert len(digest) == 64


def test_predicate_embeds_the_signed_manifest_whole() -> None:
    """The joint signatures must survive the round trip, not be summarized away."""
    manifest, _ = signed_manifest()

    statement = build_statement(manifest, name="m")
    recovered = manifest_from_statement(statement)

    assert len(recovered.signatures) == 2
    assert {s.role.value for s in recovered.signatures} == {"builder", "custodian"}
    assert recovered.weights_hash == manifest.weights_hash


def test_round_trip_verifies_against_the_original_trust_context() -> None:
    manifest, context = signed_manifest()

    outcome = verify_statement(build_statement(manifest, name="m"), context)

    assert outcome.trusted
    assert outcome.subject_matches
    assert outcome.manifest_verified


def test_manifest_stapled_to_a_different_artifact_is_refused() -> None:
    """The attack this format invites: a real manifest, the wrong subject."""
    manifest, context = signed_manifest()
    statement = build_statement(manifest, name="m")
    statement["subject"] = [{"name": "something-else", "digest": {"sha256": "9f0b" * 16}}]

    outcome = verify_statement(statement, context)

    assert not outcome.trusted
    assert not outcome.subject_matches
    assert outcome.manifest_verified, "the manifest itself is still genuine"
    assert "subject digest" in (outcome.reason or "")


def test_edited_manifest_block_fails_before_signature_checking() -> None:
    manifest, context = signed_manifest()
    statement = build_statement(manifest, name="m")
    statement["predicate"]["manifest"]["release_terms"]["permitted_environments"] = ["anywhere"]

    outcome = verify_statement(statement, context)

    assert not outcome.trusted
    assert "manifest_hash" in (outcome.reason or "")


def test_untrusted_signer_is_not_trusted_however_valid_the_envelope() -> None:
    manifest, _ = signed_manifest()

    outcome = verify_statement(build_statement(manifest, name="m"), VerificationContext())

    assert not outcome.trusted
    assert outcome.subject_matches
    assert not outcome.manifest_verified


def test_summary_is_never_the_authority() -> None:
    """A tampered summary must not change the verdict; only `manifest` is read."""
    manifest, context = signed_manifest()
    statement = build_statement(manifest, name="m")
    statement["predicate"]["summary"]["builder"] = "somebody-else"

    assert verify_statement(statement, context).trusted


def test_wrong_predicate_type_is_refused_rather_than_parsed() -> None:
    manifest, _ = signed_manifest()
    statement = build_statement(manifest, name="m")
    statement["predicateType"] = "https://slsa.dev/provenance/v1"

    with pytest.raises(StatementError, match="predicateType"):
        manifest_from_statement(statement)


def test_shake256_manifest_is_refused_rather_than_filed_under_sha256() -> None:
    """in-toto has no registered shake256 digest name; a wrong key is worse than none."""
    manifest, _ = signed_manifest(weights_hash="shake256:" + "ab" * 32)

    with pytest.raises(StatementError, match="in-toto digest-set name"):
        build_statement(manifest, name="m")


def test_name_is_required_because_a_manifest_carries_none() -> None:
    manifest, _ = signed_manifest()

    with pytest.raises(StatementError, match="name is required"):
        build_statement(manifest, name="")


def test_annotations_stay_outside_the_manifest() -> None:
    manifest, context = signed_manifest()

    statement = build_statement(manifest, name="m", annotations={"ticket": "ENG-1234"})

    assert statement["predicate"]["annotations"] == {"ticket": "ENG-1234"}
    assert "annotations" not in statement["predicate"]["manifest"]
    assert verify_statement(statement, context).trusted


def test_derivative_lineage_survives_the_wrapper() -> None:
    manifest, _ = signed_manifest(
        derived_from=OTHER_WEIGHTS,
        rights_holder={"base": "example-labs", "derivative": "example-customer"},
    )

    statement = build_statement(manifest, name="example-8b-finetune")

    assert statement["predicate"]["summary"]["derived_from"] == OTHER_WEIGHTS
    assert manifest_from_statement(statement).rights_holder.derivative == "example-customer"


def test_cli_wrap_then_verify(tmp_path: pathlib.Path, capsys) -> None:
    document = manifest_document()
    builder, custodian = generate_ed25519(), generate_ed25519()
    unsigned = WeightCustodyManifest.model_validate(document).unsigned_dict()
    document["signatures"] = [
        Ed25519Signer(builder).sign(unsigned, role="builder", signer="example-labs"),
        Ed25519Signer(custodian).sign(unsigned, role="custodian", signer="example-custodian"),
    ]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(document), encoding="utf-8")

    assert main(["wrap", str(manifest_path), "--name", "example-8b"]) == 0
    statement_path = tmp_path / "statement.json"
    statement_path.write_text(capsys.readouterr().out, encoding="utf-8")

    keys = []
    for index, keypair in enumerate((builder, custodian)):
        path = tmp_path / f"key{index}.pub"
        path.write_text(keypair.public_bytes.hex(), encoding="utf-8")
        keys += ["--public-key", str(path)]

    assert main(["verify", str(statement_path), *keys]) == 0
    assert json.loads(capsys.readouterr().out)["trusted"] is True


def test_cli_verify_exits_nonzero_without_the_keys(tmp_path: pathlib.Path, capsys) -> None:
    manifest, _ = signed_manifest()
    statement_path = tmp_path / "statement.json"
    statement_path.write_text(json.dumps(build_statement(manifest, name="m")), encoding="utf-8")

    assert main(["verify", str(statement_path)]) == 1
    assert json.loads(capsys.readouterr().out)["manifest_verified"] is False
