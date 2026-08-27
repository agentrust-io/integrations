"""Tests for the Hugging Face download gate.

No network. Every case builds a snapshot directory on disk, because what the gate
actually does is hash bytes and compare them to a signed number, and that is
testable without the Hub.
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

from wcm_hf_guard import (  # noqa: E402
    ARTIFACT_DIGEST_RECIPE,
    SIDECAR_NAME,
    GuardError,
    artifact_digest,
    artifact_files,
    guarded_snapshot_download,
    load_sidecar_manifest,
    main,
    verify_snapshot,
)

SERVING = "sha256:" + "5e2d" * 16
COMMIT = "a" * 40


def manifest_document(weights_hash: str, **overrides: object) -> dict:
    document: dict = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
        "release_terms": {
            "license": "apache-2.0",
            "permitted_derivatives": "fine-tune-only",
            "permitted_environments": ["any"],
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
        "base_confidentiality": "open",
        "signatures": [],
    }
    document.update(overrides)
    return document


def sign(document: dict) -> tuple[dict, VerificationContext]:
    builder, custodian = generate_ed25519(), generate_ed25519()
    unsigned = WeightCustodyManifest.model_validate(document).unsigned_dict()
    document["signatures"] = [
        Ed25519Signer(builder).sign(unsigned, role="builder", signer="example-labs"),
        Ed25519Signer(custodian).sign(unsigned, role="custodian", signer="example-custodian"),
    ]
    context = VerificationContext()
    context.add_key(builder.public_bytes)
    context.add_key(custodian.public_bytes)
    return document, context


def make_snapshot(tmp_path: pathlib.Path, files: dict[str, bytes] | None = None) -> pathlib.Path:
    directory = tmp_path / "snapshot"
    directory.mkdir(parents=True)
    for name, payload in (files or {"model.safetensors": b"weights", "config.json": b"{}"}).items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return directory


def publish(tmp_path: pathlib.Path, **overrides: object) -> tuple[pathlib.Path, VerificationContext]:
    """A snapshot with a correct, jointly-signed sidecar manifest."""
    directory = make_snapshot(tmp_path)
    include = [item.relative_to(directory).as_posix() for item in artifact_files(directory)]
    document, context = sign(manifest_document(artifact_digest(directory, include=include), **overrides))
    (directory / SIDECAR_NAME).write_text(json.dumps(document), encoding="utf-8")
    return directory, context


def test_correct_snapshot_is_accepted(tmp_path: pathlib.Path) -> None:
    directory, context = publish(tmp_path)

    result = verify_snapshot(directory, context, revision=COMMIT)

    assert result.ok
    assert result.signatures_verified
    assert result.computed_digest == result.expected_digest


def test_sidecar_is_excluded_from_its_own_digest(tmp_path: pathlib.Path) -> None:
    """A manifest cannot bind a hash of a directory containing that manifest."""
    directory, context = publish(tmp_path)

    assert verify_snapshot(directory, context).ok
    assert SIDECAR_NAME in {item.name for item in artifact_files(directory)}


def test_tampered_weights_are_refused(tmp_path: pathlib.Path) -> None:
    directory, context = publish(tmp_path)
    (directory / "model.safetensors").write_bytes(b"weightt")

    result = verify_snapshot(directory, context)

    assert not result.ok
    assert result.signatures_verified, "the manifest is still genuine; the bytes are not"
    assert ARTIFACT_DIGEST_RECIPE in (result.reason or "")


def test_added_file_is_refused(tmp_path: pathlib.Path) -> None:
    """Additions change the model as surely as edits do."""
    directory, context = publish(tmp_path)
    (directory / "adapter_model.safetensors").write_bytes(b"surprise")

    assert not verify_snapshot(directory, context).ok


def test_removed_file_is_refused(tmp_path: pathlib.Path) -> None:
    directory, context = publish(tmp_path)
    (directory / "config.json").unlink()

    assert not verify_snapshot(directory, context).ok


def test_untrusted_signer_fails_before_any_hashing(tmp_path: pathlib.Path) -> None:
    directory, _ = publish(tmp_path)

    result = verify_snapshot(directory, VerificationContext())

    assert not result.ok
    assert not result.signatures_verified
    assert result.computed_digest is None, "no point hashing bytes under terms you do not trust"


def test_missing_sidecar_is_unmanifested_not_verified(tmp_path: pathlib.Path) -> None:
    directory = make_snapshot(tmp_path)

    with pytest.raises(GuardError, match="publishes no custody manifest"):
        load_sidecar_manifest(directory)


def test_confidential_declaration_on_a_public_hub_repo_is_noted(tmp_path: pathlib.Path) -> None:
    """The Hub cannot provide confidentiality; the gate says so rather than passing silently."""
    directory, context = publish(tmp_path, base_confidentiality="confidential")

    result = verify_snapshot(directory, context, revision=COMMIT)

    assert result.ok
    assert any("public distribution channel" in note for note in result.notes)


def test_mutable_revision_is_noted_in_the_result(tmp_path: pathlib.Path) -> None:
    directory, context = publish(tmp_path)

    result = verify_snapshot(directory, context, revision="main")

    assert result.ok
    assert any("immutable commit sha" in note for note in result.notes)


def test_immutable_revision_produces_no_revision_note(tmp_path: pathlib.Path) -> None:
    directory, context = publish(tmp_path)

    result = verify_snapshot(directory, context, revision=COMMIT)

    assert not any("immutable commit sha" in note for note in result.notes)


def test_download_refuses_a_branch_by_default(tmp_path: pathlib.Path) -> None:
    with pytest.raises(GuardError, match="40-character commit sha"):
        guarded_snapshot_download("org/model", VerificationContext(), revision="main")


def test_explicit_inventory_selects_exactly_those_files(tmp_path: pathlib.Path) -> None:
    """A builder who hashed only the shards must be able to say so."""
    directory = make_snapshot(
        tmp_path, {"model.safetensors": b"weights", "README.md": b"docs", "config.json": b"{}"}
    )

    shards_only = artifact_digest(directory, include=["model.safetensors"])
    everything = artifact_digest(directory)

    assert shards_only != everything
    assert shards_only == artifact_digest(directory, include=["model.safetensors"])


def test_include_order_does_not_change_the_digest(tmp_path: pathlib.Path) -> None:
    directory = make_snapshot(tmp_path)

    forward = artifact_digest(directory, include=["config.json", "model.safetensors"])
    backward = artifact_digest(directory, include=["model.safetensors", "config.json"])

    assert forward == backward


def test_named_file_absent_from_the_snapshot_raises(tmp_path: pathlib.Path) -> None:
    """Hashing fewer files would blame the weights for a missing-file problem."""
    directory = make_snapshot(tmp_path)

    with pytest.raises(GuardError, match="absent from the snapshot"):
        artifact_digest(directory, include=["model.safetensors", "not-there.bin"])


def test_path_is_bound_so_renaming_changes_the_digest(tmp_path: pathlib.Path) -> None:
    """Length-prefixed paths are what stop two layouts flattening to one stream."""
    one = make_snapshot(tmp_path / "a", {"a": b"xy", "b": b"z"})
    two = make_snapshot(tmp_path / "b", {"a": b"x", "b": b"yz"})

    assert artifact_digest(one) != artifact_digest(two)


def test_cache_metadata_is_not_part_of_the_artifact(tmp_path: pathlib.Path) -> None:
    directory, context = publish(tmp_path)
    (directory / ".cache").mkdir()
    (directory / ".cache" / "state").write_bytes(b"hub bookkeeping")

    assert verify_snapshot(directory, context).ok


def test_nested_directories_are_included(tmp_path: pathlib.Path) -> None:
    directory = make_snapshot(tmp_path, {"a.bin": b"1", "nested/b.bin": b"2"})

    assert len(artifact_files(directory)) == 2


def test_empty_directory_raises_rather_than_hashing_nothing(tmp_path: pathlib.Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(GuardError, match="contains no files"):
        artifact_digest(empty)


def test_cli_reports_and_exits_on_a_local_snapshot(tmp_path: pathlib.Path, capsys) -> None:
    directory = make_snapshot(tmp_path)
    include = [item.relative_to(directory).as_posix() for item in artifact_files(directory)]
    builder, custodian = generate_ed25519(), generate_ed25519()
    document = manifest_document(artifact_digest(directory, include=include))
    unsigned = WeightCustodyManifest.model_validate(document).unsigned_dict()
    document["signatures"] = [
        Ed25519Signer(builder).sign(unsigned, role="builder", signer="example-labs"),
        Ed25519Signer(custodian).sign(unsigned, role="custodian", signer="example-custodian"),
    ]
    (directory / SIDECAR_NAME).write_text(json.dumps(document), encoding="utf-8")

    keys = []
    for index, keypair in enumerate((builder, custodian)):
        path = tmp_path / f"key{index}.pub"
        path.write_text(keypair.public_bytes.hex(), encoding="utf-8")
        keys += ["--key", str(path)]

    assert main([str(directory), "--local", *keys]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    (directory / "model.safetensors").write_bytes(b"changed")
    assert main([str(directory), "--local", *keys]) == 1
