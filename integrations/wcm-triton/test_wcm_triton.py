"""Tests for the Triton model repository staging step.

Includes a cross-check that this module's artifact digest is byte-for-byte the
same as the Hugging Face gate's. The failure mode of a digest recipe existing
twice is that it quietly stops being one recipe, and nothing else in either
module would notice.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import (  # noqa: E402
    Challenge,
    CheckResult,
    ReleaseDecision,
    SoftwareProvider,
    WeightCustodyManifest,
)

from wcm_triton import (  # noqa: E402
    AGENT_NAME,
    ARTIFACT_DIGEST_RECIPE,
    TritonStagingError,
    artifact_digest,
    artifact_files,
    build_agent_stanza,
    prepare_repository,
)

CURRENT = "sha256:" + "5e2d" * 16
OTHER_CURRENT = "sha256:" + "6f3e" * 16
KEY = b"k" * 32
PLAINTEXT = {"model.plan": b"engine-bytes", "config.pbtxt": b"name: \"m\"\n"}


def make_manifest(weights_hash: str, *, measurements: list[dict] | None = None):
    accepted = measurements or [{"measurement": CURRENT, "status": "current"}]
    return WeightCustodyManifest.model_validate(
        {
            "manifest_version": "0.1",
            "weights_hash": weights_hash,
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
                    "accepted_measurements": accepted,
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
    )


class FakeBroker:
    def __init__(self, *, released: bool = True, failures: tuple[str, ...] = ()) -> None:
        self.released = released
        self.failures = failures

    def issue_challenge(self) -> Challenge:
        now = dt.datetime.now(dt.timezone.utc)
        return Challenge(nonce="a" * 64, issued_at=now, expires_at=now + dt.timedelta(minutes=5))

    def verify_and_release(self, manifest, evidence) -> ReleaseDecision:  # noqa: ANN001
        checks = [CheckResult("nonce_fresh", True)]
        checks += [CheckResult(name, False) for name in self.failures]
        return ReleaseDecision(
            released=self.released, key=KEY if self.released else None, checks=checks
        )


def write(directory: pathlib.Path, files: dict[str, bytes]) -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (directory / name).write_bytes(payload)
    return directory


def decrypter(files: dict[str, bytes], *, seen: list[bytes] | None = None):
    def decrypt(encrypted: pathlib.Path, staging: pathlib.Path, key: bytes) -> None:
        if seen is not None:
            seen.append(key)
        write(staging, files)

    return decrypt


def expected_digest(tmp_path: pathlib.Path, files: dict[str, bytes]) -> str:
    return artifact_digest(write(tmp_path / "reference", files))


def test_successful_staging_verifies_the_decrypted_bytes(tmp_path: pathlib.Path) -> None:
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))

    result = prepare_repository(
        manifest=manifest,
        broker=FakeBroker(),
        provider=SoftwareProvider(),
        encrypted=tmp_path / "encrypted",
        staging=tmp_path / "staging",
        decrypt=decrypter(PLAINTEXT),
    )

    assert result.computed_digest == result.expected_digest
    assert result.files_staged == 2
    assert (tmp_path / "staging" / "model.plan").read_bytes() == b"engine-bytes"


def test_the_key_reaches_decrypt_only_after_release(tmp_path: pathlib.Path) -> None:
    seen: list[bytes] = []
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))

    prepare_repository(
        manifest=manifest,
        broker=FakeBroker(),
        provider=SoftwareProvider(),
        encrypted=tmp_path / "encrypted",
        staging=tmp_path / "staging",
        decrypt=decrypter(PLAINTEXT, seen=seen),
    )

    assert seen == [KEY]


def test_refused_release_stages_nothing(tmp_path: pathlib.Path) -> None:
    seen: list[bytes] = []
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))

    with pytest.raises(TritonStagingError, match="serving_image"):
        prepare_repository(
            manifest=manifest,
            broker=FakeBroker(released=False, failures=("serving_image",)),
            provider=SoftwareProvider(),
            encrypted=tmp_path / "encrypted",
            staging=tmp_path / "staging",
            decrypt=decrypter(PLAINTEXT, seen=seen),
        )

    assert seen == [], "decrypt must not be called without a released key"
    assert not (tmp_path / "staging").exists()


def test_wrong_plaintext_removes_the_staging_directory(tmp_path: pathlib.Path) -> None:
    """Triton scans its repository; a wrong staging directory is loadable."""
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))

    with pytest.raises(TritonStagingError, match="hashes to"):
        prepare_repository(
            manifest=manifest,
            broker=FakeBroker(),
            provider=SoftwareProvider(),
            encrypted=tmp_path / "encrypted",
            staging=tmp_path / "staging",
            decrypt=decrypter({"model.plan": b"different"}),
        )

    assert not (tmp_path / "staging").exists()


def test_a_failing_decrypt_also_removes_the_directory(tmp_path: pathlib.Path) -> None:
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))

    def broken(encrypted, staging, key):  # noqa: ANN001
        write(staging, {"partial.plan": b"half"})
        raise ValueError("cipher failure")

    with pytest.raises(ValueError, match="cipher failure"):
        prepare_repository(
            manifest=manifest,
            broker=FakeBroker(),
            provider=SoftwareProvider(),
            encrypted=tmp_path / "encrypted",
            staging=tmp_path / "staging",
            decrypt=broken,
        )

    assert not (tmp_path / "staging").exists()


def test_non_empty_staging_is_refused_before_anything_happens(tmp_path: pathlib.Path) -> None:
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))
    write(tmp_path / "staging", {"leftover.plan": b"old"})
    seen: list[bytes] = []

    with pytest.raises(TritonStagingError, match="not empty"):
        prepare_repository(
            manifest=manifest,
            broker=FakeBroker(),
            provider=SoftwareProvider(),
            encrypted=tmp_path / "encrypted",
            staging=tmp_path / "staging",
            decrypt=decrypter(PLAINTEXT, seen=seen),
        )

    assert seen == []
    assert (tmp_path / "staging" / "leftover.plan").exists(), "pre-existing files are untouched"


def test_ambiguous_current_image_must_be_named(tmp_path: pathlib.Path) -> None:
    manifest = make_manifest(
        expected_digest(tmp_path, PLAINTEXT),
        measurements=[
            {"measurement": CURRENT, "status": "current"},
            {"measurement": OTHER_CURRENT, "status": "current"},
        ],
    )

    with pytest.raises(TritonStagingError, match="cannot be inferred"):
        prepare_repository(
            manifest=manifest,
            broker=FakeBroker(),
            provider=SoftwareProvider(),
            encrypted=tmp_path / "encrypted",
            staging=tmp_path / "staging",
            decrypt=decrypter(PLAINTEXT),
        )


def test_mismatch_message_names_the_recipe_not_just_the_bytes(tmp_path: pathlib.Path) -> None:
    manifest = make_manifest(expected_digest(tmp_path, PLAINTEXT))

    with pytest.raises(TritonStagingError, match=ARTIFACT_DIGEST_RECIPE):
        prepare_repository(
            manifest=manifest,
            broker=FakeBroker(),
            provider=SoftwareProvider(),
            encrypted=tmp_path / "encrypted",
            staging=tmp_path / "staging",
            decrypt=decrypter({"model.plan": b"different"}),
        )


def test_agent_stanza_carries_the_two_values_an_agent_needs(tmp_path: pathlib.Path) -> None:
    stanza = build_agent_stanza(make_manifest(CURRENT))

    assert f'name: "{AGENT_NAME}"' in stanza
    assert f'key: "wcm_weights_hash" value: "{CURRENT}"' in stanza
    assert f'key: "wcm_serving_image" value: "{CURRENT}"' in stanza


def test_agent_stanza_refuses_an_ambiguous_current_image() -> None:
    manifest = make_manifest(
        CURRENT,
        measurements=[
            {"measurement": CURRENT, "status": "current"},
            {"measurement": OTHER_CURRENT, "status": "current"},
        ],
    )

    with pytest.raises(TritonStagingError, match="unreviewed choice"):
        build_agent_stanza(manifest)


def test_agent_name_is_validated() -> None:
    with pytest.raises(TritonStagingError, match="plain identifier"):
        build_agent_stanza(make_manifest(CURRENT), agent_name='x" }] } evil {')


def test_empty_artifact_raises(tmp_path: pathlib.Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(TritonStagingError, match="contains no files"):
        artifact_digest(empty)


def test_include_selects_an_explicit_inventory(tmp_path: pathlib.Path) -> None:
    directory = write(tmp_path / "d", PLAINTEXT)

    assert artifact_digest(directory, include=["model.plan"]) != artifact_digest(directory)


def test_missing_named_file_raises(tmp_path: pathlib.Path) -> None:
    directory = write(tmp_path / "d", PLAINTEXT)

    with pytest.raises(TritonStagingError, match="absent from the artifact"):
        artifact_digest(directory, include=["nope.plan"])


def test_nested_files_are_included(tmp_path: pathlib.Path) -> None:
    directory = tmp_path / "d"
    write(directory, {"a.plan": b"1"})
    write(directory / "sub", {"b.plan": b"2"})

    assert len(artifact_files(directory)) == 2


def test_artifact_digest_matches_the_hugging_face_gate_exactly(tmp_path: pathlib.Path) -> None:
    """One recipe, two implementations. This is the test that keeps them one.

    wcm-huggingface and this module both implement wcm-artifact-digest/v1,
    because it is not in the published SDK. If they ever disagree, a manifest
    produced by one path stops verifying on the other and the failure looks like
    tampered weights.
    """
    hugging_face = pathlib.Path(__file__).resolve().parents[1] / "wcm-huggingface"
    sys.path.insert(0, str(hugging_face))
    try:
        import wcm_hf_guard
    finally:
        sys.path.remove(str(hugging_face))

    assert wcm_hf_guard.ARTIFACT_DIGEST_RECIPE == ARTIFACT_DIGEST_RECIPE

    directory = write(tmp_path / "shared", PLAINTEXT)
    write(directory / "nested", {"c.bin": b"3"})
    (directory / ".cache").mkdir()
    (directory / ".cache" / "junk").write_bytes(b"ignored")

    assert wcm_hf_guard.artifact_digest(directory) == artifact_digest(directory)
    assert wcm_hf_guard.artifact_digest(directory, include=["model.plan"]) == artifact_digest(
        directory, include=["model.plan"]
    )
