"""Offline checks for deterministic complete-snapshot hashing."""
from __future__ import annotations

import pathlib

from wcm import artifact_files

from real_open_model import sha256_artifact, tampered_digest


def test_artifact_hash_is_order_independent_and_covers_all_files(tmp_path: pathlib.Path) -> None:
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "model-00002-of-00002.safetensors").write_bytes(b"second")
    (tmp_path / "model-00001-of-00002.safetensors").write_bytes(b"first")

    before = sha256_artifact(tmp_path)
    assert [p.name for p in artifact_files(tmp_path, follow_symlinks=True)] == [
        "config.json",
        "model-00001-of-00002.safetensors",
        "model-00002-of-00002.safetensors",
    ]

    (tmp_path / "model-00002-of-00002.safetensors").write_bytes(b"SECOND")
    assert sha256_artifact(tmp_path) != before


def test_cache_metadata_is_not_part_of_serving_artifact(tmp_path: pathlib.Path) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"weights")
    cache = tmp_path / ".cache" / "huggingface"
    cache.mkdir(parents=True)
    (cache / "download-metadata.json").write_text("one", encoding="utf-8")

    digest = sha256_artifact(tmp_path)
    (cache / "download-metadata.json").write_text("two", encoding="utf-8")
    assert sha256_artifact(tmp_path) == digest


def test_tampered_fork_hashes_differently_and_leaves_the_original_alone(
    tmp_path: pathlib.Path,
) -> None:
    """The demo must never write to the model somebody just downloaded.

    This used to be a flip_first_byte flag threaded through the hash function.
    That avoided the copy but meant a second hashing path existing only to fake
    tampering; the recipe now comes from the SDK and the fork is a real one.
    """
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"weights")
    original = artifact.read_bytes()

    assert tampered_digest(artifact) != sha256_artifact(artifact)
    assert artifact.read_bytes() == original


def test_tampered_fork_of_a_directory_also_differs(tmp_path: pathlib.Path) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"weights")
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")

    assert tampered_digest(tmp_path) != sha256_artifact(tmp_path)


def test_the_recipe_comes_from_the_sdk() -> None:
    """One implementation. It lived here and in two integrations until 0.27.0."""
    import wcm

    assert artifact_files is wcm.artifact_files
    assert wcm.ARTIFACT_DIGEST_RECIPE == "wcm-artifact-digest/v1"
