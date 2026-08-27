#!/usr/bin/env python3
"""Attestation-gated model repository staging for NVIDIA Triton.

Triton loads models from a model repository directory. This prepares that
directory: obtain the weight key through a WCM key broker, decrypt the model into
a staging path, verify the decrypted bytes hash to what the manifest binds, and
refuse to stage anything that does not. Triton then starts against a directory
whose contents are known good.

**This is not a Triton repository agent, and could not be.** Repository agents
are C shared objects loaded through the ``TRITONREPOAGENT_*`` API; Python cannot
provide one. What Python can do is be the step that runs before Triton starts, in
an init container or an entrypoint wrapper, or the process a C agent shells out
to. ``build_agent_stanza`` emits the ``model_repository_agents`` block for a
deployment that does have an agent, so both shapes are covered.

**No cipher is chosen here.** WCM specifies a manifest, a release protocol and a
custody state machine. It does not specify a container format for encrypted
weights, and inventing one inside an integration is how a project ends up with
three incompatible dialects of the same idea. ``prepare_repository`` therefore
takes a ``decrypt`` callable: the deployment owns the cipher and the container,
and this owns the custody decisions around it.

**What is verified after decryption.** The staged directory is hashed with
``wcm-artifact-digest/v1``, the same recipe
``integrations/wcm-huggingface`` uses, and compared with the manifest's
``weights_hash``. A cross-check test asserts the two implementations agree
byte for byte, because the failure mode of a digest recipe existing twice is that
it quietly stops being one recipe.

Usage::

    pip install weight-custody-manifest

    from wcm_triton import prepare_repository

    result = prepare_repository(
        manifest=manifest,
        broker=kbs,
        provider=provider,
        encrypted=pathlib.Path("/models/encrypted"),
        staging=pathlib.Path("/models/repository/mymodel/1"),
        decrypt=my_decrypt,
    )
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
from dataclasses import dataclass
from typing import Any, Callable, Protocol, Sequence

from wcm import (
    AttestationProvider,
    CompositeEvidence,
    ReleaseDecision,
    ServingImageStatus,
    WeightCustodyManifest,
)

__all__ = [
    "ARTIFACT_DIGEST_RECIPE",
    "AGENT_NAME",
    "TritonStagingError",
    "StagingResult",
    "artifact_files",
    "artifact_digest",
    "build_agent_stanza",
    "prepare_repository",
]

#: Must stay identical to integrations/wcm-huggingface. See the cross-check test.
ARTIFACT_DIGEST_RECIPE = "wcm-artifact-digest/v1"

#: The conventional repository-agent name for a deployment that has a C agent.
AGENT_NAME = "wcm"

_EXCLUDED_PARTS = frozenset({".cache", ".git", ".gitattributes", ".huggingface"})


class TritonStagingError(RuntimeError):
    """Raised rather than leaving Triton a directory it should not load."""


class Broker(Protocol):
    def issue_challenge(self) -> Any: ...

    def verify_and_release(
        self, manifest: WeightCustodyManifest, evidence: CompositeEvidence
    ) -> ReleaseDecision: ...


@dataclass(frozen=True)
class StagingResult:
    """What was staged, and what proved it."""

    staging: pathlib.Path
    computed_digest: str
    expected_digest: str
    files_staged: int
    failed_checks: tuple[str, ...] = ()


def artifact_files(path: pathlib.Path) -> list[pathlib.Path]:
    """The deterministic file inventory a manifest binds."""
    if path.is_file():
        return [path]
    files = [
        candidate
        for candidate in path.rglob("*")
        if candidate.is_file()
        and not _EXCLUDED_PARTS.intersection(candidate.relative_to(path).parts)
    ]
    if not files:
        raise TritonStagingError(f"model artifact contains no files: {path}")
    return sorted(files, key=lambda candidate: candidate.relative_to(path).as_posix())


def artifact_digest(path: pathlib.Path, *, include: Sequence[str] | None = None) -> str:
    """Hash a file or a complete model directory. See ARTIFACT_DIGEST_RECIPE.

    Sorted by POSIX relative path; per file the length-prefixed relative path,
    the 8-byte big-endian size, then the contents. Length prefixing stops two
    directory layouts flattening to the same byte stream.
    """
    root = path if path.is_dir() else path.parent
    files = artifact_files(path)

    if include is not None:
        wanted = set(include)
        by_relative = {item.relative_to(root).as_posix(): item for item in files}
        missing = sorted(wanted - by_relative.keys())
        if missing:
            raise TritonStagingError(
                f"named files are absent from the artifact: {', '.join(missing)}"
            )
        files = [by_relative[name] for name in sorted(wanted)]

    digest = hashlib.sha256()
    for item in files:
        relative = item.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(item.stat().st_size.to_bytes(8, "big"))
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def build_agent_stanza(
    manifest: WeightCustodyManifest, *, agent_name: str = AGENT_NAME
) -> str:
    """Emit the ``model_repository_agents`` block for a ``config.pbtxt``.

    The manifest's weights hash and the current serving-image measurement are
    passed as agent parameters, so a C agent has the two values it needs without
    reading the manifest itself, and a config that drifts from its manifest is
    visible in a diff.
    """
    if not agent_name.replace("_", "").replace("-", "").isalnum():
        raise TritonStagingError(f"agent_name {agent_name!r} is not a plain identifier")

    current = [
        entry.measurement
        for entry in manifest.release_policy.required_serving_image.accepted_measurements
        if entry.status is ServingImageStatus.current
    ]
    if len(current) != 1:
        raise TritonStagingError(
            f"the manifest lists {len(current)} current serving images. A config.pbtxt "
            "names one; emitting a stanza that picked one arbitrarily would put an "
            "unreviewed choice into a deployment file."
        )

    return (
        "model_repository_agents {\n"
        "  agents [\n"
        "    {\n"
        f'      name: "{agent_name}"\n'
        "      parameters [\n"
        f'        {{ key: "wcm_weights_hash" value: "{manifest.weights_hash}" }},\n'
        f'        {{ key: "wcm_serving_image" value: "{current[0]}" }},\n'
        f'        {{ key: "wcm_custodian" value: "{manifest.custody.custodian}" }}\n'
        "      ]\n"
        "    }\n"
        "  ]\n"
        "}\n"
    )


def prepare_repository(
    *,
    manifest: WeightCustodyManifest,
    broker: Broker,
    provider: AttestationProvider,
    encrypted: pathlib.Path,
    staging: pathlib.Path,
    decrypt: Callable[[pathlib.Path, pathlib.Path, bytes], None],
    serving_image_measurement: str | None = None,
    include: Sequence[str] | None = None,
) -> StagingResult:
    """Attest, release, decrypt into ``staging``, and verify before returning.

    ``decrypt(encrypted, staging, key)`` is the deployment's own routine. It is
    called with the key only after the broker released it, and its output is
    hashed and compared before this function returns; a mismatch removes the
    staging directory rather than leaving Triton something to load.

    Removing it on failure is the opposite of what the Hugging Face gate does,
    and deliberately so. There the files are evidence of what a registry served.
    Here they are an intermediate this process just produced, and the risk that
    matters is Triton finding them.
    """
    if staging.exists() and any(staging.iterdir()):
        raise TritonStagingError(
            f"staging directory {staging} is not empty. Refusing to decrypt over "
            "existing files: the resulting digest would cover a mixture of this "
            "release and whatever was there before."
        )

    if serving_image_measurement is None:
        current = [
            entry.measurement
            for entry in manifest.release_policy.required_serving_image.accepted_measurements
            if entry.status is ServingImageStatus.current
        ]
        if len(current) != 1:
            raise TritonStagingError(
                f"the manifest lists {len(current)} current serving images, so which one "
                "this workload is cannot be inferred. Pass serving_image_measurement."
            )
        serving_image_measurement = current[0]

    challenge = broker.issue_challenge()
    evidence = provider.produce(
        challenge, serving_image_measurement=serving_image_measurement
    )
    decision = broker.verify_and_release(manifest, evidence)
    if not decision.released or decision.key is None:
        failed = tuple(sorted(check.name for check in decision.failures))
        raise TritonStagingError(
            "key release refused, nothing staged: " + (", ".join(failed) or "no checks passed")
        )

    staging.mkdir(parents=True, exist_ok=True)
    try:
        decrypt(encrypted, staging, decision.key)
        computed = artifact_digest(staging, include=include)
        if computed != manifest.weights_hash:
            raise TritonStagingError(
                f"decrypted model hashes to {computed}, manifest binds "
                f"{manifest.weights_hash}. Either the ciphertext is not these weights, "
                f"or the manifest was produced with a recipe other than "
                f"{ARTIFACT_DIGEST_RECIPE} or over a different file inventory."
            )
    except Exception:
        # Triton scans its model repository; a half-written or wrong staging
        # directory is something it may load. Remove it before re-raising.
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return StagingResult(
        staging=staging,
        computed_digest=computed,
        expected_digest=manifest.weights_hash,
        files_staged=len(artifact_files(staging)),
    )
