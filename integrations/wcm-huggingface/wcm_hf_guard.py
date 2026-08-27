#!/usr/bin/env python3
"""Hugging Face Hub download gate for Weight Custody Manifests.

Refuses a model snapshot whose bytes do not hash to the ``weights_hash`` a
jointly-signed WCM manifest binds. The manifest travels as an ordinary file in
the repository, so nothing about the Hub has to change and no private index is
involved.

**This is Layer 1 only.** Integrity and provenance: are these the weights the
builder shipped, under terms the builder and custodian both signed. It is not
Layer 2. Nothing here is attested, no key is released, and a public Hub
repository is not an enclave. A manifest published this way should normally
carry ``base_confidentiality: open``, because the bytes are downloadable by
anyone and calling them confidential would be false on its face. The value this
adds is that a swapped or tampered checkpoint is refused **before** it reaches a
loader, and that the licence and derivative terms are bound into a signature
rather than sitting in a README nobody diffed.

**Pin an immutable revision.** A branch name resolves to whatever the branch
points at today. Verifying a snapshot fetched from ``main`` proves that
*something* on main matched at some moment, which is not a claim anybody can
re-check. ``guarded_snapshot_download`` therefore requires a 40-character commit
sha unless ``allow_mutable_revision=True`` is passed explicitly, and says so.

**The artifact digest recipe is shared, not invented here.** See
``artifact_digest``. A manifest whose ``weights_hash`` was produced by a
different recipe will not match, and that is a mismatch in the recipe rather
than in the weights, so the failure message says which.

Usage::

    pip install weight-custody-manifest huggingface_hub

    python wcm_hf_guard.py HuggingFaceTB/SmolLM2-135M \\
        --revision <40-char-commit-sha> --public-key builder.pub --public-key custodian.pub
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from wcm import (
    ArtifactDigestError,
    BaseConfidentiality,
    VerificationContext,
    WeightCustodyManifest,
    artifact_digest,
    artifact_files,
    verify_manifest,
)
from wcm.artifact_digest import RECIPE_ID

__all__ = [
    "SIDECAR_NAME",
    "ARTIFACT_DIGEST_RECIPE",
    "FOLLOW_HUB_SYMLINKS",
    "GuardError",
    "GuardResult",
    "artifact_files",
    "artifact_digest",
    "load_sidecar_manifest",
    "verify_snapshot",
    "guarded_snapshot_download",
]

#: Where the manifest lives inside the model repository. A plain file at the
#: repository root: no Hub feature, no private index, and `huggingface_hub`
#: fetches it like any other artifact.
SIDECAR_NAME = "wcm.manifest.json"

#: Named so a digest mismatch can be attributed to the recipe rather than the
#: bytes. Re-exported from the SDK, which is where this now lives: it was
#: implemented separately here and in wcm-triton until
#: weight-custody-manifest 0.27.0 published ``wcm.artifact_digest``.
ARTIFACT_DIGEST_RECIPE = RECIPE_ID

#: Hub snapshots are symlink trees.
#:
#: ``snapshot_download`` populates ``snapshots/<revision>/`` with links into a
#: content-addressed ``blobs/`` directory in the same cache (on Windows without
#: developer mode it copies instead, so both layouts occur). The SDK refuses
#: symlinks by default, which is right for an artifact directory somebody handed
#: you and wrong here: refusing would make the gate fail on every Hub download
#: that used the normal cache.
#:
#: Following them is safe in this specific case because the targets are inside
#: the same locally-controlled cache and are named by their own content hash.
#: ``verify_snapshot`` exposes the flag so a caller verifying a plain copied
#: directory can tighten it back.
FOLLOW_HUB_SYMLINKS = True

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class GuardError(RuntimeError):
    """Raised when a snapshot must not be used.

    ``verify_snapshot`` and ``guarded_snapshot_download`` raise only this, so a
    caller needs one except clause. The SDK's ``ArtifactDigestError`` is
    translated inside them.

    ``artifact_digest`` and ``artifact_files`` are re-exported from the SDK
    unwrapped, and raise ``ArtifactDigestError`` as the SDK does. Wrapping a
    re-export would claim the function is ours when it is not, and would hide
    which layer rejected the inventory.
    """


@dataclass(frozen=True)
class GuardResult:
    """What the gate found. ``ok`` is the only value a caller should branch on."""

    ok: bool
    manifest: WeightCustodyManifest | None
    computed_digest: str | None
    expected_digest: str | None
    signatures_verified: bool
    reason: str | None = None
    #: Advisories that do not fail the gate but change what the result means.
    notes: tuple[str, ...] = field(default_factory=tuple)


def load_sidecar_manifest(directory: pathlib.Path) -> WeightCustodyManifest:
    """Read the manifest from a downloaded snapshot directory."""
    sidecar = directory / SIDECAR_NAME
    if not sidecar.is_file():
        raise GuardError(
            f"{SIDECAR_NAME} is not in the snapshot. This repository publishes no "
            "custody manifest, so there is nothing to verify against; treat the "
            "download as unmanifested rather than as verified."
        )
    try:
        return WeightCustodyManifest.model_validate_json(sidecar.read_text(encoding="utf-8"))
    except Exception as exc:  # pydantic ValidationError, kept narrow at the edge
        raise GuardError(f"{SIDECAR_NAME} is not a valid WCM manifest: {exc}") from exc


def _notes(manifest: WeightCustodyManifest, revision: str | None) -> tuple[str, ...]:
    notes: list[str] = []
    if manifest.base_confidentiality is BaseConfidentiality.confidential:
        notes.append(
            "manifest declares base_confidentiality: confidential, but these weights "
            "were downloaded from a Hub repository. Confidentiality is not something "
            "a public distribution channel can provide; the integrity and licence "
            "bindings still hold."
        )
    if revision is not None and not _COMMIT_SHA_RE.match(revision):
        notes.append(
            f"revision {revision!r} is not an immutable commit sha, so this result "
            "describes whatever that reference pointed at during the download."
        )
    return tuple(notes)


def verify_snapshot(
    directory: pathlib.Path,
    context: VerificationContext,
    *,
    include: Sequence[str] | None = None,
    revision: str | None = None,
    manifest: WeightCustodyManifest | None = None,
    follow_symlinks: bool = FOLLOW_HUB_SYMLINKS,
) -> GuardResult:
    """Check a downloaded snapshot against its manifest. Never raises on mismatch.

    Two independent facts are established and reported separately: whether the
    manifest's joint signatures verify against keys the caller trusts, and
    whether the bytes on disk hash to what that manifest binds. A snapshot can
    fail either way and the distinction matters, because a signature failure
    means the terms are not the ones you think and a digest failure means the
    weights are not the ones the terms cover.

    The manifest sidecar is excluded from the digest automatically. A manifest
    cannot bind a digest computed over a directory that contains that manifest,
    which would require the file to contain its own hash.
    """
    manifest = manifest or load_sidecar_manifest(directory)

    result = verify_manifest(manifest, context)
    notes = _notes(manifest, revision) + tuple(result.notes)
    if not result.ok:
        detail = "; ".join(result.errors) or "no trusted signature for a required role"
        return GuardResult(
            ok=False,
            manifest=manifest,
            computed_digest=None,
            expected_digest=manifest.weights_hash,
            signatures_verified=False,
            reason=f"manifest signatures did not verify: {detail}",
            notes=notes,
        )

    if include is None:
        try:
            include = [
                item.relative_to(directory).as_posix()
                for item in artifact_files(directory, follow_symlinks=follow_symlinks)
                if item.name != SIDECAR_NAME
            ]
        except ArtifactDigestError as exc:
            raise GuardError(str(exc)) from exc

    try:
        computed = str(
            artifact_digest(directory, include=include, follow_symlinks=follow_symlinks)
        )
    except ArtifactDigestError as exc:
        raise GuardError(str(exc)) from exc
    if computed != manifest.weights_hash:
        return GuardResult(
            ok=False,
            manifest=manifest,
            computed_digest=computed,
            expected_digest=manifest.weights_hash,
            signatures_verified=True,
            reason=(
                f"snapshot hashes to {computed}, manifest binds {manifest.weights_hash}. "
                f"Either the bytes differ, or the manifest was produced with a digest "
                f"recipe other than {ARTIFACT_DIGEST_RECIPE} or over a different file "
                f"inventory. Pass include= with the exact inventory the builder hashed "
                f"before concluding the weights were tampered with."
            ),
            notes=notes,
        )

    return GuardResult(
        ok=True,
        manifest=manifest,
        computed_digest=computed,
        expected_digest=manifest.weights_hash,
        signatures_verified=True,
        notes=notes,
    )


def guarded_snapshot_download(
    repo_id: str,
    context: VerificationContext,
    *,
    revision: str,
    include: Sequence[str] | None = None,
    allow_mutable_revision: bool = False,
    follow_symlinks: bool = FOLLOW_HUB_SYMLINKS,
    **snapshot_kwargs: Any,
) -> tuple[pathlib.Path, GuardResult]:
    """Download a snapshot and verify it, raising rather than returning bad weights.

    ``revision`` must be a 40-character commit sha. A branch or tag resolves to
    whatever it points at today, so verifying a snapshot fetched from ``main``
    establishes that something on main matched at some moment, which nobody can
    re-check later. Pass ``allow_mutable_revision=True`` to accept the weaker
    claim deliberately; the result carries a note saying you did.

    The downloaded files are left in place on failure. Deleting them would
    destroy the evidence of what was served, which is exactly what an
    investigation needs.
    """
    # Argument validation first. A caller who passed a branch name has a problem
    # this function can describe precisely, and reporting a missing dependency
    # instead would send them to fix the wrong thing.
    if not allow_mutable_revision and not _COMMIT_SHA_RE.match(revision or ""):
        raise GuardError(
            f"revision {revision!r} is not a 40-character commit sha. A branch or tag "
            "points at different bytes over time, so a verification against one is not "
            "a claim anyone can re-check. Pass allow_mutable_revision=True to accept "
            "that deliberately."
        )

    try:
        from huggingface_hub import snapshot_download
    except ModuleNotFoundError as exc:
        raise GuardError(
            "huggingface_hub is required for downloads. Verification of an "
            "already-downloaded directory works without it: use verify_snapshot."
        ) from exc

    directory = pathlib.Path(snapshot_download(repo_id, revision=revision, **snapshot_kwargs))
    result = verify_snapshot(
        directory,
        context,
        include=include,
        revision=revision,
        follow_symlinks=follow_symlinks,
    )
    if not result.ok:
        raise GuardError(
            f"{repo_id}@{revision} refused: {result.reason} "
            f"(files left at {directory} rather than deleted, so the evidence survives)"
        )
    return directory, result


def _public_key_context(paths: Iterable[pathlib.Path]) -> VerificationContext:
    """Trust the given raw Ed25519 PUBLIC keys. No private key is read here."""
    context = VerificationContext()
    for path in paths:
        raw = path.read_bytes().strip()
        try:
            material = bytes.fromhex(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            text = raw.decode("ascii")
            material = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        context.add_key(material)
    return context


def _report(**fields: object) -> str:
    """Serialize a CLI report from primitives only.

    Every value is coerced to bool, str or None here rather than being passed
    through from a result object. Nothing in this file puts key material in a
    result, and this makes that structural instead of a property of the current
    code: an attribute added later cannot reach stdout by being included in a
    dict comprehension somebody wrote in a hurry.
    """
    safe: dict[str, object] = {}
    for name, value in fields.items():
        if isinstance(value, bool) or value is None:
            safe[name] = value
        elif isinstance(value, (list, tuple)):
            safe[name] = [str(item) for item in value]
        else:
            safe[name] = str(value)
    return json.dumps(safe, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Hugging Face snapshot against a WCM manifest")
    parser.add_argument("repo_id", help="Hub repo id, or a local snapshot path with --local")
    parser.add_argument("--revision", help="40-character commit sha")
    parser.add_argument("--local", action="store_true", help="repo_id is a local directory")
    parser.add_argument(
        "--public-key",
        dest="public_key",
        type=pathlib.Path,
        action="append",
        default=[],
        required=True,
        help="raw Ed25519 PUBLIC key (hex or base64url); repeatable",
    )
    parser.add_argument("--include", action="append", help="POSIX relative path; repeatable")
    parser.add_argument("--allow-mutable-revision", action="store_true")
    parser.add_argument(
        "--no-follow-symlinks",
        action="store_true",
        help="refuse symlinks; use for a plain copied directory, not a Hub cache",
    )
    args = parser.parse_args(argv)

    context = _public_key_context(args.public_key)
    if args.local:
        result = verify_snapshot(
            pathlib.Path(args.repo_id),
            context,
            include=args.include,
            revision=args.revision,
            follow_symlinks=not args.no_follow_symlinks,
        )
    else:
        if not args.revision:
            parser.error("--revision is required for a Hub download")
        try:
            _, result = guarded_snapshot_download(
                args.repo_id,
                context,
                revision=args.revision,
                include=args.include,
                allow_mutable_revision=args.allow_mutable_revision,
                follow_symlinks=not args.no_follow_symlinks,
            )
        except GuardError as exc:
            print(json.dumps({"ok": False, "reason": str(exc)}, indent=2))
            return 1

    print(
        _report(
            ok=result.ok,
            signatures_verified=result.signatures_verified,
            computed_digest=result.computed_digest,
            expected_digest=result.expected_digest,
            reason=result.reason,
            notes=result.notes,
        )
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
