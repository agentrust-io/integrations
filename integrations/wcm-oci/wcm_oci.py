#!/usr/bin/env python3
"""Weight Custody Manifest as an OCI referrer artifact.

Enterprises move model weights through registries. The OCI Referrers API (image
spec v1.1) exists so that an artifact can be attached to another artifact
without changing it: push the custody manifest with a ``subject`` pointing at the
model, and ``oras discover`` / ``GET /v2/<name>/referrers/<digest>`` finds it.
The model artifact's own digest never moves, so attaching custody terms after
publication does not invalidate anything downstream.

This module builds that referrer, and verifies one on the way back.

**The digest-domain problem, which is the whole difficulty here.**

An OCI ``subject`` descriptor names a *registry manifest digest*: the hash of the
model artifact's JSON manifest. WCM's ``weights_hash`` covers the *weight bytes*.
These are different numbers over different bytes, and neither can be derived from
the other by a registry.

So a referrer that only carries a subject digest proves the custody manifest was
attached to a particular registry object. It does **not** prove that object
contains the weights the manifest binds. Something has to close that gap, and a
registry cannot: it stores blobs and does not know that one of them, once
decompressed, is a safetensors shard.

``verify_referrer`` therefore takes the subject's layer descriptors and reports
``weights_binding`` as one of three values, never as a bare boolean:

``layer-digest``
    A layer descriptor's digest equals the manifest's ``weights_hash``. The
    strongest form available without unpacking, and the one to aim for: publish
    the weights as a single uncompressed layer whose digest is the bound hash.

``annotation-only``
    The referrer records the weights hash but no layer digest matches. The
    binding rests on whoever pushed the referrer. Useful, and not proof.

``unbound``
    Nothing connects this custody manifest to those bytes. Treat as unverified.

A caller that collapses these into "verified" has discarded the distinction the
format forces on us, which is why the field is a string.

Usage::

    pip install weight-custody-manifest

    python wcm_oci.py build manifest.json \\
        --subject-digest sha256:<model manifest digest> \\
        --subject-size 1234 \\
        --out-dir ./referrer
    oras push registry/model:custody --artifact-type ... ./referrer/...
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from wcm import VerificationContext, WeightCustodyManifest, verify_manifest

__all__ = [
    "ARTIFACT_TYPE",
    "MANIFEST_MEDIA_TYPE",
    "OCI_MANIFEST_MEDIA_TYPE",
    "EMPTY_DESCRIPTOR",
    "WEIGHTS_HASH_ANNOTATION",
    "WeightsBinding",
    "OciError",
    "ReferrerVerification",
    "build_referrer",
    "verify_referrer",
    "descriptor_for",
]

#: What a registry filters referrers by. Registries return this in the referrers
#: listing, so a client can ask for custody manifests specifically rather than
#: fetching every attachment on a model.
ARTIFACT_TYPE = "application/vnd.agentrust.wcm.manifest.v1+json"

#: Media type of the blob carrying the WCM manifest document.
MANIFEST_MEDIA_TYPE = "application/vnd.agentrust.wcm.manifest.v1+json"

OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"

#: The image-spec v1.1 empty descriptor. A referrer has no config of its own, and
#: the spec's guidance for that case is this exact blob, not an omitted field.
EMPTY_DESCRIPTOR = {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2,
    "data": "e30=",
}

#: Records the bound weights hash on the referrer, for the annotation-only case.
WEIGHTS_HASH_ANNOTATION = "org.agentrust.wcm.weights-hash"

_BUILDER_ANNOTATION = "org.agentrust.wcm.builder"
_CUSTODIAN_ANNOTATION = "org.agentrust.wcm.custodian"
_CREATED_ANNOTATION = "org.opencontainers.image.created"


class WeightsBinding:
    """How, if at all, the referrer ties the custody manifest to actual bytes."""

    LAYER_DIGEST = "layer-digest"
    ANNOTATION_ONLY = "annotation-only"
    UNBOUND = "unbound"

    ALL = (LAYER_DIGEST, ANNOTATION_ONLY, UNBOUND)


class OciError(ValueError):
    """Raised when a referrer cannot be built or read."""


@dataclass(frozen=True)
class ReferrerVerification:
    """Three independent facts. ``trusted`` deliberately requires all of them."""

    subject_matches: bool
    manifest_verified: bool
    weights_binding: str
    manifest: WeightCustodyManifest | None
    reason: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def trusted(self) -> bool:
        """True only for a layer-digest binding.

        ``annotation-only`` is not promoted to trusted here. It may well be good
        enough for a given deployment, and a caller is free to decide that, but
        the decision has to be taken explicitly rather than inherited from a
        property that quietly accepted a weaker binding.
        """
        return (
            self.subject_matches
            and self.manifest_verified
            and self.weights_binding == WeightsBinding.LAYER_DIGEST
        )


def descriptor_for(payload: bytes, media_type: str, **extra: Any) -> dict[str, Any]:
    """An OCI content descriptor over exact bytes."""
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        **extra,
    }


def build_referrer(
    manifest: WeightCustodyManifest,
    *,
    subject_digest: str,
    subject_size: int,
    subject_media_type: str = OCI_MANIFEST_MEDIA_TYPE,
    created: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Build the referrer manifest and the blob it references.

    Returns ``(referrer_manifest, blob_bytes)``. The blob is the WCM manifest
    document serialized exactly as it will be pushed; the descriptor inside the
    referrer is computed over those bytes, so a caller that re-serializes before
    pushing will produce a digest mismatch at the registry. Push the bytes this
    returns.

    ``created`` is passed through rather than defaulted to the current time. Two
    builds of the same manifest should produce byte-identical referrers, and a
    timestamp injected here would break that for no benefit; a registry records
    push time anyway.
    """
    if not subject_digest.startswith("sha256:") or len(subject_digest) != 71:
        raise OciError(
            f"subject_digest {subject_digest!r} is not an OCI sha256 descriptor digest. "
            "This is the digest of the model artifact's registry manifest, which is "
            "what a registry returns from a push and what the referrers API is keyed "
            "on. It is not the manifest's weights_hash; those cover different bytes."
        )
    if subject_size <= 0:
        raise OciError("subject_size must be the byte length of the subject manifest")

    blob = json.dumps(
        manifest.model_dump(mode="json", exclude_none=True),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    annotations = {
        WEIGHTS_HASH_ANNOTATION: manifest.weights_hash,
        _BUILDER_ANNOTATION: manifest.builder.identity,
        _CUSTODIAN_ANNOTATION: manifest.custody.custodian,
    }
    if created is not None:
        annotations[_CREATED_ANNOTATION] = created

    referrer = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": dict(EMPTY_DESCRIPTOR),
        "layers": [descriptor_for(blob, MANIFEST_MEDIA_TYPE)],
        "subject": {
            "mediaType": subject_media_type,
            "digest": subject_digest,
            "size": subject_size,
        },
        "annotations": annotations,
    }
    return referrer, blob


def _classify_binding(
    manifest: WeightCustodyManifest,
    referrer: dict[str, Any],
    subject_layers: Sequence[dict[str, Any]] | None,
) -> tuple[str, tuple[str, ...]]:
    notes: list[str] = []
    annotated = (referrer.get("annotations") or {}).get(WEIGHTS_HASH_ANNOTATION)

    if annotated is not None and annotated != manifest.weights_hash:
        notes.append(
            f"referrer annotation says {annotated}, the embedded manifest binds "
            f"{manifest.weights_hash}. The annotation is not authoritative and the "
            "manifest wins, but a disagreement means the referrer was assembled by "
            "something that did not read the document it carries."
        )

    if subject_layers is None:
        notes.append(
            "subject layer descriptors were not supplied, so no layer-digest binding "
            "could be attempted. Fetch the model artifact's manifest and pass its "
            "layers to get past annotation-only."
        )
        binding = WeightsBinding.ANNOTATION_ONLY if annotated else WeightsBinding.UNBOUND
        return binding, tuple(notes)

    digests = {layer.get("digest") for layer in subject_layers}
    if manifest.weights_hash in digests:
        return WeightsBinding.LAYER_DIGEST, tuple(notes)

    if annotated:
        notes.append(
            "no subject layer digest equals the bound weights_hash. This is the normal "
            "case for a multi-layer or compressed model artifact: a registry layer "
            "digest covers the compressed blob, while weights_hash covers the weights. "
            "Publish the weights as a single uncompressed layer to reach layer-digest, "
            "or verify the unpacked bytes separately."
        )
        return WeightsBinding.ANNOTATION_ONLY, tuple(notes)

    return WeightsBinding.UNBOUND, tuple(notes)


def verify_referrer(
    referrer: dict[str, Any],
    blob: bytes,
    context: VerificationContext,
    *,
    expected_subject_digest: str | None = None,
    subject_layers: Sequence[dict[str, Any]] | None = None,
) -> ReferrerVerification:
    """Check a fetched referrer and its blob. Never raises on an untrusted result.

    ``expected_subject_digest`` is the model artifact digest the caller believes
    it is pulling. Omitting it means the subject binding is unchecked, which
    reduces the referrer to "a custody manifest, from somewhere", so it is
    reported as a failed subject match rather than silently skipped.
    """
    if referrer.get("artifactType") != ARTIFACT_TYPE:
        raise OciError(
            f"artifactType is {referrer.get('artifactType')!r}, not {ARTIFACT_TYPE}. "
            "Another referrer may legitimately be attached to this model; it is not a "
            "custody manifest and must not be read as one."
        )

    layers = referrer.get("layers") or []
    if len(layers) != 1:
        raise OciError(
            f"expected exactly one layer carrying the manifest, found {len(layers)}"
        )
    expected = layers[0].get("digest")
    actual = "sha256:" + hashlib.sha256(blob).hexdigest()
    if expected != actual:
        raise OciError(
            f"blob digest {actual} does not match the layer descriptor {expected}. "
            "The referrer and the blob did not come from the same push."
        )
    if layers[0].get("size") != len(blob):
        raise OciError("layer descriptor size does not match the blob length")

    try:
        manifest = WeightCustodyManifest.model_validate_json(blob.decode("utf-8"))
    except Exception as exc:  # pydantic ValidationError, kept narrow at the edge
        raise OciError(f"referrer blob is not a valid WCM manifest: {exc}") from exc

    subject_digest = (referrer.get("subject") or {}).get("digest")
    subject_matches = (
        expected_subject_digest is not None and subject_digest == expected_subject_digest
    )

    result = verify_manifest(manifest, context)
    binding, binding_notes = _classify_binding(manifest, referrer, subject_layers)

    reason: str | None = None
    if expected_subject_digest is None:
        reason = (
            "expected_subject_digest was not supplied, so this referrer is a custody "
            "manifest from somewhere rather than one attached to the artifact you pulled"
        )
    elif not subject_matches:
        reason = (
            f"referrer subject is {subject_digest}, expected {expected_subject_digest}"
        )
    elif not result.ok:
        detail = "; ".join(result.errors) or "no trusted signature for a required role"
        reason = f"manifest did not verify: {detail}"
    elif binding != WeightsBinding.LAYER_DIGEST:
        reason = f"weights binding is {binding}, not a layer digest"

    return ReferrerVerification(
        subject_matches=subject_matches,
        manifest_verified=bool(result.ok),
        weights_binding=binding,
        manifest=manifest,
        reason=reason,
        notes=binding_notes + tuple(result.notes),
    )


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
    parser = argparse.ArgumentParser(description="WCM manifest <-> OCI referrer artifact")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build a referrer manifest and its blob")
    build.add_argument("manifest", type=pathlib.Path)
    build.add_argument("--subject-digest", required=True, help="model artifact manifest digest")
    build.add_argument("--subject-size", required=True, type=int)
    build.add_argument("--subject-media-type", default=OCI_MANIFEST_MEDIA_TYPE)
    build.add_argument("--created", help="RFC 3339 timestamp; omitted keeps builds reproducible")
    build.add_argument("--out-dir", type=pathlib.Path, required=True)

    check = sub.add_parser("verify", help="Verify a fetched referrer and blob")
    check.add_argument("referrer", type=pathlib.Path)
    check.add_argument("--blob", type=pathlib.Path, required=True)
    check.add_argument(
        "--public-key",
        dest="public_key",
        type=pathlib.Path,
        action="append",
        default=[],
        help="raw Ed25519 PUBLIC key (hex or base64url); repeatable",
    )
    check.add_argument("--expect-subject", help="model artifact digest you are pulling")
    check.add_argument("--subject-manifest", type=pathlib.Path, help="the model's OCI manifest")

    args = parser.parse_args(argv)

    if args.command == "build":
        manifest = WeightCustodyManifest.model_validate_json(
            args.manifest.read_text(encoding="utf-8")
        )
        referrer, blob = build_referrer(
            manifest,
            subject_digest=args.subject_digest,
            subject_size=args.subject_size,
            subject_media_type=args.subject_media_type,
            created=args.created,
        )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "referrer.json").write_bytes(
            json.dumps(referrer, indent=2, sort_keys=True).encode("utf-8")
        )
        (args.out_dir / "wcm.manifest.json").write_bytes(blob)
        print(json.dumps({"layers": referrer["layers"], "subject": referrer["subject"]}, indent=2))
        return 0

    subject_layers = None
    if args.subject_manifest:
        subject_layers = json.loads(args.subject_manifest.read_text(encoding="utf-8")).get("layers")

    outcome = verify_referrer(
        json.loads(args.referrer.read_text(encoding="utf-8")),
        args.blob.read_bytes(),
        _public_key_context(args.public_key),
        expected_subject_digest=args.expect_subject,
        subject_layers=subject_layers,
    )
    print(
        _report(
            trusted=outcome.trusted,
            subject_matches=outcome.subject_matches,
            manifest_verified=outcome.manifest_verified,
            weights_binding=outcome.weights_binding,
            reason=outcome.reason,
            notes=outcome.notes,
        )
    )
    return 0 if outcome.trusted else 1


if __name__ == "__main__":
    sys.exit(main())
