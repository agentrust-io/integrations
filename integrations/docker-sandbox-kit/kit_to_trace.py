#!/usr/bin/env python3
"""Docker Sandbox Kit (v3) manifest -> TRACE Trust Record, policy declared.

A Kit is one OCI image whose manifest annotation
``vnd.docker.sandbox.kit.descriptor`` carries the Kit's typed capability
requests: network allow and deny lists, credentials by phase, volumes, ports
(`SPEC-v3 <https://github.com/docker/sandbox-kit-spec/blob/main/docs/spec/SPEC-v3.md>`_,
section 1). The published descriptor is, in the spec's words, "what signatures
cover, what the resolver and the gate judge, and what the lock records"
(section 9.1). That makes it a real policy artifact, and this adapter binds its
exact bytes into ``policy.bundle_hash``.

**Why the record always says ``declared``.** The descriptor is a request. What
a host granted, and what a runtime then enforced, is the permission surface of
the *effective* descriptor, with this installation's create-phase args expanded,
stored in the runtime's lock (sections 7.4 and 10). None of that is in the
image. A record built from the image alone can name the policy the Kit asked
for and nothing more, which is exactly what TRACE ``declared`` means. Claiming
``enforce`` needs evidence from the runtime that it applied this descriptor, and
this adapter does not accept a mode argument that could say otherwise.

**Why the Kit digest is not the workload digest.** "What runs is never a
published artifact" (section 10): at create, an assembler emits an ordinary
image identified by the lock. The caller supplies the digest of the image that
ran. The Kit manifest digest goes into ``origin.source_event_id`` and
``policy.policy_uri``, where it identifies the evidence rather than the
execution.

Usage:
    python kit_to_trace.py kit-manifest.json \\
        --kit-reference docker.io/docker/sbx-kit-claude-acp-set \\
        --subject spiffe://example.org/agent/claude-acp \\
        --model-provider anthropic --model-id claude-sonnet-4-6 \\
        --workload-digest sha256:<64 hex, the assembled image that ran> \\
        --jwk pubkey.jwk > record.json

``kit-manifest.json`` is the raw platform manifest, byte for byte, as returned
by ``docker buildx imagetools inspect --raw <ref>@<platform digest>`` or
``crane manifest``. Re-serialised JSON has a different digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any

from agentrust_trace_adapters import MissingEvidence, PolicyEvidence, SourceSystem, build_record

SPEC_URL = "https://github.com/docker/sandbox-kit-spec/blob/main/docs/spec/SPEC-v3.md"
ADAPTER_URI = "https://github.com/agentrust-io/integrations/tree/main/integrations/docker-sandbox-kit"

DESCRIPTOR = "vnd.docker.sandbox.kit.descriptor"
SCHEMA_VERSION = "vnd.docker.sandbox.kit.schema-version"
CAPABILITIES = "vnd.docker.sandbox.kit.capabilities"
BUILT_BY = "vnd.docker.sandbox.kit.built-by"
# Annotations a v2 Kit carried. Seeing them means the grammar this adapter reads
# is absent, which deserves a better message than "not a Kit".
V2_MARKERS = ("vnd.docker.sandbox.kit.kind", "vnd.docker.sandbox.kit.name")

IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"

_REFERENCE_RE = re.compile(r"^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$")


@dataclass(frozen=True)
class KitEvidence:
    """A Kit's published descriptor, taken from a manifest the caller holds."""

    manifest_digest: str
    descriptor: bytes
    kind: str
    capability_types: tuple[str, ...]
    version: str | None
    frontend: str | None

    @classmethod
    def from_manifest(cls, raw: bytes, *, expected_digest: str | None = None) -> "KitEvidence":
        """Parse and check one platform manifest. Raises rather than guessing."""
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            raise MissingEvidence("no manifest bytes: there is no Kit here to describe")
        digest = "sha256:" + hashlib.sha256(bytes(raw)).hexdigest()
        if expected_digest is not None and digest != expected_digest:
            raise MissingEvidence(
                f"manifest bytes hash to {digest}, not {expected_digest}. The file was "
                "re-serialised or is a different manifest; fetch it raw."
            )
        try:
            manifest = json.loads(raw)
        except ValueError as exc:
            raise MissingEvidence(f"manifest is not JSON: {exc}") from exc
        if not isinstance(manifest, dict):
            raise MissingEvidence("manifest is not a JSON object")

        media_type = manifest.get("mediaType")
        if media_type in (IMAGE_INDEX, DOCKER_LIST) or "manifests" in manifest:
            raise MissingEvidence(
                "this is an image index, not a platform manifest. An index digest names "
                "no runnable image, and index annotations are an optimisation a "
                "multi-node build can drop (SPEC-v3 section 9.3). Pass the platform "
                "manifest the runtime pulled."
            )
        if media_type != IMAGE_MANIFEST or "artifactType" in manifest:
            raise MissingEvidence(
                f"mediaType {media_type!r}: a v3 Kit is a plain OCI image manifest with "
                "no artifactType (SPEC-v3 section 10)"
            )

        annotations = manifest.get("annotations") or {}
        if DESCRIPTOR not in annotations:
            if any(m in annotations for m in V2_MARKERS):
                raise MissingEvidence(
                    "this Kit was published with the v2 grammar, which carries no "
                    f"{DESCRIPTOR} annotation. Republish it with the v3 frontend."
                )
            raise MissingEvidence(f"no {DESCRIPTOR} annotation: this image is not a Kit")

        descriptor_text = annotations[DESCRIPTOR]
        if not isinstance(descriptor_text, str) or not descriptor_text:
            raise MissingEvidence(f"{DESCRIPTOR} is empty")
        try:
            descriptor = json.loads(descriptor_text)
        except ValueError as exc:
            # A YAML-valued annotation from before the switch to JSON would land
            # here. Its bytes are still a descriptor, but this adapter has no YAML
            # parser to check it with, and an unchecked bundle is not one to bind.
            raise MissingEvidence(
                f"{DESCRIPTOR} is not JSON ({exc}). Kits published before the frontend "
                "switched to compact JSON are not supported."
            ) from exc
        if not isinstance(descriptor, dict):
            raise MissingEvidence(f"{DESCRIPTOR} is not a JSON object")

        schema = descriptor.get("schemaVersion")
        if schema != "3" or annotations.get(SCHEMA_VERSION) != schema:
            raise MissingEvidence(
                f"schemaVersion {schema!r} with annotation "
                f"{annotations.get(SCHEMA_VERSION)!r}: this adapter reads schema 3, and "
                "the two MUST be equal (SPEC-v3 section 9.3)"
            )
        kind = descriptor.get("kind")
        if kind not in ("workload", "mixin"):
            raise MissingEvidence(
                f"kind {kind!r}: a published Kit is a workload or a mixin, never a set "
                "(SPEC-v3 section 11)"
            )

        requested = descriptor.get("capabilities") or []
        if not isinstance(requested, list) or not all(
            isinstance(c, dict) and isinstance(c.get("type"), str) for c in requested
        ):
            raise MissingEvidence("descriptor capabilities are not a list of typed entries")
        types = tuple(sorted({c["type"] for c in requested}))
        # The capabilities annotation is "an index, never a second source". If
        # it disagrees with the descriptor, something edited one of them, and a
        # policy filter reading the index would judge a different Kit from the
        # one this record names.
        index = annotations.get(CAPABILITIES)
        if (index or None) != (",".join(types) or None):
            raise MissingEvidence(
                f"{CAPABILITIES} is {index!r} but the descriptor requests "
                f"{','.join(types) or 'nothing'}. The index must mirror the descriptor."
            )

        frontend = None
        if BUILT_BY in annotations:
            try:
                built = json.loads(annotations[BUILT_BY])
                frontend = f"{built['name']}/{built['version']}"
            except (ValueError, KeyError, TypeError):
                frontend = None

        version = descriptor.get("version")
        return cls(
            manifest_digest=digest,
            descriptor=descriptor_text.encode("utf-8"),
            kind=kind,
            capability_types=types,
            version=version if isinstance(version, str) else None,
            frontend=frontend,
        )


def build_from_kit(
    evidence: KitEvidence,
    *,
    subject: str,
    model_provider: str,
    model_id: str,
    workload_digest: str,
    jwk: dict[str, Any],
    kit_reference: str | None = None,
    data_class: str = "unclassified",
    model_version: str | None = None,
) -> dict[str, Any]:
    """Map one Kit onto an unsigned Trust Record with a declared policy."""
    policy_uri = None
    if kit_reference is not None:
        if not _REFERENCE_RE.fullmatch(kit_reference):
            raise ValueError(
                f"kit_reference {kit_reference!r} must be a registry/repository name "
                "with no tag or digest; the digest comes from the manifest bytes"
            )
        policy_uri = f"oci://{kit_reference}@{evidence.manifest_digest}"

    record = build_record(
        source=SourceSystem(
            producer=evidence.frontend or "docker/sandbox-kit",
            kind="third-party-control-plane",
            source_event_id=evidence.manifest_digest,
        ),
        subject=subject,
        model_provider=model_provider,
        model_id=model_id,
        model_version=model_version,
        policy=PolicyEvidence(
            bundle=evidence.descriptor,
            enforcement_mode="declared",
            version="docker-sandbox-kit-v3",
            policy_uri=policy_uri,
        ),
        data_class=data_class,
        workload_digest=workload_digest,
        jwk=jwk,
    )
    # TRACE wants a URI here. Name this adapter as the party stating "none",
    # not Docker: no appraisal ran, and the record should not imply one did.
    record["appraisal"]["verifier"] = ADAPTER_URI
    return record


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", help="Raw platform manifest bytes of the Kit")
    ap.add_argument("--expected-digest", help="Refuse unless the manifest hashes to this sha256: digest")
    ap.add_argument("--kit-reference", help="Repository the Kit was pulled from, e.g. docker.io/docker/doodle")
    ap.add_argument("--subject", required=True, help="spiffe:// or did: identity of the workload")
    ap.add_argument("--model-provider", required=True)
    ap.add_argument("--model-id", required=True)
    ap.add_argument("--model-version")
    ap.add_argument(
        "--workload-digest",
        required=True,
        help="sha256: digest of the assembled image that ran, not of the Kit (SPEC-v3 section 10)",
    )
    ap.add_argument("--jwk", required=True, help="File holding the public confirmation key (JWK)")
    ap.add_argument("--data-class", default="unclassified")
    args = ap.parse_args()

    try:
        evidence = KitEvidence.from_manifest(
            pathlib.Path(args.manifest).read_bytes(), expected_digest=args.expected_digest
        )
        record = build_from_kit(
            evidence,
            subject=args.subject,
            model_provider=args.model_provider,
            model_id=args.model_id,
            model_version=args.model_version,
            workload_digest=args.workload_digest,
            jwk=json.loads(pathlib.Path(args.jwk).read_text()),
            kit_reference=args.kit_reference,
            data_class=args.data_class,
        )
    except MissingEvidence as exc:
        print(f"cannot build a truthful record: {exc}", file=sys.stderr)
        return 2

    json.dump(record, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
