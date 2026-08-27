#!/usr/bin/env python3
"""Weight Custody Manifest -> CycloneDX 1.6 ML-BOM component.

Procurement, licence review and third-party risk all run on BOM tooling. A WCM
manifest carries the facts those processes ask for (which weights, under what
licence, deployable where, derived from what) and none of it currently reaches
them, because a custody manifest is not a format any of those tools read.

This emits a CycloneDX 1.6 component of type ``machine-learning-model`` carrying
the manifest's terms, so a custody agreement shows up where a licence review is
already looking.

**A BOM is a description, not a control.** Nothing here is signed by this module,
verified by a consumer, or enforced anywhere. A BOM entry saying weights may not
leave the EU does not stop anyone. It exists so that the constraint is visible to
the people whose job is to notice it, and so a deployment inventory and a custody
agreement can be diffed rather than compared by hand.

The manifest's own signatures are what make its terms trustworthy, and they do
not survive this conversion. ``build_component`` therefore records the manifest's
canonical hash in an external reference, so a reviewer who wants the real
document can fetch it and verify it rather than trusting the BOM's summary.

**Fields with no CycloneDX home are dropped, not approximated.**
``UNMAPPED_FIELDS`` lists them with the reason. The temptation is to stuff the
release policy into ``properties`` as free text; that produces a BOM which looks
like it carries enforcement semantics and carries strings.

Usage::

    pip install weight-custody-manifest

    python wcm_cyclonedx.py manifest.json --name example-8b-instruct > mlbom.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Sequence

from wcm import WeightCustodyManifest, canonical_hash

__all__ = [
    "SPEC_VERSION",
    "PROPERTY_NAMESPACE",
    "UNMAPPED_FIELDS",
    "CycloneDxError",
    "build_component",
    "build_bom",
]

SPEC_VERSION = "1.6"

#: CycloneDX reserves property names by namespace. Everything this module adds is
#: under one prefix so a consumer can strip it wholesale and so nothing collides
#: with another tool's properties.
PROPERTY_NAMESPACE = "agentrust:wcm"

#: Manifest fields deliberately not represented, and why.
UNMAPPED_FIELDS = {
    "release_policy.required_serving_image": (
        "launch measurements of an approved serving stack. CycloneDX has no field "
        "for 'this component may only execute under these measurements', and a "
        "property holding them would read as enforceable when a BOM enforces "
        "nothing. The manifest is the authority; the external reference points at it."
    ),
    "release_policy.required_gpu_measurement": "same reason",
    "custody.kbs_image": (
        "describes the key broker, not this component. A BOM entry for the model "
        "should not carry the measurement of an unrelated service."
    ),
    "release_policy.memory_fingerprint_challenge": (
        "a hostile-owner runtime control. Recording it in a BOM would suggest a "
        "procurement process could verify it."
    ),
    "signatures": (
        "the joint signatures do not survive conversion, and a BOM carrying a "
        "signature over a different document would be worse than carrying none. "
        "The manifest hash in externalReferences is the way back to the signed "
        "original."
    ),
}


class CycloneDxError(ValueError):
    """Raised rather than emitting a BOM entry that misdescribes the manifest."""


def _properties(manifest: WeightCustodyManifest) -> list[dict[str, str]]:
    policy = manifest.release_policy
    values: dict[str, str] = {
        "manifest-version": manifest.manifest_version,
        "weights-hash": manifest.weights_hash,
        "builder": manifest.builder.identity,
        "custodian": manifest.custody.custodian,
        "custodian-type": manifest.custody.custodian_type.value,
        "deployment-model": manifest.deployment_model.value,
        "base-confidentiality": manifest.base_confidentiality.value,
        "permitted-derivatives": manifest.release_terms.permitted_derivatives,
        "permitted-environments": ", ".join(manifest.release_terms.permitted_environments),
        "required-hw-platform": ", ".join(policy.required_hw_platform),
        "required-assurance-tier": policy.required_assurance_tier.value,
        "tenancy": policy.tenancy.value,
        "key-release-mode": policy.key_release_mode.value,
        "attestation-cadence": manifest.custody.attestation_cadence,
    }
    if manifest.release_terms.jurisdiction_restriction:
        values["jurisdiction-restriction"] = manifest.release_terms.jurisdiction_restriction
    if manifest.release_terms.derivatives is not None:
        values["derivative-policy"] = manifest.release_terms.derivatives.value
    if policy.sovereign_profile.enabled:
        values["sovereign-profile"] = "enabled"
        values["sovereign-revocation-authority"] = policy.sovereign_profile.revocation_authority
    if manifest.rights_holder is not None:
        values["rights-holder-base"] = manifest.rights_holder.base
        if manifest.rights_holder.derivative:
            values["rights-holder-derivative"] = manifest.rights_holder.derivative

    return [
        {"name": f"{PROPERTY_NAMESPACE}:{key}", "value": value}
        for key, value in sorted(values.items())
    ]


def build_component(
    manifest: WeightCustodyManifest,
    *,
    name: str,
    version: str,
    publisher: str | None = None,
    description: str | None = None,
    manifest_uri: str | None = None,
) -> dict[str, Any]:
    """Build the ``machine-learning-model`` component for this manifest.

    ``name`` and ``version`` are required. A WCM manifest identifies weights by
    digest on purpose and carries no catalogue name or release version, and a BOM
    entry with no name is one a human cannot find in a review.

    ``manifest_uri`` is where the signed manifest can be fetched. When absent, the
    external reference still carries the manifest hash, so a reviewer can at
    least tell whether the document they were handed is the one this describes.
    """
    if not name or not version:
        raise CycloneDxError(
            "name and version are required. A WCM manifest identifies weights by "
            "digest and carries no catalogue name, and a nameless BOM entry is one "
            "nobody can find in a review."
        )

    algorithm, _, digest = manifest.weights_hash.partition(":")
    if algorithm != "sha256":
        raise CycloneDxError(
            f"weights_hash uses {algorithm!r}. CycloneDX hash algorithms are an "
            "enumerated set with no shake256 member, so the digest cannot be "
            "recorded as a hash. Emitting it under 'SHA-256' would make every "
            "consumer compare the wrong bytes."
        )

    external_references: list[dict[str, Any]] = [
        {
            "type": "other",
            "url": manifest_uri or "https://wcm.agentrust-io.com",
            "comment": (
                "Weight Custody Manifest, canonical hash "
                f"{canonical_hash(manifest.model_dump(mode='json', exclude_none=True))}. "
                "The manifest's joint signatures are the authority for these terms; "
                "this BOM is a description of them."
            ),
        }
    ]

    component: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": f"wcm:{digest}",
        "name": name,
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "licenses": [{"license": {"name": manifest.release_terms.license}}],
        "externalReferences": external_references,
        "properties": _properties(manifest),
    }
    if publisher:
        component["publisher"] = publisher
    if description:
        component["description"] = description
    if manifest.derived_from is not None:
        # A derivative points at its parent. Recording it as a bom-ref lets a
        # consumer resolve lineage inside the BOM when the parent is also listed,
        # and identifies it by digest when it is not.
        component["properties"].append(
            {"name": f"{PROPERTY_NAMESPACE}:derived-from", "value": str(manifest.derived_from)}
        )
    return component


def build_bom(
    manifests: Sequence[tuple[WeightCustodyManifest, dict[str, Any]]],
    *,
    serial_number: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Assemble a BOM around one or more components, with lineage as dependencies.

    ``timestamp`` and ``serial_number`` are passed through rather than generated,
    so two runs over the same manifests produce identical bytes and a BOM can be
    diffed across builds. A tool that stamps its own clock makes every rebuild
    look like a change.
    """
    components = [build_component(manifest, **kwargs) for manifest, kwargs in manifests]
    by_digest = {
        component["bom-ref"].split(":", 1)[1]: component["bom-ref"] for component in components
    }

    dependencies = []
    for (manifest, _), component in zip(manifests, components):
        if manifest.derived_from is None:
            continue
        parent = by_digest.get(str(manifest.derived_from).partition(":")[2])
        if parent is not None:
            dependencies.append({"ref": component["bom-ref"], "dependsOn": [parent]})

    metadata: dict[str, Any] = {
        "tools": {
            "components": [
                {"type": "application", "name": "wcm-cyclonedx", "group": "agentrust-io"}
            ]
        }
    }
    if timestamp is not None:
        metadata["timestamp"] = timestamp

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if serial_number is not None:
        bom["serialNumber"] = serial_number
    if dependencies:
        bom["dependencies"] = dependencies
    return bom


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WCM manifest -> CycloneDX 1.6 ML-BOM")
    parser.add_argument("manifest", type=pathlib.Path, nargs="+")
    parser.add_argument("--name", required=True, help="component name; repeat order matches manifests")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--publisher")
    parser.add_argument("--manifest-uri")
    parser.add_argument("--serial-number")
    parser.add_argument("--timestamp", help="RFC 3339; omitted keeps the output reproducible")
    parser.add_argument("--describe-unmapped", action="store_true")
    args = parser.parse_args(argv)

    if args.describe_unmapped:
        print(json.dumps(UNMAPPED_FIELDS, indent=2, sort_keys=True))
        return 0

    entries = []
    for index, path in enumerate(args.manifest):
        manifest = WeightCustodyManifest.model_validate_json(path.read_text(encoding="utf-8"))
        entries.append(
            (
                manifest,
                {
                    "name": args.name if index == 0 else f"{args.name}-{index}",
                    "version": args.version,
                    "publisher": args.publisher,
                    "manifest_uri": args.manifest_uri,
                },
            )
        )

    try:
        bom = build_bom(entries, serial_number=args.serial_number, timestamp=args.timestamp)
    except CycloneDxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(bom, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
