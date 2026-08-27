#!/usr/bin/env python3
"""Weight Custody Manifest -> Confidential Containers Trustee resource policy.

Trustee is the key broker the confidential-containers project ships, and it is
the one an open confidential-computing deployment is most likely already
running. A workload asks for a resource by URI (``kbs:///<repo>/<type>/<tag>``),
Trustee's Attestation Service verifies the evidence and issues a token, and a
Rego policy decides whether that token entitles the caller to the resource.

That is WCM Layer 2 with different nouns. This generates the Rego, and the
resource layout the model key should live at.

**The measurement problem again, and the same answer.** A WCM ``HashValue`` is
256-bit. An SEV-SNP launch measurement in a Trustee token is 384-bit, and a TDX
MRTD is 384-bit. They cannot be compared, and a Rego rule comparing them denies
every request while looking correct. ``build_policy`` therefore requires
``measurement_path``: the dotted path into the token claims that holds the value
your manifest's measurements were computed against. Widths are checked where
known.

Where WCM's Azure vTPM path is in use, the corresponding Trustee TEE is
``azsnpvtpm`` or ``aztdxvtpm`` rather than ``snp`` or ``tdx``, and the value in
the token is a TPM PCR digest, which is 256-bit and therefore does fit. That is
the configuration where this composes without an impedance mismatch, and it is
the one to prefer.

**Rego is generated, not templated from user strings.** Every value interpolated
into the policy is either a hex digest validated against a character class or a
TEE name from a fixed set. A policy generator that concatenated arbitrary input
into Rego would be an injection vector into the component that decides who gets
model keys.

Usage::

    pip install weight-custody-manifest

    python wcm_coco.py manifest.json \\
        --measurement-path tcb_status.azsnpvtpm.tpm.pcr04 \\
        --repository default > policy.rego
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any, Sequence

from wcm import AssuranceTier, ServingImageStatus, WeightCustodyManifest

__all__ = [
    "TEE_BY_PLATFORM",
    "CLAIM_HEX_WIDTH",
    "RESOURCE_TYPE",
    "CocoPolicyError",
    "build_policy",
    "resource_uri",
]

#: WCM platform -> the ``tee`` values Trustee reports.
#:
#: The vTPM variants matter: they are what a cloud CVM reports, and they are the
#: configuration where a WCM measurement (256-bit, a PCR digest) and a Trustee
#: claim are the same width. The bare ``snp``/``tdx`` values come from bare-metal
#: evidence carrying a 384-bit launch measurement, which does not fit a WCM
#: HashValue at all.
TEE_BY_PLATFORM = {
    "amd-sev-snp": ("snp", "azsnpvtpm"),
    "intel-tdx": ("tdx", "aztdxvtpm"),
}

#: Known hex widths for claim paths, so a mismatch fails at generation time.
#: A path not listed here is accepted without a width check, because Trustee's
#: claim set is deployment-specific and asserting a width for a claim we have
#: not confirmed would be a worse error than not checking.
CLAIM_HEX_WIDTH = {
    "tcb_status.snp.measurement": 96,
    "tcb_status.tdx.mrtd": 96,
}

#: The resource type segment in a kbs:/// URI for a WCM-governed model key.
RESOURCE_TYPE = "wcm-model-key"

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class CocoPolicyError(ValueError):
    """Raised when a manifest cannot be translated into a usable Trustee policy."""


def resource_uri(manifest: WeightCustodyManifest, *, repository: str = "default") -> str:
    """Where the model key for this manifest should live in Trustee.

    The tag is the manifest's ``weights_hash`` digest, so two manifests over
    different weights cannot collide on one resource, and rotating weights means
    publishing to a new URI rather than overwriting the key a running workload
    still holds a lease on.
    """
    if not _TAG_RE.match(repository):
        raise CocoPolicyError(f"repository {repository!r} is not a valid Trustee path segment")
    return f"kbs:///{repository}/{RESOURCE_TYPE}/{manifest.weights_hash.split(':', 1)[1]}"


def _usable_measurements(manifest: WeightCustodyManifest) -> list[str]:
    """Non-revoked accepted measurements, as bare hex.

    ``retiring`` is kept: WCM's rule is prefer-current, and denying retiring
    images would take a fleet offline during a rollover.
    """
    digests = []
    for entry in manifest.release_policy.required_serving_image.accepted_measurements:
        if entry.status is ServingImageStatus.revoked:
            continue
        digest = entry.measurement.split(":", 1)[1]
        if not _HEX_RE.match(digest):
            raise CocoPolicyError(
                f"measurement {entry.measurement} is not lowercase hex; refusing to "
                "interpolate it into Rego"
            )
        digests.append(digest)
    if not digests:
        raise CocoPolicyError(
            "every accepted measurement is revoked. A policy with no permitted "
            "measurement denies everything, which is correct but is a manifest "
            "problem rather than something to emit and forget."
        )
    return digests


def _tee_values(manifest: WeightCustodyManifest, vtpm: bool) -> list[str]:
    values: list[str] = []
    for platform in manifest.release_policy.required_hw_platform:
        options = TEE_BY_PLATFORM.get(platform)
        if options is None:
            continue
        values.append(options[1] if vtpm else options[0])
    if not values:
        raise CocoPolicyError(
            f"none of {list(manifest.release_policy.required_hw_platform)} maps to a "
            "Trustee TEE. Trustee gates on CVM evidence; a GPU-only requirement has no "
            "tee value and stays with the WCM broker's GPU check."
        )
    return list(dict.fromkeys(values))


def build_policy(
    manifest: WeightCustodyManifest,
    *,
    measurement_path: str,
    repository: str = "default",
    vtpm: bool = True,
    allow_unbound_workload: bool = False,
) -> str:
    """Generate the Rego resource policy for this manifest.

    ``measurement_path`` is a dotted path into the Trustee token claims, for
    example ``tcb_status.azsnpvtpm.tpm.pcr04``. It cannot be inferred: which
    claim carries the value a manifest binds depends on how that manifest was
    built, and guessing produces a policy that denies everything while looking
    right.

    ``vtpm`` selects the cloud CVM TEE names (``azsnpvtpm``, ``aztdxvtpm``) over
    the bare-metal ones. It defaults to true because that is where a 256-bit WCM
    measurement and a Trustee claim are the same width.
    """
    if not _PATH_RE.match(measurement_path or ""):
        raise CocoPolicyError(
            f"measurement_path {measurement_path!r} is not a dotted identifier path. "
            "Only identifiers and dots are accepted: this string is interpolated into "
            "Rego that decides who gets model keys."
        )

    tees = _tee_values(manifest, vtpm)
    measurements = _usable_measurements(manifest)

    width = CLAIM_HEX_WIDTH.get(measurement_path)
    if width is not None:
        for digest in measurements:
            if len(digest) != width:
                raise CocoPolicyError(
                    f"measurement has {len(digest)} hex characters but {measurement_path} "
                    f"carries {width}. A WCM HashValue is 256-bit; an SNP launch "
                    "measurement and a TDX MRTD are 384-bit. Comparing them denies every "
                    "request while looking correct. Use the vTPM path, whose PCR digests "
                    "are 256-bit, or record measurements the claim's width."
                )

    lines: list[str] = [
        "# Generated from a Weight Custody Manifest. Do not hand-edit: regenerate.",
        "#",
        f"# Resource: {resource_uri(manifest, repository=repository)}",
        f"# Weights:  {manifest.weights_hash}",
        f"# Builder:  {manifest.builder.identity}",
        "#",
        "# This policy decides whether an attested workload may fetch the model key.",
        "# It does NOT verify the evidence: Trustee's Attestation Service does that",
        "# before this policy runs, and this reads the claims it produced.",
        "",
        "package policy",
        "",
        "default allow = false",
        "",
        "allowed_tee := {" + ", ".join(json.dumps(tee) for tee in tees) + "}",
        "",
    ]

    if allow_unbound_workload:
        lines += [
            "# WARNING: no workload measurement condition was generated. Any workload",
            "# whose evidence verifies on an allowed TEE can fetch this key. The",
            "# manifest's accepted_measurements are NOT enforced here.",
            "allow {",
            "\tinput.tee == allowed_tee[_]",
            "}",
            "",
        ]
    else:
        lines += [
            "allowed_measurement := {"
            + ", ".join(json.dumps(digest) for digest in measurements)
            + "}",
            "",
            "allow {",
            "\tinput.tee == allowed_tee[_]",
            f"\tinput.{measurement_path} == allowed_measurement[_]",
        ]
        if manifest.release_policy.required_assurance_tier is AssuranceTier.hardware_attested:
            lines.append('\tinput.tee != "sample"')
        lines += ["}", ""]

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WCM manifest -> Confidential Containers Trustee resource policy"
    )
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument(
        "--measurement-path",
        help="dotted claim path holding the manifest's measurement values",
    )
    parser.add_argument("--repository", default="default")
    parser.add_argument(
        "--bare-metal",
        action="store_true",
        help="use snp/tdx rather than the azsnpvtpm/aztdxvtpm cloud CVM names",
    )
    parser.add_argument("--allow-unbound-workload", action="store_true")
    parser.add_argument("--print-uri", action="store_true", help="print the resource URI and exit")
    args = parser.parse_args(argv)

    manifest = WeightCustodyManifest.model_validate_json(
        args.manifest.read_text(encoding="utf-8")
    )
    if args.print_uri:
        print(resource_uri(manifest, repository=args.repository))
        return 0

    if not args.measurement_path and not args.allow_unbound_workload:
        print(
            "error: --measurement-path is required. Which Trustee claim carries the "
            "value your manifest's measurements were computed against depends on how "
            "the manifest was built, and guessing produces a policy that denies every "
            "request while looking correct. Pass --allow-unbound-workload to generate "
            "a TEE-only policy deliberately.",
            file=sys.stderr,
        )
        return 1

    try:
        policy = build_policy(
            manifest,
            measurement_path=args.measurement_path or "unused",
            repository=args.repository,
            vtpm=not args.bare_metal,
            allow_unbound_workload=args.allow_unbound_workload,
        )
    except CocoPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(policy)
    if args.allow_unbound_workload:
        print(
            "warning: this policy binds the TEE only. Any workload whose evidence "
            "verifies on an allowed TEE can fetch this key.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
