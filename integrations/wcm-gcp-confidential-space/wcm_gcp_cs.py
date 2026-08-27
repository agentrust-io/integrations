#!/usr/bin/env python3
"""Weight Custody Manifest -> GCP Confidential Space workload identity condition.

Confidential Space runs a container in a confidential VM and hands it an OIDC
attestation token from Google's Attestation Verifier. A Workload Identity Pool
provider carries a CEL attribute condition over that token's claims; only a
workload whose token satisfies the condition can impersonate the service account
that can decrypt with Cloud KMS. That is WCM Layer 2 in Google's encoding.

**Here the measurement mapping actually works, unlike on Azure.**

Confidential Space identifies the workload by ``submods.container.image_digest``,
which is an OCI image digest: ``sha256:`` followed by 64 hex characters. A WCM
``HashValue`` is the same shape. So if a manifest's ``accepted_measurements``
were computed as container image digests, the condition compares like with like
and no impedance mismatch exists.

That is a real "if", and this module does not hide it. The generated condition
carries a comment stating that the manifest's measurements are being read as OCI
image digests, and that a manifest built some other way produces a condition
which never matches. ``--measurement-claim`` overrides the claim when a
deployment binds workload identity differently.

Compare ``integrations/wcm-azure-skr``, where a 256-bit WCM measurement and a
384-bit SNP launch measurement cannot be compared at all. The difference is worth
knowing when choosing where to deploy.

**Hardware model values are not asserted from memory.** ``HWMODEL_BY_PLATFORM``
maps WCM platforms to the ``hwmodel`` values a Confidential Space token is
expected to carry, and it is overridable. Run ``--print-claims`` against a token
from your own project to confirm what your fleet actually reports before pinning
it; a condition naming a value your tokens do not carry denies everything.

Usage::

    pip install weight-custody-manifest

    python wcm_gcp_cs.py manifest.json --project-number 123456789012 \\
        --pool wcm-pool --provider confidential-space
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any, Mapping, Sequence

from wcm import (
    AssuranceTier,
    Challenge,
    CompositeEvidence,
    CpuQuote,
    ServingImageStatus,
    WeightCustodyManifest,
)

__all__ = [
    "HWMODEL_BY_PLATFORM",
    "SUPPORT_ATTRIBUTES",
    "IMAGE_DIGEST_CLAIM",
    "ConfidentialSpaceError",
    "build_attribute_condition",
    "build_provider_command",
    "evidence_from_cs_claims",
]

#: The claim Confidential Space uses to identify the workload container.
#: An OCI image digest, sha256 and 64 hex characters, the same shape as a WCM
#: HashValue. This is why the mapping works here.
IMAGE_DIGEST_CLAIM = "submods.container.image_digest"

#: WCM platform -> expected ``hwmodel`` claim value.
#:
#: Overridable, and worth confirming with --print-claims against a token from
#: your own project before pinning. A condition naming a value your tokens do not
#: carry denies every request and looks like a broken attestation verifier.
HWMODEL_BY_PLATFORM = {
    "amd-sev-snp": "GCP_AMD_SEV_SNP",
    "intel-tdx": "GCP_INTEL_TDX",
}

#: Confidential Space image support attributes, strongest first. STABLE is the
#: only one appropriate for a production custody deployment: the others mark
#: images that may change behaviour without notice.
SUPPORT_ATTRIBUTES = ("STABLE", "LATEST", "USABLE")

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLAIM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


class ConfidentialSpaceError(ValueError):
    """Raised when a manifest cannot be turned into a usable condition."""


def _usable_measurements(manifest: WeightCustodyManifest) -> list[str]:
    digests = [
        entry.measurement
        for entry in manifest.release_policy.required_serving_image.accepted_measurements
        if entry.status is not ServingImageStatus.revoked
    ]
    if not digests:
        raise ConfidentialSpaceError(
            "every accepted measurement is revoked. The resulting condition would deny "
            "everything, which is a manifest problem rather than a condition to emit."
        )
    return digests


def build_attribute_condition(
    manifest: WeightCustodyManifest,
    *,
    measurement_claim: str = IMAGE_DIGEST_CLAIM,
    support_attribute: str = "STABLE",
    require_debug_disabled: bool = True,
    allow_unbound_workload: bool = False,
) -> str:
    """Build the CEL attribute condition for a Workload Identity Pool provider.

    Returns a single CEL expression. Every literal interpolated into it is either
    a validated digest, a claim path matching a dotted-identifier pattern, or a
    value from a fixed set: this expression decides who can decrypt model
    weights, and building it by string concatenation from unvalidated input would
    be an injection into that decision.
    """
    if not _CLAIM_RE.match(measurement_claim or ""):
        raise ConfidentialSpaceError(
            f"measurement_claim {measurement_claim!r} is not a dotted identifier path"
        )
    if support_attribute not in SUPPORT_ATTRIBUTES:
        raise ConfidentialSpaceError(
            f"support_attribute must be one of {', '.join(SUPPORT_ATTRIBUTES)}"
        )

    hwmodels = [
        HWMODEL_BY_PLATFORM[platform]
        for platform in manifest.release_policy.required_hw_platform
        if platform in HWMODEL_BY_PLATFORM
    ]
    if not hwmodels:
        raise ConfidentialSpaceError(
            f"none of {list(manifest.release_policy.required_hw_platform)} maps to a "
            "Confidential Space hwmodel. The token describes the confidential VM; a "
            "GPU-only requirement has no hwmodel and stays with the WCM broker's GPU "
            "check."
        )

    clauses = [
        'assertion.swname == "CONFIDENTIAL_SPACE"',
        "["
        + ", ".join(json.dumps(model) for model in dict.fromkeys(hwmodels))
        + "].exists(m, assertion.hwmodel == m)",
        f'{json.dumps(support_attribute)} in '
        "assertion.submods.confidential_space.support_attributes",
    ]
    if require_debug_disabled:
        # A guest that was debuggable at any point since boot can have been
        # inspected, which is the software adversary WCM's guarantee is against.
        clauses.append('assertion.dbgstat == "disabled-since-boot"')

    if not allow_unbound_workload:
        measurements = _usable_measurements(manifest)
        for measurement in measurements:
            if not _DIGEST_RE.match(measurement):
                raise ConfidentialSpaceError(
                    f"measurement {measurement} is not sha256:<64 hex>, so it cannot be "
                    f"compared with {measurement_claim}, which carries an OCI image "
                    "digest. Either record measurements as image digests or name the "
                    "claim your deployment binds workload identity with."
                )
        clauses.append(
            "["
            + ", ".join(json.dumps(value) for value in measurements)
            + f"].exists(d, assertion.{measurement_claim} == d)"
        )

    return " && ".join(clauses)


def build_provider_command(
    manifest: WeightCustodyManifest,
    *,
    project_number: str,
    pool: str,
    provider: str,
    condition: str,
    issuer: str = "https://confidentialcomputing.googleapis.com/",
) -> str:
    """The gcloud invocation that installs the condition, with a header comment."""
    if not project_number.isdigit():
        raise ConfidentialSpaceError(
            "project_number must be the numeric project number, not the project id: "
            "workload identity pool resource names use the number"
        )
    for label, value in (("pool", pool), ("provider", provider)):
        if not re.match(r"^[a-z][a-z0-9-]{3,31}$", value or ""):
            raise ConfidentialSpaceError(f"{label} {value!r} is not a valid resource id")

    unbound = "assertion." + IMAGE_DIGEST_CLAIM not in condition and IMAGE_DIGEST_CLAIM not in condition
    lines = [
        "# Generated from a Weight Custody Manifest. Do not hand-edit: regenerate.",
        f"# Weights: {manifest.weights_hash}",
        f"# Builder: {manifest.builder.identity}",
        "#",
        "# The manifest's accepted_measurements are compared against",
        f"# {IMAGE_DIGEST_CLAIM}, an OCI image digest. If this manifest's",
        "# measurements were computed some other way, this condition never matches.",
    ]
    if unbound:
        lines += [
            "#",
            "# WARNING: no workload measurement clause was generated. Any Confidential",
            "# Space workload meeting the platform conditions can assume this identity.",
        ]
    lines += [
        "",
        "gcloud iam workload-identity-pools providers update-oidc \\",
        f"  {provider} \\",
        f"  --location=global --workload-identity-pool={pool} \\",
        f"  --issuer-uri={issuer} \\",
        f"  --project={project_number} \\",
        f"  --attribute-condition={json.dumps(condition)}",
    ]
    return "\n".join(lines) + "\n"


def evidence_from_cs_claims(
    claims: Mapping[str, Any],
    challenge: Challenge,
    *,
    serving_image_measurement: str | None = None,
    transport_public_key: str | None = None,
) -> CompositeEvidence:
    """Map an already-verified Confidential Space token into WCM evidence.

    **Verify the token first.** This takes a claims mapping, not a JWT, so it
    cannot be mistaken for a verifier: no signature check, no JWKS fetch, no
    issuer validation. Unverified claims here produce evidence that looks
    hardware-attested and is not.

    ``serving_image_measurement`` defaults to the token's own image digest, which
    is correct when the manifest binds image digests. Pass it explicitly when it
    does not.
    """
    if claims.get("swname") != "CONFIDENTIAL_SPACE":
        raise ConfidentialSpaceError(
            f"swname is {claims.get('swname')!r}, not CONFIDENTIAL_SPACE. This token did "
            "not come from a Confidential Space workload."
        )
    hwmodel = claims.get("hwmodel")
    platform = next(
        (wcm_platform for wcm_platform, model in HWMODEL_BY_PLATFORM.items() if model == hwmodel),
        None,
    )
    if platform is None:
        raise ConfidentialSpaceError(
            f"hwmodel {hwmodel!r} does not map to a WCM platform. Confirm what your "
            "tokens carry with --print-claims and override HWMODEL_BY_PLATFORM rather "
            "than building evidence naming a platform WCM cannot verify against."
        )
    if claims.get("dbgstat") != "disabled-since-boot":
        raise ConfidentialSpaceError(
            f"dbgstat is {claims.get('dbgstat')!r}. A guest that was debuggable at any "
            "point since boot may have been inspected, so this does not support a "
            "hardware-attested assurance tier."
        )

    digest = serving_image_measurement
    if digest is None:
        submods = claims.get("submods") or {}
        container = submods.get("container") if isinstance(submods, dict) else None
        digest = (container or {}).get("image_digest")
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        raise ConfidentialSpaceError(
            "no usable serving image measurement: the token's image_digest is absent or "
            "malformed and none was supplied"
        )

    return CompositeEvidence(
        cpu=CpuQuote(
            platform=platform,
            assurance_tier=AssuranceTier.hardware_attested.value,
            serving_image_measurement=digest,
            nonce_echo=challenge.nonce,
            attestation_key_id=str(claims.get("iss", "confidential-space-token")),
            transport_public_key=transport_public_key,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WCM manifest -> GCP Confidential Space attribute condition"
    )
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--project-number")
    parser.add_argument("--pool")
    parser.add_argument("--provider")
    parser.add_argument("--measurement-claim", default=IMAGE_DIGEST_CLAIM)
    parser.add_argument("--support-attribute", default="STABLE", choices=SUPPORT_ATTRIBUTES)
    parser.add_argument("--allow-debuggable", action="store_true")
    parser.add_argument("--allow-unbound-workload", action="store_true")
    parser.add_argument("--condition-only", action="store_true")
    parser.add_argument(
        "--print-claims",
        type=pathlib.Path,
        help="print the claims of a Confidential Space token payload file and exit",
    )
    args = parser.parse_args(argv)

    if args.print_claims:
        print(json.dumps(json.loads(args.print_claims.read_text(encoding="utf-8")), indent=2, sort_keys=True))
        return 0

    manifest = WeightCustodyManifest.model_validate_json(
        args.manifest.read_text(encoding="utf-8")
    )
    try:
        condition = build_attribute_condition(
            manifest,
            measurement_claim=args.measurement_claim,
            support_attribute=args.support_attribute,
            require_debug_disabled=not args.allow_debuggable,
            allow_unbound_workload=args.allow_unbound_workload,
        )
        if args.condition_only:
            print(condition)
            return 0
        if not (args.project_number and args.pool and args.provider):
            print(
                "error: --project-number, --pool and --provider are required unless "
                "--condition-only is given",
                file=sys.stderr,
            )
            return 1
        sys.stdout.write(
            build_provider_command(
                manifest,
                project_number=args.project_number,
                pool=args.pool,
                provider=args.provider,
                condition=condition,
            )
        )
    except ConfidentialSpaceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.allow_unbound_workload:
        print(
            "warning: this condition binds the platform only. Any Confidential Space "
            "workload meeting it can assume the identity that decrypts these weights.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
