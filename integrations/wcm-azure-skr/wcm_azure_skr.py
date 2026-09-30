#!/usr/bin/env python3
"""Weight Custody Manifest -> Azure Managed HSM Secure Key Release policy.

Azure Secure Key Release is the same shape as WCM Layer 2: a key marked
exportable carries a release policy; a confidential VM obtains an attestation
token from Microsoft Azure Attestation; Key Vault checks the token's claims
against that policy and returns the key wrapped to the TEE's public key. Nobody
who cannot produce a conforming token gets the key.

So a WCM ``release_policy`` and an SKR release policy are two encodings of one
intent, and this translates between them. It also maps a **verified** MAA claim
set into ``CompositeEvidence`` so the WCM broker's own checks can run over the
same attestation.

**The measurement mapping is the hard part, and this module will not guess it.**

WCM's ``HashValue`` is strictly 256-bit: ``sha256:<64 hex>`` or
``shake256:<64 hex>``. An SEV-SNP launch measurement is 384-bit, 96 hex
characters, and MAA reports it as ``x-ms-sevsnpvm-launchmeasurement``. A WCM
``accepted_measurements`` entry therefore *cannot* be an SNP launch measurement:
it will not fit the type. On Azure the WCM path binds a SHA-256 PCR 23 digest
instead (see ``wcm.azure_vtpm``), which is a different value produced by a
different chain.

Emitting ``x-ms-sevsnpvm-launchmeasurement equals <a 64-hex WCM measurement>``
would produce a policy that never matches, and an engineer debugging it would
reasonably conclude the CVM was broken. Worse, the plausible "fix" is to widen
the manifest's measurement field, which breaks the binding WCM's own broker
relies on.

``build_release_policy`` therefore requires ``measurement_claim`` naming which
MAA claim carries the value the manifest's measurements hold, and refuses to
emit a measurement condition without it. Pass ``allow_unbound_workload=True`` to
get the platform conditions alone; the returned policy is then annotated as not
binding a workload, and the CLI prints that to stderr.

**Claims used, and where they come from.** Every claim is one Microsoft
documents for MAA. SEV-SNP claims are from the MAA claim sets page
(https://learn.microsoft.com/azure/attestation/claim-sets). TDX claims are from
the MAA TDX EAT profile
(https://learn.microsoft.com/azure/attestation/trust-domain-extensions-eat-profile)
and its ``tdxvm`` sample token
(https://learn.microsoft.com/azure/attestation/attestation-token-examples).

**Each branch carries only claims of its own TEE.** A token has one
``x-ms-attestation-type``; MAA issues ``x-ms-sevsnpvm-*`` claims only on a
``sevsnpvm`` token and ``tdx_*`` claims only on a ``tdxvm`` token. A condition
naming the other TEE's claim is never met, so a branch mixing them never
matches. The debug gate is therefore per branch: ``x-ms-sevsnpvm-is-debuggable``
on SNP, ``tdx_td_attributes_debug`` on TDX.

Usage::

    pip install weight-custody-manifest

    python wcm_azure_skr.py manifest.json \\
        --measurement-claim x-ms-sevsnpvm-hostdata \\
        --authority https://sharedeus.eus.attest.azure.net > skr-policy.json

    az keyvault key create --exportable true --policy skr-policy.json ...
"""

from __future__ import annotations

import argparse
import json
import pathlib
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
    "ATTESTATION_TYPE_BY_PLATFORM",
    "MAA_CLAIMS",
    "DEBUG_CLAIM_BY_ATTESTATION_TYPE",
    "SKR_POLICY_VERSION",
    "SkrPolicyError",
    "build_release_policy",
    "evidence_from_maa_claims",
]

SKR_POLICY_VERSION = "1.0.0"

#: WCM platform -> the value MAA reports in ``x-ms-attestation-type``.
ATTESTATION_TYPE_BY_PLATFORM = {
    "amd-sev-snp": "sevsnpvm",
    "intel-tdx": "tdxvm",
    # nvidia-cc-gpu is a GPU evidence chain. MAA's CVM attestation type describes
    # the virtual machine, and there is no attestation-type value that means "the
    # GPU is in CC mode". GPU binding stays with the WCM broker's GPU check.
}

#: MAA claims this module reads or emits, with what each one is.
#:
#: Restricted to CVM claims Microsoft documents (see the module docstring for the
#: pages). A claim not listed here is refused, because a policy referencing a
#: claim MAA does not issue never matches and presents as a broken CVM.
MAA_CLAIMS = {
    "x-ms-attestation-type": "sevsnpvm or tdxvm; which TEE produced the token",
    "x-ms-compliance-status": "azure-compliant-cvm when the platform met Azure's CVM baseline",
    "x-ms-sevsnpvm-is-debuggable": "true when the guest was launched debuggable",
    "x-ms-sevsnpvm-launchmeasurement": "384-bit SNP launch measurement, 96 hex characters",
    "x-ms-sevsnpvm-hostdata": "256-bit host-supplied data, 64 hex characters",
    "x-ms-sevsnpvm-idkeydigest": "digest of the key that signed the guest's ID block",
    "x-ms-sevsnpvm-guestsvn": "guest security version number",
    "tdx_td_attributes_debug": "true when the TD runs in TD debug mode (host VMM can read it)",
    "tdx_mrtd": "384-bit measurement of the TD's initial contents, 96 hex characters",
    "tdx_rtmr0": "384-bit runtime measurement register 0, 96 hex characters",
    "tdx_rtmr1": "384-bit runtime measurement register 1, 96 hex characters",
    "tdx_rtmr2": "384-bit runtime measurement register 2, 96 hex characters",
    "tdx_rtmr3": "384-bit runtime measurement register 3, 96 hex characters",
    "tdx_mrconfigid": "384-bit software-defined configuration ID, 96 hex characters",
    "tdx_mrowner": "384-bit software-defined owner ID, 96 hex characters",
    "tdx_mrownerconfig": "384-bit owner-defined configuration ID, 96 hex characters",
    "tdx_report_data": "512-bit TD report data, 128 hex characters",
}

#: Attestation type -> the claim that says the guest was launched debuggable.
#: SNP: MAA claim sets page. TDX: MAA TDX EAT profile; the tdxvm sample token on
#: the token examples page carries ``"tdx_td_attributes_debug": false``.
DEBUG_CLAIM_BY_ATTESTATION_TYPE = {
    "sevsnpvm": "x-ms-sevsnpvm-is-debuggable",
    "tdxvm": "tdx_td_attributes_debug",
}

#: Claim-name prefix -> the only attestation type whose tokens carry it.
_TEE_CLAIM_PREFIX = {
    "x-ms-sevsnpvm-": "sevsnpvm",
    "tdx_": "tdxvm",
}


def _claim_tee(claim: str) -> str | None:
    """The attestation type a claim belongs to, or None if it is TEE-neutral."""
    for prefix, attestation_type in _TEE_CLAIM_PREFIX.items():
        if claim.startswith(prefix):
            return attestation_type
    return None

#: Claims whose width makes them incompatible with a WCM HashValue, and why.
#: build_release_policy checks this before emitting a condition, so the failure
#: arrives at generation time rather than as a policy that never matches.
_CLAIM_HEX_WIDTH = {
    "x-ms-sevsnpvm-launchmeasurement": 96,
    "x-ms-sevsnpvm-hostdata": 64,
    "x-ms-sevsnpvm-idkeydigest": 96,
    "tdx_mrtd": 96,
    "tdx_rtmr0": 96,
    "tdx_rtmr1": 96,
    "tdx_rtmr2": 96,
    "tdx_rtmr3": 96,
    "tdx_mrconfigid": 96,
    "tdx_mrowner": 96,
    "tdx_mrownerconfig": 96,
    "tdx_report_data": 128,
}


def _token_nonce(claims: Mapping[str, Any], expected: str) -> str:
    """Return the nonce the MAA token carries, after checking it is ``expected``.

    The nonce can arrive top level or inside ``x-ms-runtime``. Every place it is
    present must match, and at least one must be present. Copying the verifier's
    own challenge into ``nonce_echo`` instead would make a stale token look fresh.
    """
    runtime = claims.get("x-ms-runtime")
    found = [claims.get("nonce")]
    if isinstance(runtime, Mapping):
        found.append(runtime.get("nonce"))
    found = [value for value in found if value is not None]
    if not found:
        raise SkrPolicyError(
            "the MAA token carries no nonce, so nothing binds it to this challenge. "
            "Pass the challenge nonce to the attestation request."
        )
    if any(value != expected for value in found):
        raise SkrPolicyError(
            "the MAA token's nonce does not match this challenge, so the token was "
            "not produced for this request"
        )
    return expected


class SkrPolicyError(ValueError):
    """Raised when a manifest cannot be translated into a usable SKR policy."""


def _usable_measurements(manifest: WeightCustodyManifest) -> list[str]:
    """Accepted measurements a key should still be released under.

    ``revoked`` is excluded outright. ``retiring`` is included: WCM's release
    rule is prefer-current rather than refuse-retiring, and a policy that dropped
    retiring images would take a fleet offline during a rollover, which is the
    opposite of what the status means.
    """
    serving = manifest.release_policy.required_serving_image
    return [
        entry.measurement
        for entry in serving.accepted_measurements
        if entry.status is not ServingImageStatus.revoked
    ]


def _measurement_claims_by_type(
    measurement_claim: str | Mapping[str, str], attestation_types: Sequence[str]
) -> dict[str, str]:
    """Resolve ``measurement_claim`` to one claim per attestation type, or refuse."""
    if isinstance(measurement_claim, str):
        requested = {attestation_type: measurement_claim for attestation_type in attestation_types}
    else:
        requested = dict(measurement_claim)
        unknown = sorted(set(requested) - set(DEBUG_CLAIM_BY_ATTESTATION_TYPE))
        if unknown:
            raise SkrPolicyError(
                f"measurement_claim keys {unknown} are not MAA attestation types; use "
                f"{sorted(DEBUG_CLAIM_BY_ATTESTATION_TYPE)}"
            )
    resolved: dict[str, str] = {}
    for attestation_type in attestation_types:
        claim = requested.get(attestation_type)
        if claim is None:
            raise SkrPolicyError(
                f"no measurement_claim for {attestation_type}. The manifest allows it, and "
                "a branch without a measurement condition would release the key to any "
                "compliant CVM of that type. Pass a mapping with a claim for every "
                "attestation type."
            )
        if claim not in MAA_CLAIMS:
            raise SkrPolicyError(
                f"{claim!r} is not in MAA_CLAIMS. A policy referencing a "
                "claim MAA does not issue never matches, and presents as a broken CVM "
                "rather than as a policy error. Add it to MAA_CLAIMS with a description "
                "once you have confirmed Azure issues it."
            )
        tee = _claim_tee(claim)
        if tee is not None and tee != attestation_type:
            raise SkrPolicyError(
                f"{claim} is only issued on {tee} tokens, so it can never match on the "
                f"{attestation_type} branch this manifest requires. Pass a mapping from "
                "attestation type to a claim of that type."
            )
        resolved[attestation_type] = claim
    return resolved


def _check_measurement_width(claim: str, measurements: Sequence[str]) -> None:
    width = _CLAIM_HEX_WIDTH.get(claim)
    for measurement in measurements:
        digest = measurement.split(":", 1)[1]
        if width is not None and len(digest) != width:
            raise SkrPolicyError(
                f"measurement {measurement} has {len(digest)} hex characters but "
                f"{claim} carries {width}. These are values from "
                "different chains; comparing them would produce a policy that "
                "never matches. On Azure the WCM path binds a SHA-256 PCR 23 "
                "digest (see wcm.azure_vtpm), which is not the SNP launch "
                "measurement."
            )


def build_release_policy(
    manifest: WeightCustodyManifest,
    *,
    authority: str,
    measurement_claim: str | Mapping[str, str] | None = None,
    allow_unbound_workload: bool = False,
    require_not_debuggable: bool = True,
) -> dict[str, Any]:
    """Translate a WCM release policy into an Azure SKR release policy.

    ``authority`` is the MAA endpoint whose tokens are accepted, for example
    ``https://sharedeus.eus.attest.azure.net``. It is required: an SKR policy
    with no authority accepts a token from any attestation service, including one
    an attacker stood up.

    ``measurement_claim`` names the MAA claim carrying the value the manifest's
    ``accepted_measurements`` hold. See the module docstring for why this cannot
    be inferred. When the manifest allows more than one TEE, pass a mapping from
    attestation type (``sevsnpvm``, ``tdxvm``) to claim: a TEE-specific claim
    such as ``x-ms-sevsnpvm-hostdata`` is only issued on that TEE's tokens, so it
    cannot bind the other TEE's branch.
    """
    if not authority.startswith("https://"):
        raise SkrPolicyError(
            f"authority {authority!r} must be an https MAA endpoint. A release policy "
            "without a pinned authority accepts tokens from any attestation service."
        )

    platforms = list(manifest.release_policy.required_hw_platform)
    attestation_types = [
        ATTESTATION_TYPE_BY_PLATFORM[platform]
        for platform in platforms
        if platform in ATTESTATION_TYPE_BY_PLATFORM
    ]
    if not attestation_types:
        raise SkrPolicyError(
            f"none of {platforms} maps to an MAA attestation type. SKR gates on the "
            "CVM's attestation token; a GPU-only requirement has no attestation-type "
            "value and stays with the WCM broker's GPU check."
        )

    measurements = _usable_measurements(manifest)
    if measurement_claim is None:
        if not allow_unbound_workload:
            raise SkrPolicyError(
                "measurement_claim is required. A WCM HashValue is 256-bit "
                "(sha256:<64 hex>), while x-ms-sevsnpvm-launchmeasurement is 384-bit, "
                "so the two cannot be compared and no mapping can be inferred. Name the "
                "MAA claim your manifest's measurements were computed against, or pass "
                "allow_unbound_workload=True to emit platform conditions only and "
                "accept that any compliant CVM in this authority can obtain the key."
            )
        claim_by_type: dict[str, str] = {}
    else:
        claim_by_type = _measurement_claims_by_type(measurement_claim, attestation_types)
        for claim in dict.fromkeys(claim_by_type.values()):
            _check_measurement_width(claim, measurements)

    branches: list[dict[str, Any]] = []
    for attestation_type in attestation_types:
        # Built from this branch's own attestation type. Deriving any of it from
        # attestation_types[0] made the debug gate depend on the order of
        # required_hw_platform and put SNP-only claims on TDX branches.
        conditions: list[dict[str, Any]] = [
            {"claim": "x-ms-attestation-type", "equals": attestation_type}
        ]
        if manifest.release_policy.required_assurance_tier is AssuranceTier.hardware_attested:
            conditions.append({"claim": "x-ms-compliance-status", "equals": "azure-compliant-cvm"})
        if require_not_debuggable:
            # A debuggable guest can be inspected by the host, which defeats the
            # software-adversary half of WCM's guarantee before any key moves.
            conditions.append(
                {"claim": DEBUG_CLAIM_BY_ATTESTATION_TYPE[attestation_type], "equals": "false"}
            )
        if measurement_claim is None:
            branches.append({"authority": authority, "allOf": conditions})
            continue
        claim = claim_by_type[attestation_type]
        # One branch per accepted measurement: SKR's grammar has anyOf at the
        # branch level and allOf inside, with no disjunction over a single claim.
        for measurement in measurements:
            branches.append(
                {
                    "authority": authority,
                    "allOf": conditions
                    + [{"claim": claim, "equals": measurement.split(":", 1)[1]}],
                }
            )

    policy: dict[str, Any] = {"version": SKR_POLICY_VERSION, "anyOf": branches}
    if measurement_claim is None:
        # Not a policy field Azure reads. It is here so the intent survives in
        # whatever repository or ticket this document ends up in.
        policy["x-wcm-note"] = (
            "This policy binds the platform only. No workload measurement condition "
            "was emitted, so any compliant CVM attesting to this authority can obtain "
            "the key. The manifest's accepted_measurements are NOT enforced here; the "
            "WCM broker still checks them."
        )
    return policy


def evidence_from_maa_claims(
    claims: Mapping[str, Any],
    challenge: Challenge,
    *,
    serving_image_measurement: str,
    transport_public_key: str | None = None,
) -> CompositeEvidence:
    """Map an already-verified MAA claim set into WCM ``CompositeEvidence``.

    **The caller must have verified the token first.** This takes a claims
    mapping, not a JWT, precisely so it cannot be mistaken for a verifier: it
    performs no signature check, fetches no JWKS, and validates no issuer. Feeding
    it unverified claims produces evidence that looks hardware-attested and is
    not, which is the single worst outcome available in this file.

    ``serving_image_measurement`` is supplied rather than read from the claims for
    the reason in the module docstring: the value the manifest binds and the value
    MAA reports are from different chains, and only the deployment knows how its
    manifest was built.
    """
    attestation_type = claims.get("x-ms-attestation-type")
    platform = next(
        (
            wcm_platform
            for wcm_platform, maa_type in ATTESTATION_TYPE_BY_PLATFORM.items()
            if maa_type == attestation_type
        ),
        None,
    )
    if platform is None:
        raise SkrPolicyError(
            f"x-ms-attestation-type {attestation_type!r} does not map to a WCM platform. "
            "Evidence naming a platform WCM does not know would be verified against "
            "nothing."
        )
    if claims.get("x-ms-compliance-status") != "azure-compliant-cvm":
        raise SkrPolicyError(
            "x-ms-compliance-status is not azure-compliant-cvm. The platform did not "
            "meet Azure's CVM baseline, so this is not hardware-attested evidence and "
            "must not be built into a CompositeEvidence that says it is."
        )
    if str(claims.get(DEBUG_CLAIM_BY_ATTESTATION_TYPE[attestation_type], "false")).lower() == "true":
        raise SkrPolicyError(
            "the guest was launched debuggable, so the host can inspect it. Evidence "
            "from a debuggable guest does not support a hardware-attested assurance "
            "tier."
        )

    return CompositeEvidence(
        cpu=CpuQuote(
            platform=platform,
            assurance_tier=AssuranceTier.hardware_attested.value,
            serving_image_measurement=serving_image_measurement,
            nonce_echo=_token_nonce(claims, challenge.nonce),
            attestation_key_id=str(claims.get("x-ms-sevsnpvm-idkeydigest", "maa-token")),
            transport_public_key=transport_public_key,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WCM manifest -> Azure SKR release policy")
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--authority", required=True, help="MAA endpoint, https://...")
    parser.add_argument(
        "--measurement-claim",
        help="MAA claim carrying the manifest's accepted_measurements values",
    )
    parser.add_argument(
        "--allow-unbound-workload",
        action="store_true",
        help="emit platform conditions only, with no workload binding",
    )
    parser.add_argument("--allow-debuggable", action="store_true")
    parser.add_argument("--describe-claims", action="store_true")
    args = parser.parse_args(argv)

    if args.describe_claims:
        print(json.dumps(MAA_CLAIMS, indent=2, sort_keys=True))
        return 0

    manifest = WeightCustodyManifest.model_validate_json(
        args.manifest.read_text(encoding="utf-8")
    )
    try:
        policy = build_release_policy(
            manifest,
            authority=args.authority,
            measurement_claim=args.measurement_claim,
            allow_unbound_workload=args.allow_unbound_workload,
            require_not_debuggable=not args.allow_debuggable,
        )
    except SkrPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(policy, indent=2))
    if "x-wcm-note" in policy:
        print(
            "warning: this policy binds the platform only. Any compliant CVM attesting "
            "to this authority can obtain the key; accepted_measurements are enforced "
            "by the WCM broker, not by Key Vault.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
