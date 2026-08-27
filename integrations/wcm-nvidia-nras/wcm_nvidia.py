#!/usr/bin/env python3
"""NVIDIA GPU attestation -> WCM ``GpuReport``.

Turns ``nvattest`` output into the GPU half of a WCM ``CompositeEvidence``, so a
manifest requiring ``required_gpu_measurement`` can actually be satisfied by a
confidential-compute GPU.

**Two appraisals, deliberately.** This is the design point worth understanding
before using it.

NVIDIA's appraisal (local verifier, or the remote attestation service) checks
what only NVIDIA can: that the driver and VBIOS RIMs fetched from NVIDIA match
the reference measurements, that the certificate chain is live and its OCSP
status is good, that the report signature verifies, and that the nonce binds.
That is a rich appraisal against NVIDIA's own reference data.

WCM then independently verifies the raw report's certificate chain, signature
and nonce through ``wcm.nvidia``. The raw evidence is carried through in
``quote_b64`` precisely so that second check has something to check.

Neither replaces the other. Trusting only NVIDIA's appraisal means trusting a
JWT that this process parsed; trusting only WCM's means losing the RIM
comparison, which is the part that says the GPU is running firmware NVIDIA
published. The adapter's job is to refuse unless the first passed, and to hand
the second its input intact.

**The measurement is an identity, not a hash.** ``required_gpu_measurement.rim_pin``
is a free-form string in WCM, not a ``HashValue``, and this emits
``nvidia-rim:arch=<arch>;driver=<version>;vbios=<version>``. That is deliberate:
what a manifest wants to pin on the GPU side is the firmware identity NVIDIA
appraised, and there is no single digest that means "this driver and this VBIOS
both matched their RIMs". A digest would look stronger and say less.

**Every claim below came from a live capture.** The required-true list and the
certificate claim shapes are those a real H100 in CC mode produced under
``nvattest --verifier local``. A claim NVIDIA renames will make this fail
closed, which is the correct direction.

Usage::

    pip install weight-custody-manifest

    nvattest --format=json collect-evidence --device gpu --nonce $NONCE > evidence.json
    nvattest --format=json attest --device gpu --verifier local --nonce $NONCE > appraisal.json
    python wcm_nvidia.py --nonce $NONCE --evidence evidence.json --appraisal appraisal.json
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import pathlib
import sys
from typing import Any, Sequence

from wcm import GpuReport

__all__ = [
    "GPU_PLATFORM",
    "REQUIRED_TRUE_CLAIMS",
    "CERT_CHAIN_CLAIMS",
    "NvidiaAttestationError",
    "adapt",
    "rim_pin",
]

#: The platform string WCM expects for a confidential-compute NVIDIA GPU.
GPU_PLATFORM = "nvidia-cc-gpu"

#: Appraisal claims that must be exactly ``True``.
#:
#: Read from a live H100 capture under ``nvattest --verifier local``. Absent or
#: false is a refusal, not a warning: each of these is a link in the chain from
#: "a GPU produced a report" to "NVIDIA's published reference measurements match
#: what this GPU is running".
REQUIRED_TRUE_CLAIMS = (
    "secboot",
    "x-nvidia-gpu-arch-check",
    "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
    "x-nvidia-gpu-attestation-report-nonce-match",
    "x-nvidia-gpu-attestation-report-parsed",
    "x-nvidia-gpu-attestation-report-signature-verified",
    "x-nvidia-gpu-driver-rim-fetched",
    "x-nvidia-gpu-driver-rim-measurements-available",
    "x-nvidia-gpu-driver-rim-signature-verified",
    "x-nvidia-gpu-driver-rim-version-match",
    "x-nvidia-gpu-vbios-index-no-conflict",
    "x-nvidia-gpu-vbios-rim-fetched",
    "x-nvidia-gpu-vbios-rim-measurements-available",
    "x-nvidia-gpu-vbios-rim-signature-verified",
    "x-nvidia-gpu-vbios-rim-version-match",
)

#: Claims holding a certificate-chain appraisal, each checked for live OCSP.
CERT_CHAIN_CLAIMS = (
    "x-nvidia-gpu-attestation-report-cert-chain",
    "x-nvidia-gpu-driver-rim-cert-chain",
    "x-nvidia-gpu-vbios-rim-cert-chain",
)


class NvidiaAttestationError(RuntimeError):
    """Raised rather than emitting evidence that would verify against nothing."""


def _jwt_payload(token: str) -> dict[str, Any]:
    """Decode a JWT payload without verifying it.

    The signature is NVIDIA's to check, and the appraisal document is the output
    of a verifier that already did. Decoding here is parsing, not trust, and
    every value taken from it is then required to have passed that verifier.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        value = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
        raise NvidiaAttestationError(f"unparseable NVIDIA appraisal token: {exc}") from exc
    if not isinstance(value, dict):
        raise NvidiaAttestationError("NVIDIA appraisal token payload is not an object")
    return value


def _gpu_claims(appraisal: dict[str, Any]) -> dict[str, Any]:
    if appraisal.get("result_code") != 0:
        raise NvidiaAttestationError(
            f"NVIDIA appraisal failed: {appraisal.get('result_message', 'unknown')}"
        )
    detached = appraisal.get("detached_eat")
    try:
        overall = _jwt_payload(detached[0][1])
        gpu = _jwt_payload(detached[1]["GPU-0"])
    except (KeyError, IndexError, TypeError) as exc:
        raise NvidiaAttestationError(
            "NVIDIA appraisal is missing GPU-0 detached EAT claims"
        ) from exc
    if overall.get("x-nvidia-overall-att-result") is not True:
        raise NvidiaAttestationError("NVIDIA overall attestation result is not true")
    return gpu


def _require_cert_good(claims: dict[str, Any], name: str) -> None:
    """A valid certificate with a stale or absent OCSP response is not enough.

    Revocation is the reason this check exists: a GPU whose attestation
    certificate was revoked still presents a well-formed chain.
    """
    value = claims.get(name)
    if not isinstance(value, dict):
        raise NvidiaAttestationError(f"NVIDIA appraisal is missing {name}")
    for field in ("x-nvidia-cert-ocsp-nonce-matches", "x-nvidia-cert-ocsp-response-valid"):
        if value.get(field) is not True:
            raise NvidiaAttestationError(f"NVIDIA appraisal failed {field} in {name}")
    if value.get("x-nvidia-cert-status") != "valid":
        raise NvidiaAttestationError(f"NVIDIA certificate status is not valid in {name}")
    if value.get("x-nvidia-cert-ocsp-status") != "good":
        raise NvidiaAttestationError(f"NVIDIA OCSP status is not good in {name}")


def rim_pin(*, arch: str, driver_version: str, vbios_version: str) -> str:
    """The canonical ``required_gpu_measurement.rim_pin`` for an appraised GPU.

    Build a manifest's pin with this rather than by hand, so a manifest and an
    adapter cannot disagree about spacing or field order and produce a mismatch
    that reads as a firmware change.
    """
    for label, value in (("arch", arch), ("driver", driver_version), ("vbios", vbios_version)):
        if not isinstance(value, str) or not value or ";" in value or "=" in value:
            raise NvidiaAttestationError(
                f"{label} must be a non-empty string containing no ';' or '=': {value!r}"
            )
    return f"nvidia-rim:arch={arch};driver={driver_version};vbios={vbios_version}"


def adapt(
    evidence_doc: dict[str, Any],
    appraisal_doc: dict[str, Any],
    expected_nonce: str,
) -> GpuReport:
    """Build a ``GpuReport`` from a collected evidence document and its appraisal.

    ``expected_nonce`` is the WCM challenge nonce. It is checked against both
    documents independently: the collector records what it asked the GPU for, the
    appraisal records what the GPU echoed, and a mismatch on either means the
    evidence in hand describes a different challenge than the one being answered.
    Accepting it would make replay trivially easy.
    """
    if evidence_doc.get("result_code") != 0:
        raise NvidiaAttestationError(
            f"NVIDIA evidence collection failed: {evidence_doc.get('result_message', 'unknown')}"
        )
    evidences = evidence_doc.get("evidences")
    if not isinstance(evidences, list) or len(evidences) != 1:
        raise NvidiaAttestationError(
            "exactly one GPU evidence item is required. A multi-GPU host produces one "
            "report per device and a manifest pins one; adapting several into a single "
            "report would silently pick one and claim it covered them all."
        )
    evidence = evidences[0]
    if not isinstance(evidence, dict):
        raise NvidiaAttestationError("NVIDIA GPU evidence item is not an object")
    if evidence.get("nonce") != expected_nonce:
        raise NvidiaAttestationError(
            "collected evidence nonce does not match the WCM challenge"
        )

    claims = _gpu_claims(appraisal_doc)
    if claims.get("eat_nonce") != expected_nonce:
        raise NvidiaAttestationError("appraisal nonce does not match the WCM challenge")

    failed = [name for name in REQUIRED_TRUE_CLAIMS if claims.get(name) is not True]
    if failed:
        raise NvidiaAttestationError("NVIDIA appraisal checks failed: " + ", ".join(failed))
    if claims.get("x-nvidia-mismatch-measurement-records") is not None:
        raise NvidiaAttestationError(
            "NVIDIA appraisal reports mismatched measurement records: the GPU is not "
            "running the firmware whose RIMs were fetched"
        )
    for name in CERT_CHAIN_CLAIMS:
        _require_cert_good(claims, name)

    arch = evidence.get("arch")
    driver = claims.get("x-nvidia-gpu-driver-version")
    vbios = claims.get("x-nvidia-gpu-vbios-version")
    if not all(isinstance(value, str) and value for value in (arch, driver, vbios)):
        raise NvidiaAttestationError("appraisal is missing arch, driver or VBIOS identity")

    try:
        cert_chain_pem = base64.b64decode(evidence["certificate"], validate=True).decode()
        base64.b64decode(evidence["evidence"], validate=True)
    except (KeyError, ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise NvidiaAttestationError(f"raw GPU evidence is malformed: {exc}") from exc

    # The container WCM's own verifier reads. Carrying the raw report and its
    # chain through is the whole point: without them, WCM has nothing to check
    # independently and the record rests entirely on this process having parsed
    # a JWT correctly.
    container = json.dumps(
        {"report_b64": evidence["evidence"], "cert_chain_pem": cert_chain_pem},
        separators=(",", ":"),
    )

    return GpuReport(
        platform=GPU_PLATFORM,
        measurement=rim_pin(arch=arch, driver_version=driver, vbios_version=vbios),
        cc_mode=True,
        nonce_echo=expected_nonce,
        quote_b64=base64.b64encode(container.encode()).decode(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NVIDIA nvattest output -> WCM GpuReport")
    parser.add_argument("--nonce", required=True, help="the WCM challenge nonce, 64 hex characters")
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--appraisal", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)

    if len(args.nonce) != 64:
        print("error: --nonce must be exactly 32 bytes of hex", file=sys.stderr)
        return 1
    try:
        bytes.fromhex(args.nonce)
    except ValueError:
        print("error: --nonce is not hex", file=sys.stderr)
        return 1

    try:
        report = adapt(
            json.loads(args.evidence.read_text(encoding="utf-8")),
            json.loads(args.appraisal.read_text(encoding="utf-8")),
            args.nonce,
        )
    except NvidiaAttestationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(report.model_dump_json(indent=2, exclude_none=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
