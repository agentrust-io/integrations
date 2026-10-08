"""Adapter from cMCP attestation/appraisal objects to an AUCP appraisal result."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import BundleError, _digest, _sign, _verify_signed


class AttestationReportLike(Protocol):
    provider: str
    measurement: str
    report_data: str
    raw_evidence: bytes | None
    attestation_generated_at: datetime
    attestation_validity_seconds: int
    measurement_note: str | None


class AppraisalResultLike(Protocol):
    status: str
    verifier: str
    timestamp: str
    ear_raw: dict[str, Any]


@dataclass(frozen=True)
class AppraisalPolicy:
    policy_ref: str
    max_age_seconds: int = 300
    require_hardware: bool = False
    accepted_hardware_providers: tuple[str, ...] = (
        "sev-snp",
        "azure-cvm-sev-snp",
        "tdx",
        "tpm",
    )


def _workload_key_thumbprint(workload_key: str) -> bytes:
    try:
        key_bytes = bytes.fromhex(workload_key)
    except ValueError as exc:
        raise BundleError("workload key is not valid hex") from exc
    if len(key_bytes) != 32:
        raise BundleError("workload key must be a 32-byte Ed25519 public key")
    x = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode()
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).digest()


def _azure_imds_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise BundleError("Azure IMDS document timestamp is missing")
    try:
        return datetime.strptime(value, "%m/%d/%y %H:%M:%S %z")
    except ValueError as exc:
        raise BundleError("Azure IMDS document timestamp is malformed") from exc


def make_placement_assertion(
    *,
    workload_key: str,
    jurisdiction: str,
    operator: str,
    issued_at: datetime,
    validity_seconds: int,
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Create accountable placement evidence, explicitly separate from hardware."""
    return _sign(
        {
            "type": "auc:OperatorPlacementAssertion",
            "workload_key": workload_key,
            "jurisdiction": jurisdiction,
            "operator": operator,
            "issued_at": int(issued_at.timestamp()),
            "expires_at": int(issued_at.timestamp()) + validity_seconds,
            "evidence_basis": "operator-asserted-placement",
        },
        signing_key,
    )


def make_azure_placement_assertion(
    *,
    workload_key: str,
    imds_document: dict[str, Any],
    arm_resource: dict[str, Any],
    region_jurisdictions: dict[str, str],
    observed_at: datetime,
    validity_seconds: int,
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Join verified Azure IMDS identity to ARM placement and derive jurisdiction."""
    _workload_key_thumbprint(workload_key)
    nonce = imds_document.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != 10 or not nonce.isdigit():
        raise BundleError("Azure IMDS document has no valid 10-digit challenge")
    vm_id = imds_document.get("vmId")
    subscription_id = imds_document.get("subscriptionId")
    try:
        vm_id = str(UUID(str(vm_id)))
        subscription_id = str(UUID(str(subscription_id)))
    except ValueError as exc:
        raise BundleError("Azure IMDS identity is malformed") from exc

    arm_vm_id = arm_resource.get("properties", {}).get("vmId")
    if not isinstance(arm_vm_id, str) or arm_vm_id.lower() != vm_id.lower():
        raise BundleError("Azure ARM resource does not match the attested VM ID")
    resource_id = arm_resource.get("id")
    if not isinstance(resource_id, str) or (
        f"/subscriptions/{subscription_id}/" not in resource_id.lower()
    ):
        raise BundleError("Azure ARM resource does not match the attested subscription")
    if str(arm_resource.get("type", "")).lower() != "microsoft.compute/virtualmachines":
        raise BundleError("Azure ARM resource is not a virtual machine")
    region = arm_resource.get("location")
    if not isinstance(region, str) or region.lower() not in region_jurisdictions:
        raise BundleError("Azure region has no approved jurisdiction mapping")
    jurisdiction = region_jurisdictions[region.lower()]
    timestamps = imds_document.get("timeStamp", {})
    created_at = _azure_imds_time(timestamps.get("createdOn"))
    expires_at = _azure_imds_time(timestamps.get("expiresOn"))
    if observed_at.tzinfo is None or not created_at <= observed_at <= expires_at:
        raise BundleError("Azure IMDS document is stale or from the future")
    assertion_expiry = min(
        int(observed_at.timestamp()) + validity_seconds,
        int(expires_at.timestamp()),
    )
    return _sign(
        {
            "type": "auc:AzureControlPlanePlacementAssertion",
            "workload_key": workload_key,
            "cloud": "Azure",
            "azure_region": region.lower(),
            "jurisdiction": jurisdiction,
            "subscription_id": subscription_id.lower(),
            "vm_id": vm_id.lower(),
            "resource_id": resource_id.lower(),
            "imds_nonce": nonce,
            "issued_at": int(observed_at.timestamp()),
            "expires_at": assertion_expiry,
            "evidence_basis": "azure-attested-imds+arm-control-plane",
            "imds_document_hash": _digest(imds_document),
            "arm_resource_hash": _digest(arm_resource),
            "jurisdiction_mapping": "urn:agentrust:azure-region-jurisdiction:v1",
        },
        signing_key,
    )


def make_gcp_placement_assertion(
    *,
    workload_key: str,
    token: str,
    verified_claims: dict[str, Any],
    zone_jurisdictions: dict[str, str],
    observed_at: datetime,
    validity_seconds: int,
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Derive placement from a separately verified Confidential Space token.

    The token's TDX claims establish workload identity. Jurisdiction remains a
    relying-party interpretation of Google's signed GCE zone claim.
    """
    _workload_key_thumbprint(workload_key)
    if observed_at.tzinfo is None:
        raise BundleError("GCP observation timestamp must be timezone-aware")
    gce = verified_claims.get("submods", {}).get("gce", {})
    container = verified_claims.get("submods", {}).get("container", {})
    zone = gce.get("zone")
    if not isinstance(zone, str) or zone.lower() not in zone_jurisdictions:
        raise BundleError("GCP zone has no approved jurisdiction mapping")
    if verified_claims.get("swname") != "CONFIDENTIAL_SPACE":
        raise BundleError("GCP token is not for Confidential Space")
    if verified_claims.get("hwmodel") != "GCP_INTEL_TDX":
        raise BundleError("GCP token does not assert Intel TDX")
    if verified_claims.get("secboot") is not True:
        raise BundleError("GCP token does not assert Secure Boot")
    if verified_claims.get("dbgstat") != "disabled-since-boot":
        raise BundleError("GCP Confidential Space debug mode is not allowed")
    issued_at = verified_claims.get("iat")
    expires_at = verified_claims.get("exp")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise BundleError("GCP token validity window is malformed")
    observed_epoch = int(observed_at.timestamp())
    if not issued_at <= observed_epoch <= expires_at:
        raise BundleError("GCP token is stale or from the future")
    image_digest = container.get("image_digest")
    project_id = gce.get("project_id")
    instance_id = gce.get("instance_id")
    if not all(isinstance(value, str) and value for value in (image_digest, project_id)):
        raise BundleError("GCP workload identity claims are incomplete")
    if not isinstance(instance_id, str | int):
        raise BundleError("GCP instance identity claim is missing")

    return _sign(
        {
            "type": "auc:GcpConfidentialSpacePlacementAssertion",
            "workload_key": workload_key,
            "cloud": "GCP",
            "gcp_zone": zone.lower(),
            "jurisdiction": zone_jurisdictions[zone.lower()],
            "project_id": project_id,
            "instance_id": str(instance_id),
            "container_image_digest": image_digest,
            "attestation_token_hash": "sha256:" + hashlib.sha256(token.encode()).hexdigest(),
            "issued_at": observed_epoch,
            "expires_at": min(observed_epoch + validity_seconds, expires_at),
            "evidence_basis": "gcp-confidential-space-attested-zone",
            "jurisdiction_mapping": "urn:agentrust:gcp-zone-jurisdiction:v1",
        },
        signing_key,
    )


def create_attestation_result(
    *,
    report: AttestationReportLike,
    appraisal: AppraisalResultLike,
    workload_key: str,
    placement_assertion: dict[str, Any],
    placement_trust_key: str,
    policy: AppraisalPolicy,
    verifier_signing_key: Ed25519PrivateKey,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate provider and placement inputs and emit a signed normalized result."""
    current = now or datetime.now(tz=UTC)
    _verify_signed(placement_assertion, placement_trust_key)
    if placement_assertion.get("workload_key") != workload_key:
        raise BundleError("placement assertion workload key does not match delegation leaf")
    now_epoch = int(current.timestamp())
    if (
        not placement_assertion.get("issued_at", 0)
        <= now_epoch
        <= placement_assertion.get("expires_at", 0)
    ):
        raise BundleError("placement assertion is not currently valid")

    generated = report.attestation_generated_at
    if generated.tzinfo is None:
        raise BundleError("attestation report timestamp must be timezone-aware")
    age = (current - generated).total_seconds()
    effective_validity = min(report.attestation_validity_seconds, policy.max_age_seconds)
    if age < 0 or age > effective_validity:
        raise BundleError("attestation report is stale or from the future")
    if appraisal.status == "contraindicated":
        raise BundleError("evidence appraisal is contraindicated")
    try:
        report_data = bytes.fromhex(report.report_data)
    except ValueError as exc:
        raise BundleError("attestation report_data is not valid hex") from exc
    if len(report_data) < 32 or report_data[:32] != _workload_key_thumbprint(workload_key):
        raise BundleError("attestation report does not bind the workload key")

    hardware = report.provider in policy.accepted_hardware_providers
    if hardware and (report.raw_evidence is None or appraisal.status != "affirming"):
        raise BundleError("hardware appraisal requires raw evidence and an affirming result")
    if policy.require_hardware and not hardware:
        raise BundleError("relying-party policy requires hardware-attested evidence")

    return _sign(
        {
            "type": "rats:AttestationResult",
            "result_id": "urn:sha256:"
            + _digest(
                {
                    "provider": report.provider,
                    "measurement": report.measurement,
                    "report_data": report.report_data,
                    "workload_key": workload_key,
                    "placement": _digest(placement_assertion),
                }
            ).split(":", 1)[1],
            "workload_key": workload_key,
            "jurisdiction": placement_assertion["jurisdiction"],
            "placement_assertion_hash": _digest(placement_assertion),
            "placement_evidence_basis": placement_assertion["evidence_basis"],
            "attestation": {
                "provider": report.provider,
                "measurement": report.measurement,
                "report_data": report.report_data,
                "raw_evidence_present": report.raw_evidence is not None,
                "generated_at": int(generated.timestamp()),
                "valid_until": int(generated.timestamp()) + effective_validity,
                "measurement_note": report.measurement_note,
            },
            "appraisal": {
                "status": appraisal.status,
                "verifier": appraisal.verifier,
                "policy_ref": policy.policy_ref,
                "ear_hash": _digest(appraisal.ear_raw),
            },
            "evaluated_at": now_epoch,
            "hardware_attested": hardware,
        },
        verifier_signing_key,
    )


def verify_attestation_result(
    result: dict[str, Any],
    *,
    verifier_trust_key: str,
    placement_assertion: dict[str, Any],
    placement_trust_key: str,
    workload_key: str,
    now: datetime | None = None,
) -> None:
    """Verify the normalized result, freshness, workload, and placement binding."""
    _verify_signed(result, verifier_trust_key)
    _verify_signed(placement_assertion, placement_trust_key)
    if result.get("workload_key") != workload_key:
        raise BundleError("attestation result workload key does not match delegation leaf")
    if placement_assertion.get("workload_key") != workload_key:
        raise BundleError("placement assertion workload key does not match delegation leaf")
    if result.get("placement_assertion_hash") != _digest(placement_assertion):
        raise BundleError("attestation result does not bind the placement assertion")
    if result.get("jurisdiction") != placement_assertion.get("jurisdiction"):
        raise BundleError("attestation result jurisdiction does not match placement assertion")
    current_epoch = int((now or datetime.now(tz=UTC)).timestamp())
    if current_epoch > result.get("attestation", {}).get("valid_until", 0):
        raise BundleError("attestation result is stale")
    if (
        not placement_assertion.get("issued_at", 0)
        <= current_epoch
        <= placement_assertion.get("expires_at", 0)
    ):
        raise BundleError("placement assertion is not currently valid")
    if result.get("placement_evidence_basis") != placement_assertion.get("evidence_basis"):
        raise BundleError("attestation result placement evidence basis does not match assertion")
    if str(result.get("placement_evidence_basis", "")).startswith("hardware"):
        raise BundleError("hardware attestation cannot be used as placement evidence")
