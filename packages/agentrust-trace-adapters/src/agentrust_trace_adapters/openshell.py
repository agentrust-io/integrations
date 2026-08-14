"""Build TRACE inputs from NVIDIA OpenShell evidence without upgrading its trust."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .builder import build_record
from .evidence import MissingEvidence, PolicyEvidence, SourceSystem, digest_bytes

__all__ = [
    "OpenShellEvidence",
    "build_openshell_record",
    "build_policy_bundle",
    "build_transcript",
]

_POLICY_FORMAT = "agentrust.openshell-policy-bundle.v1"
_TRANSCRIPT_FORMAT = "agentrust.openshell-transcript.v1"
_MODES = {"enforce", "advisory", "silent"}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _required_bytes(name: str, value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise MissingEvidence(f"{name} must contain the exact non-empty evidence bytes")
    return bytes(value)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _combined_mode(openshell_mode: str, acs_mode: str) -> str:
    for name, value in (("openshell_mode", openshell_mode), ("acs_mode", acs_mode)):
        if value not in _MODES:
            raise ValueError(f"{name} {value!r} is not one of {', '.join(sorted(_MODES))}")
    if "advisory" in (openshell_mode, acs_mode):
        return "advisory"
    if "silent" in (openshell_mode, acs_mode):
        return "silent"
    return "enforce"


def build_policy_bundle(
    *,
    openshell_policy: bytes,
    policy_revision: str,
    acs_manifest: bytes,
    openshell_mode: str = "enforce",
    acs_mode: str = "enforce",
) -> tuple[bytes, str]:
    """Return exact canonical bytes committing both enforcement layers."""
    policy = _required_bytes("openshell_policy", openshell_policy)
    manifest = _required_bytes("acs_manifest", acs_manifest)
    if not policy_revision or not policy_revision.strip():
        raise MissingEvidence("policy_revision is required to bind the effective OpenShell policy")
    mode = _combined_mode(openshell_mode, acs_mode)
    bundle = {
        "format": _POLICY_FORMAT,
        "openshell": {
            "content": _b64(policy),
            "content_sha256": digest_bytes(policy),
            "enforcement_mode": openshell_mode,
            "media_type": "application/yaml",
            "revision": policy_revision,
        },
        "agt_acs": {
            "content": _b64(manifest),
            "content_sha256": digest_bytes(manifest),
            "enforcement_mode": acs_mode,
            "media_type": "application/yaml",
        },
    }
    return _canonical_json(bundle), mode


def _parse_ocsf_jsonl(data: bytes) -> list[dict[str, Any]]:
    raw = _required_bytes("ocsf_jsonl", data)
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"OCSF JSONL line {line_number} is invalid JSON") from exc
        if not isinstance(event, dict):
            raise ValueError(f"OCSF JSONL line {line_number} must be a JSON object")
        for field in ("class_uid", "time", "metadata"):
            if field not in event:
                raise MissingEvidence(f"OCSF JSONL line {line_number} has no {field!r}")
        metadata = event["metadata"]
        if not isinstance(metadata, dict):
            raise ValueError(f"OCSF JSONL line {line_number} metadata must be an object")
        product = metadata.get("product", {})
        if not isinstance(product, dict):
            raise ValueError(
                f"OCSF JSONL line {line_number} metadata.product must be an object"
            )
        if product.get("vendor_name") != "NVIDIA" or "OpenShell" not in str(
            product.get("name", "")
        ):
            raise ValueError(f"OCSF JSONL line {line_number} is not OpenShell evidence")
        events.append(event)
    if not events:
        raise MissingEvidence("ocsf_jsonl contains no OpenShell events")
    return events


def build_transcript(
    *,
    sandbox_id: str,
    policy_bundle_hash: str,
    ocsf_jsonl: bytes,
    acs_decisions: Iterable[Mapping[str, Any]],
    capture_start: int,
    capture_end: int,
    capture_complete: bool,
) -> tuple[bytes, int]:
    """Build the canonical transcript and return its bytes and action count."""
    if not sandbox_id or not sandbox_id.strip():
        raise MissingEvidence("sandbox_id is required to correlate OpenShell and ACS evidence")
    if not capture_complete:
        raise MissingEvidence("capture is incomplete; refusing to present a partial log as a transcript")
    if capture_start < 0 or capture_end < capture_start:
        raise ValueError("capture_start and capture_end must be ordered Unix milliseconds")
    events = _parse_ocsf_jsonl(ocsf_jsonl)
    decisions = [dict(item) for item in acs_decisions]
    if any(not item for item in decisions):
        raise ValueError("ACS decisions must be non-empty mappings")
    transcript = {
        "format": _TRANSCRIPT_FORMAT,
        "sandbox_id": sandbox_id,
        "capture": {
            "complete": True,
            "end_ms": capture_end,
            "start_ms": capture_start,
            "source_sha256": "sha256:" + hashlib.sha256(ocsf_jsonl).hexdigest(),
        },
        "policy_bundle_hash": policy_bundle_hash,
        "acs_decisions": decisions,
        "ocsf_events": events,
    }
    return _canonical_json(transcript), len(decisions)


@dataclass(frozen=True)
class OpenShellEvidence:
    """Complete evidence required to describe one OpenShell sandbox execution."""

    sandbox_id: str
    policy_revision: str
    openshell_policy: bytes
    acs_manifest: bytes
    ocsf_jsonl: bytes
    acs_decisions: tuple[Mapping[str, Any], ...]
    capture_start: int
    capture_end: int
    capture_complete: bool
    openshell_version: str
    openshell_mode: str = "enforce"
    acs_mode: str = "enforce"


def build_openshell_record(
    evidence: OpenShellEvidence,
    *,
    subject: str,
    model_provider: str,
    model_id: str,
    data_class: str,
    workload_digest: str,
    jwk: dict[str, Any],
    model_version: str | None = None,
    transcript_uri: str | None = None,
    policy_uri: str | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Build an unsigned Level 0 TRACE record from OpenShell control-plane evidence."""
    if not evidence.openshell_version or not evidence.openshell_version.strip():
        raise MissingEvidence("openshell_version is required to identify the evidence producer")
    bundle, mode = build_policy_bundle(
        openshell_policy=evidence.openshell_policy,
        policy_revision=evidence.policy_revision,
        acs_manifest=evidence.acs_manifest,
        openshell_mode=evidence.openshell_mode,
        acs_mode=evidence.acs_mode,
    )
    policy = PolicyEvidence(
        bundle=bundle,
        enforcement_mode=mode,
        version="openshell-acs-v1",
        policy_uri=policy_uri,
    )
    transcript, call_count = build_transcript(
        sandbox_id=evidence.sandbox_id,
        policy_bundle_hash=policy.bundle_hash,
        ocsf_jsonl=evidence.ocsf_jsonl,
        acs_decisions=evidence.acs_decisions,
        capture_start=evidence.capture_start,
        capture_end=evidence.capture_end,
        capture_complete=evidence.capture_complete,
    )
    return build_record(
        source=SourceSystem(
            producer=f"nvidia-openshell/{evidence.openshell_version}",
            source_event_id=evidence.sandbox_id,
        ),
        subject=subject,
        model_provider=model_provider,
        model_id=model_id,
        model_version=model_version,
        policy=policy,
        data_class=data_class,
        transcript_bytes=transcript,
        tool_call_count=call_count,
        transcript_uri=transcript_uri,
        workload_digest=workload_digest,
        jwk=jwk,
        iat=iat,
    )
