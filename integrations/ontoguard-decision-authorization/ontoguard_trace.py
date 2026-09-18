"""Thin OntoGuard Decision Authorization → TRACE v0.2 projector.

This module does not authorize movements. It contains no OntoGuard core
authorization or semantic-governance implementation.

Two independently supplied objects are required before a Trust Record exists:

1. signed OntoGuard authorization result bytes
2. an execution receipt from the runtime that actually ran the operation

ALLOW never proves execution. TRACE spec 3.1.2: a record is issued per
execution; a reference cannot carry a pre-execution commitment.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    import agentrust_trace
except ImportError:  # TRACE signing requires the released package
    agentrust_trace = None

EAT_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
REGISTERED_REL = "authorized-intent"
SOFTWARE_MEASUREMENT = "sha256:" + ("0" * 64)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SUBJECT_RE = re.compile(r"^(spiffe://|did:).+")
ACTIONS = frozenset({"ALLOW", "BLOCK", "ESCALATE"})
ADAPTER_VERSION = "0.5.0"
ACTION_BINDING_PROFILE = "ontoguard.partner-execution-action/v1"
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_ONTOGUARD_JWKS = PACKAGE_DIR / "keys" / "ontoguard_jwks.json"
DEFAULT_EXECUTION_JWKS = PACKAGE_DIR / "keys" / "execution_runtime_jwks.json"


class AdapterError(ValueError):
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    required = {"crv": jwk.get("crv"), "kty": jwk.get("kty"), "x": jwk.get("x")}
    raw = json.dumps(required, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(hashlib.sha256(raw).digest())


def _allow_test_keys(explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    return os.environ.get("ONTOGUARD_ADAPTER_ALLOW_TEST_KEYS") == "1"


def load_jwks(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        raise AdapterError(f"invalid JWKS at {path}")
    return [k for k in keys if isinstance(k, dict)]


def resolve_trusted_jwk(
    *,
    registry_path: Path,
    presented_jwk: dict[str, Any] | None = None,
    kid: str | None = None,
    allow_test_keys: bool | None = None,
    registry_name: str,
) -> dict[str, Any]:
    keys = load_jwks(registry_path)
    allow_test = _allow_test_keys(allow_test_keys)
    usable = []
    for key in keys:
        if key.get("test_only") and not allow_test:
            continue
        usable.append(key)
    if not usable:
        raise AdapterError(f"no trusted {registry_name} keys available")

    if kid:
        matches = [k for k in usable if k.get("kid") == kid]
        if not matches:
            raise AdapterError(f"unknown or test-only {registry_name} kid")
        trusted = matches[0]
    elif presented_jwk:
        tp = jwk_thumbprint(presented_jwk)
        matches = [k for k in usable if jwk_thumbprint(k) == tp]
        if not matches:
            raise AdapterError(f"{registry_name} JWK is not in the trusted allowlist")
        trusted = matches[0]
    else:
        raise AdapterError(f"{registry_name} kid or allowlisted JWK is required")

    if presented_jwk and jwk_thumbprint(presented_jwk) != jwk_thumbprint(trusted):
        raise AdapterError(f"presented {registry_name} JWK does not match trusted key")
    return trusted


def _b64url_decode(value: str, name: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + pad)
    except Exception as exc:
        raise AdapterError(f"invalid base64url {name}") from exc


def _digest_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise AdapterError(f"{name} must be sha256:<64 hex>")
    return value


def parse_signed_json_object(signed_bytes: bytes, name: str) -> dict[str, Any]:
    """Parse exact signed bytes. This adapter does not recanonicalize them."""
    try:
        parsed = json.loads(signed_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"{name} are not UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise AdapterError(f"{name} must decode to a JSON object")
    return parsed


def _objects_equal(left: Any, right: Any) -> bool:
    return json.loads(json.dumps(left, sort_keys=True)) == json.loads(json.dumps(right, sort_keys=True))


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def partner_action_binding_object(
    *,
    operation: str,
    amount: str | float | int,
    currency: str,
    counterparty: str,
    cross_border: bool,
    consequence_class: str,
) -> dict[str, Any]:
    if isinstance(amount, (int, float)):
        amount_s = f"{float(amount):.2f}"
    else:
        amount_s = str(amount)
    return {
        "amount": amount_s,
        "consequence_class": consequence_class,
        "counterparty": counterparty,
        "cross_border": bool(cross_border),
        "currency": currency,
        "operation": operation,
    }


def partner_action_binding_bytes(obj: dict[str, Any]) -> bytes:
    """Deterministic partner-safe bytes. Not OntoGuard's internal movement hash."""
    required = (
        "amount",
        "consequence_class",
        "counterparty",
        "cross_border",
        "currency",
        "operation",
    )
    missing = [k for k in required if k not in obj]
    if missing:
        raise AdapterError("partner action binding missing " + ", ".join(missing))
    canonical = {
        "amount": str(obj["amount"]),
        "consequence_class": obj["consequence_class"],
        "counterparty": obj["counterparty"],
        "cross_border": bool(obj["cross_border"]),
        "currency": obj["currency"],
        "operation": obj["operation"],
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def partner_action_binding_digest(obj: dict[str, Any]) -> str:
    return sha256_digest(partner_action_binding_bytes(obj))


def authorization_fields(
    result: dict[str, Any],
    *,
    verification_time_utc: datetime | None = None,
) -> dict[str, Any]:
    required = (
        "action",
        "release_authorized",
        "trace_id",
        "handoff_hash",
        "decision_binding_hash",
        "movement_hash",
        "action_binding_profile",
        "action_binding_digest",
    )
    missing = [k for k in required if k not in result]
    if missing:
        raise AdapterError("authorization result missing " + ", ".join(missing))
    action = result["action"]
    if action not in ACTIONS:
        raise AdapterError(f"unsupported action: {action!r}")
    if not isinstance(result["release_authorized"], bool):
        raise AdapterError("release_authorized must be boolean")
    _digest_str(result["handoff_hash"], "handoff_hash")
    _digest_str(result["decision_binding_hash"], "decision_binding_hash")
    _digest_str(result["movement_hash"], "movement_hash")
    _digest_str(result["action_binding_digest"], "action_binding_digest")
    if result.get("action_binding_profile") != ACTION_BINDING_PROFILE:
        raise AdapterError("action_binding_profile must be ontoguard.partner-execution-action/v1")
    if result["action"] in {"BLOCK", "ESCALATE"} and result["release_authorized"] is True:
        raise AdapterError("withheld action cannot be release_authorized")
    issued = result.get("issued_at_utc")
    expires = result.get("expires_at_utc")
    if issued is not None and not isinstance(issued, str):
        raise AdapterError("issued_at_utc must be a string when present")
    if expires is not None and not isinstance(expires, str):
        raise AdapterError("expires_at_utc must be a string when present")
    if expires:
        try:
            exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AdapterError("expires_at_utc is not ISO-8601") from exc
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if verification_time_utc is None:
            verification_time_utc = datetime.now(timezone.utc)
        elif not isinstance(verification_time_utc, datetime):
            raise AdapterError("verification_time_utc must be a datetime")
        elif verification_time_utc.tzinfo is None:
            raise AdapterError("verification_time_utc must be timezone-aware")
        if verification_time_utc.astimezone(timezone.utc) > exp:
            raise AdapterError("authorization has expired")
    return {
        "action": action,
        "release_authorized": result["release_authorized"],
        "trace_id": str(result["trace_id"]),
        "handoff_hash": result["handoff_hash"],
        "decision_binding_hash": result["decision_binding_hash"],
        "movement_hash": result["movement_hash"],
        "action_binding_profile": result["action_binding_profile"],
        "action_binding_digest": result["action_binding_digest"],
        "issued_at_utc": issued,
        "expires_at_utc": expires,
    }


def verify_authorization_signature(
    result_bytes: bytes,
    signature_b64url: str,
    public_jwk: dict[str, Any],
) -> None:
    if not isinstance(public_jwk, dict):
        raise AdapterError("authorization public_jwk must be an object")
    if public_jwk.get("kty") != "OKP" or public_jwk.get("crv") != "Ed25519":
        raise AdapterError("authorization public_jwk must be OKP Ed25519")
    x = public_jwk.get("x")
    if not isinstance(x, str):
        raise AdapterError("authorization public_jwk.x missing")
    raw_pub = _b64url_decode(x, "public_jwk.x")
    raw_sig = _b64url_decode(signature_b64url, "authorization signature")
    if len(raw_pub) != 32 or len(raw_sig) != 64:
        raise AdapterError("authorization signature or public key has unexpected length")
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(raw_sig, result_bytes)
    except InvalidSignature as exc:
        raise AdapterError("OntoGuard authorization signature verification failed") from exc


def bind_authorization(
    result: dict[str, Any] | None = None,
    *,
    result_bytes: bytes,
    signature_b64url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    kid: str | None = None,
    claimed_digest: str | None = None,
    ontoguard_jwks_path: Path | None = None,
    allow_test_keys: bool | None = None,
    verification_time_utc: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(result_bytes, (bytes, bytearray)) or not result_bytes:
        raise AdapterError("exact authorization result bytes are required")
    parsed = parse_signed_json_object(bytes(result_bytes), "authorization result bytes")
    if result is not None and not _objects_equal(parsed, result):
        raise AdapterError("supplied authorization object does not match exact signed bytes")
    fields = authorization_fields(parsed, verification_time_utc=verification_time_utc)
    raw = bytes(result_bytes)
    digest = sha256_digest(raw)
    if claimed_digest is not None and digest != _digest_str(claimed_digest, "claimed_digest"):
        raise AdapterError("authorization result digest mismatch")
    if not signature_b64url:
        raise AdapterError("authorization signature is required")
    trusted = resolve_trusted_jwk(
        registry_path=ontoguard_jwks_path or Path(os.environ.get("ONTOGUARD_TRUSTED_JWKS", DEFAULT_ONTOGUARD_JWKS)),
        presented_jwk=public_jwk,
        kid=kid,
        allow_test_keys=allow_test_keys,
        registry_name="OntoGuard authorization",
    )
    verify_authorization_signature(raw, signature_b64url, trusted)
    return {
        **fields,
        "result_bytes": raw,
        "result_digest": digest,
        "public_jwk": trusted,
        "kid": trusted.get("kid"),
    }


def classify(
    result: dict[str, Any],
    execution_receipt: dict[str, Any] | None = None,
    *,
    verification_time_utc: datetime | None = None,
) -> str:
    action = authorization_fields(
        result, verification_time_utc=verification_time_utc
    )["action"]
    receipt_executed = bool(execution_receipt and execution_receipt.get("executed"))
    if action in {"BLOCK", "ESCALATE"}:
        if receipt_executed:
            raise AdapterError(
                f"{action} authorization cannot be paired with executed=true receipt"
            )
        return f"{action}_NO_EXECUTION"
    if result.get("release_authorized") is not True:
        raise AdapterError("ALLOW without release_authorized cannot enter the executed path")
    if not receipt_executed:
        return "ALLOW_NO_EXECUTION_YET"
    return "ALLOW_EXECUTION_CANDIDATE"


def _require_subject(value: Any) -> str:
    if not isinstance(value, str) or not SUBJECT_RE.match(value):
        raise AdapterError("execution subject must be a SPIFFE or DID string")
    return value


def receipt_payload(execution_receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in execution_receipt.items()
        if k not in {"signature", "kid", "public_jwk", "receipt_bytes"}
    }


def verify_execution_receipt(
    bound: dict[str, Any],
    execution_receipt: dict[str, Any],
    *,
    execution_jwks_path: Path | None = None,
    allow_test_keys: bool | None = None,
    receipt_bytes: bytes | None = None,
) -> dict[str, Any]:
    if not isinstance(execution_receipt, dict):
        raise AdapterError("execution_receipt must be an object")
    _require_subject(execution_receipt.get("subject"))
    build_early = execution_receipt.get("build_provenance")
    if isinstance(build_early, dict) and "slsa_level" not in build_early:
        raise AdapterError("execution_receipt.build_provenance.slsa_level is required")
    model_early = execution_receipt.get("model")
    if not isinstance(model_early, dict) or not str(model_early.get("model_id") or "").strip():
        raise AdapterError("execution_receipt.model.model_id is required")
    if not str(model_early.get("provider") or "").strip():
        raise AdapterError("execution_receipt.model.provider is required")
    if not str(execution_receipt.get("data_class") or "").strip():
        raise AdapterError("execution_receipt.data_class is required")
    if not str(execution_receipt.get("execution_event_id") or "").strip():
        raise AdapterError("execution_receipt.execution_event_id is required")
    if not str(execution_receipt.get("execution_producer") or "").strip():
        raise AdapterError("execution_receipt.execution_producer is required")
    required_binding_fields = (
        "authorized_action",
        "authorized_trace_id",
        "authorized_decision_binding_hash",
        "authorized_handoff_hash",
        "authorized_result_digest",
        "authorized_movement_hash",
        "executed_movement_hash",
        "authorized_action_binding_digest",
        "executed_action_binding_digest",
    )
    missing = [field for field in required_binding_fields if field not in execution_receipt]
    if missing:
        raise AdapterError(
            "execution receipt missing required authorization bindings: " + ", ".join(missing)
        )
    if execution_receipt.get("executed_movement_hash") and bound.get("movement_hash"):
        if execution_receipt["executed_movement_hash"] != bound["movement_hash"]:
            raise AdapterError("executed_movement_hash does not match authorized movement")
    if execution_receipt.get("authorized_movement_hash") and bound.get("movement_hash"):
        if execution_receipt["authorized_movement_hash"] != bound["movement_hash"]:
            raise AdapterError("authorized_movement_hash does not match signed authorization")
    if execution_receipt.get("authorized_action_binding_digest") and bound.get("action_binding_digest"):
        if execution_receipt["authorized_action_binding_digest"] != bound["action_binding_digest"]:
            raise AdapterError("authorized_action_binding_digest does not match signed authorization")
    if execution_receipt.get("executed_action_binding_digest") and bound.get("action_binding_digest"):
        if execution_receipt["executed_action_binding_digest"] != bound["action_binding_digest"]:
            raise AdapterError("executed_action_binding_digest does not match authorized action binding")
    trusted = resolve_trusted_jwk(
        registry_path=execution_jwks_path
        or Path(os.environ.get("EXECUTION_TRUSTED_JWKS", DEFAULT_EXECUTION_JWKS)),
        presented_jwk=execution_receipt.get("public_jwk")
        if isinstance(execution_receipt.get("public_jwk"), dict)
        else None,
        kid=execution_receipt.get("kid") if isinstance(execution_receipt.get("kid"), str) else None,
        allow_test_keys=allow_test_keys,
        registry_name="execution runtime",
    )
    signature = execution_receipt.get("signature")
    if not isinstance(signature, str) or not signature:
        raise AdapterError("execution receipt signature is required")
    raw_receipt = receipt_bytes or execution_receipt.get("receipt_bytes")
    if isinstance(raw_receipt, str):
        raw_receipt = raw_receipt.encode("utf-8")
    if not isinstance(raw_receipt, (bytes, bytearray)) or not raw_receipt:
        raise AdapterError("exact execution receipt bytes are required")
    parsed_receipt = parse_signed_json_object(bytes(raw_receipt), "execution receipt bytes")
    if not _objects_equal(parsed_receipt, receipt_payload(execution_receipt)):
        raise AdapterError("supplied execution receipt does not match exact signed bytes")
    verify_authorization_signature(
        bytes(raw_receipt),
        signature,
        trusted,
    )
    if execution_receipt.get("executed") is not True:
        raise AdapterError("execution_receipt.executed must be true")
    if execution_receipt.get("protected_effect_formed") is not True:
        raise AdapterError("execution_receipt.protected_effect_formed must be true")
    receipt_handoff = _digest_str(
        execution_receipt.get("authorized_handoff_hash"),
        "execution_receipt.authorized_handoff_hash",
    )
    receipt_digest = _digest_str(
        execution_receipt.get("authorized_result_digest"),
        "execution_receipt.authorized_result_digest",
    )
    if receipt_handoff != bound["handoff_hash"]:
        raise AdapterError("execution receipt handoff does not match signed authorization")
    if receipt_digest != bound["result_digest"]:
        raise AdapterError("execution receipt result digest does not match signed authorization")
    if execution_receipt["authorized_decision_binding_hash"] != bound["decision_binding_hash"]:
        raise AdapterError("execution receipt decision binding does not match authorization")
    if str(execution_receipt["authorized_trace_id"]) != bound["trace_id"]:
        raise AdapterError("execution receipt trace_id does not match authorization")
    if execution_receipt["authorized_action"] != "ALLOW":
        raise AdapterError("execution receipt is not bound to an ALLOW authorization")
    if execution_receipt["authorized_action_binding_digest"] != bound["action_binding_digest"]:
        raise AdapterError("authorized_action_binding_digest does not match signed authorization")
    if execution_receipt["executed_action_binding_digest"] != bound["action_binding_digest"]:
        raise AdapterError("executed_action_binding_digest does not match authorized action binding")
    auth_move = _digest_str(
        execution_receipt.get("authorized_movement_hash"),
        "execution_receipt.authorized_movement_hash",
    )
    exec_move = _digest_str(
        execution_receipt.get("executed_movement_hash"),
        "execution_receipt.executed_movement_hash",
    )
    if auth_move != bound["movement_hash"]:
        raise AdapterError("authorized_movement_hash does not match signed authorization")
    if exec_move != bound["movement_hash"]:
        raise AdapterError("executed_movement_hash does not match authorized movement")
    subject = _require_subject(execution_receipt.get("subject"))
    policy = execution_receipt.get("policy")
    build = execution_receipt.get("build_provenance")
    if not isinstance(policy, dict) or not DIGEST_RE.fullmatch(str(policy.get("bundle_hash") or "")):
        raise AdapterError("execution_receipt.policy.bundle_hash is required")
    if policy.get("enforcement_mode") not in {"enforce", "advisory", "silent", "declared"}:
        raise AdapterError("execution_receipt.policy.enforcement_mode is required")
    if not isinstance(build, dict) or not DIGEST_RE.fullmatch(str(build.get("digest") or "")):
        raise AdapterError("execution_receipt.build_provenance.digest is required")
    if not isinstance(build.get("slsa_level"), int) or build["slsa_level"] < 0:
        raise AdapterError("execution_receipt.build_provenance.slsa_level is required")
    model = execution_receipt.get("model")
    if not isinstance(model, dict):
        raise AdapterError("execution_receipt.model is required")
    provider = model.get("provider")
    model_id = model.get("model_id")
    if not isinstance(provider, str) or not provider.strip():
        raise AdapterError("execution_receipt.model.provider is required")
    if not isinstance(model_id, str) or not model_id.strip():
        raise AdapterError("execution_receipt.model.model_id is required")
    data_class = execution_receipt.get("data_class")
    if not isinstance(data_class, str) or not data_class.strip():
        raise AdapterError("execution_receipt.data_class is required")
    event_id = execution_receipt.get("execution_event_id")
    producer = execution_receipt.get("execution_producer")
    if not isinstance(event_id, str) or not event_id.strip():
        raise AdapterError("execution_receipt.execution_event_id is required")
    if not isinstance(producer, str) or not producer.strip():
        raise AdapterError("execution_receipt.execution_producer is required")
    verifier = execution_receipt.get("appraisal_verifier")
    if not isinstance(verifier, str) or not verifier.strip():
        raise AdapterError("execution_receipt.appraisal_verifier is required")
    return {
        "subject": subject,
        "policy": policy,
        "build_provenance": build,
        "model": model,
        "data_class": data_class,
        "appraisal_verifier": verifier,
        "execution_event_id": event_id.strip(),
        "execution_producer": producer.strip(),
    }


def build_unsigned_record(
    bound: dict[str, Any],
    execution: dict[str, Any],
    *,
    iat: int | None = None,
) -> dict[str, Any]:
    issued = int(time.time() if iat is None else iat)
    return {
        "eat_profile": EAT_PROFILE,
        "iat": issued,
        "subject": execution["subject"],
        "model": execution["model"],
        "runtime": {
            "platform": "software-only",
            "measurement": SOFTWARE_MEASUREMENT,
        },
        "policy": execution["policy"],
        "data_class": execution["data_class"],
        "origin": {
            "kind": "third-party-control-plane",
            "producer": execution["execution_producer"],
            "source_event_id": execution["execution_event_id"],
            "ingested_at": issued,
        },
        "references": [
            {
                "rel": REGISTERED_REL,
                "id": bound["handoff_hash"],
                "resolver": "OntoGuard",
                "digest": bound["result_digest"],
            }
        ],
        "build_provenance": execution["build_provenance"],
        "appraisal": {
            "status": "none",
            "verifier": execution["appraisal_verifier"],
            "timestamp": issued,
        },
    }


def project(
    result: dict[str, Any],
    *,
    signature_b64url: str,
    public_jwk: dict[str, Any] | None = None,
    kid: str | None = None,
    result_bytes: bytes,
    claimed_digest: str | None = None,
    execution_receipt: dict[str, Any] | None = None,
    sign_trace: bool = False,
    private_key_pem: str | None = None,
    ontoguard_jwks_path: Path | None = None,
    execution_jwks_path: Path | None = None,
    allow_test_keys: bool | None = None,
    verification_time_utc: datetime | None = None,
) -> dict[str, Any]:
    bound = bind_authorization(
        result,
        result_bytes=result_bytes,
        signature_b64url=signature_b64url,
        public_jwk=public_jwk,
        kid=kid,
        claimed_digest=claimed_digest,
        ontoguard_jwks_path=ontoguard_jwks_path,
        allow_test_keys=allow_test_keys,
        verification_time_utc=verification_time_utc,
    )
    state = classify(
        result,
        execution_receipt,
        verification_time_utc=verification_time_utc,
    )
    out: dict[str, Any] = {
        "adapter": "ontoguard-decision-authorization",
        "adapter_version": ADAPTER_VERSION,
        "state": state,
        "trace_record_emitted": False,
        "trace_record": None,
        "authorization": {
            "action": bound["action"],
            "release_authorized": bound["release_authorized"],
            "trace_id": bound["trace_id"],
            "handoff_hash": bound["handoff_hash"],
            "decision_binding_hash": bound["decision_binding_hash"],
            "movement_hash": bound["movement_hash"],
            "action_binding_digest": bound["action_binding_digest"],
            "result_digest": bound["result_digest"],
        },
        "limitations": [
            "OntoGuard remains the pre-execution authorization authority.",
            "A TRACE record is issued per execution (TRACE spec 3.1.2).",
            "references[].rel=authorized-intent points at a prior OntoGuard handoff; it does not authorize execution.",
            "runtime.platform=software-only; no hardware attestation.",
            "This adapter contains no OntoGuard core authorization or semantic-governance implementation.",
        ],
    }
    if state != "ALLOW_EXECUTION_CANDIDATE":
        return out
    execution = verify_execution_receipt(
        bound,
        execution_receipt or {},
        execution_jwks_path=execution_jwks_path,
        allow_test_keys=allow_test_keys,
        receipt_bytes=(execution_receipt or {}).get("receipt_bytes")
        if isinstance(execution_receipt, dict)
        else None,
    )
    unsigned = build_unsigned_record(bound, execution)
    if not sign_trace:
        out["trace_claim_candidate"] = unsigned
        out["trace_record"] = None
        out["trace_record_emitted"] = False
        out["signed"] = False
        out["state"] = "ALLOW_EXECUTION_CANDIDATE"
        return out
    if agentrust_trace is None:
        raise AdapterError("agentrust-trace is required to sign a TRACE record")
    pem = private_key_pem or os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if not pem:
        raise AdapterError("TRACE_PRIVATE_KEY_PEM is required to sign")
    key = agentrust_trace.load_key(pem)
    record = agentrust_trace.sign_record(unsigned, key)
    jwk = agentrust_trace.key_to_jwk(key)
    agentrust_trace.verify_record(record, jwk)
    out["trace_record"] = record
    out["trace_record_emitted"] = True
    out["signed"] = True
    out["state"] = "ALLOW_EXECUTION_PROVEN"
    return out
