"""Relying-party verification for the PIC Standard MCP guard TRACE adapter.

This verification module does not import or invoke `pic_standard` or
`agentrust_trace_adapters`; its verification path uses only `agentrust_trace`,
`rfc8785`, and the standard library. (The installed distribution still pulls the
producer dependencies; the guarantee here is code-level, enforced by a test.) The
producer side, bridge construction, record building, and measurement, lives in
`pic_trace_guard`.

Two public entry points: `verify_authorization_artifacts` verifies the detached
authorization bridge alone (the bridge-only outcome where no Trust Record was emitted),
and `verify_adapter_artifacts` delegates to it and then adds the record-specific checks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from typing import Any

import rfc8785
from agentrust_trace import verify_record
from agentrust_trace.intent_bridge import verify_bridge
from agentrust_trace.validate import validate_json

TRANSCRIPT_PROFILE = "pic-trace-stage1-transcript/v1"
BRIDGE_REFERENCE_REL = "authorized-intent"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_PIC_HEX = re.compile(r"^[0-9a-f]{64}$")
_B64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")


class AdapterVerifyError(Exception):
    """A relying-party verification check failed (no sensitive detail in the message)."""


def sha256_prefixed(data: bytes) -> str:
    """SHA-256 of `data` in TRACE's `sha256:<hex>` form."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_jcs(value: Any) -> str:
    return sha256_prefixed(rfc8785.dumps(value))


def build_transcript(
    *,
    pic_decision_raw: bytes,
    bridge: Mapping[str, Any],
    tool_call: Mapping[str, Any],
    tool_response: Any,
    observation: Mapping[str, Any],
) -> dict:
    """The transcript preimage hashed into `tool_transcript.hash` (JCS-canonical)."""
    return {
        "profile": TRANSCRIPT_PROFILE,
        "pic_decision_digest": sha256_prefixed(pic_decision_raw),
        "authorization_bridge_digest": _digest_jcs(bridge),
        "tool_call": dict(tool_call),
        "tool_response": tool_response,
        "observation": dict(observation),
    }


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise AdapterVerifyError(message)


def _b64url_decode_32(s: str) -> bytes:
    _require(
        isinstance(s, str) and bool(_B64URL_32.fullmatch(s)),
        "invalid unpadded base64url Ed25519 key",
    )
    try:
        raw = base64.urlsafe_b64decode(s + "=")
    except (binascii.Error, ValueError) as exc:
        raise AdapterVerifyError("invalid unpadded base64url Ed25519 key") from exc
    _require(len(raw) == 32, "expected a 32-byte Ed25519 public key")
    # Reject alternate spellings whose unused final bits are non-zero.
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    _require(s == canonical, "non-canonical base64url Ed25519 key")
    return raw


def _did_key_public_bytes(did: str) -> bytes:
    prefix = "did:key:z"
    _require(isinstance(did, str) and did.startswith(prefix), "subject is not a base58btc did:key")
    n = 0
    for ch in did[len(prefix):]:
        idx = _B58.find(ch)
        _require(idx >= 0, "invalid base58btc character in did:key")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    _require(body[:2] == b"\xed\x01", "did:key multicodec is not Ed25519 (0xed01)")
    _require(len(body) - 2 == 32, "did:key does not hold a 32-byte Ed25519 key")
    return body[2:]


def verify_authorization_artifacts(
    *,
    bridge: Mapping[str, Any],
    pic_decision_raw: bytes,
    declaration: Mapping[str, Any],
    pic_intent_digest: str,
    pic_args_digest: str,
    tool_call: Mapping[str, Any],
    authorizer_jwk: Mapping[str, Any],
) -> dict:
    """Verify the detached authorization bridge alone, with only agentrust_trace + rfc8785.

    This is the public verifier for the bridge-only outcome (PIC allowed and the bridge
    was produced, but no Trust Record was emitted). `pic_decision_raw` is the exact PIC
    decision bytes (`decision.to_audit_bytes()`); the `authorization_id` is recomputed
    from them. `pic_intent_digest` / `pic_args_digest` must be bare lowercase 64-char
    SHA-256 hex (PIC's `canonical.py` form); this function adds the `sha256:` prefix the
    bridge requires. Raises `AdapterVerifyError` on any failure.
    """
    try:
        _require(bool(_PIC_HEX.match(pic_intent_digest)), "pic_intent_digest is not bare 64-char hex")
        _require(bool(_PIC_HEX.match(pic_args_digest)), "pic_args_digest is not bare 64-char hex")
        authz = bridge["authorization"]

        # 1. authorization_id is the hash of the PIC decision bytes, not an arbitrary id.
        expected_authorization_id = "urn:sha256:" + hashlib.sha256(pic_decision_raw).hexdigest()
        _require(
            authz["authorization_id"] == expected_authorization_id,
            "authorization_id does not match the PIC decision bytes",
        )

        # 2. Bridge signature + binding (declaration, tool call, PIC digests), replayed
        #    at its own authorized_at.
        verify_bridge(
            bridge,
            authorizer_jwk,
            declaration=dict(declaration),
            pic_intent_digest="sha256:" + pic_intent_digest,
            pic_args_digest="sha256:" + pic_args_digest,
            tool_call=dict(tool_call),
            now=authz["authorized_at"],
        )
        _require(authz["pic"]["intent_digest"] == "sha256:" + pic_intent_digest, "bridge intent digest")
        _require(authz["pic"]["args_digest"] == "sha256:" + pic_args_digest, "bridge args digest")

        return {
            "authorization_id_bound_to_decision": True,
            "bridge_signature": True,
            "bridge_intent_digest": True,
            "bridge_args_digest": True,
        }
    except AdapterVerifyError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize to the module's error, keep cause, hide detail
        raise AdapterVerifyError("authorization artifact verification failed") from exc


def verify_adapter_artifacts(
    *,
    record: Mapping[str, Any],
    bridge: Mapping[str, Any],
    pic_decision_raw: bytes,
    declaration: Mapping[str, Any],
    pic_intent_digest: str,
    pic_args_digest: str,
    tool_call: Mapping[str, Any],
    authorizer_jwk: Mapping[str, Any],
    transcript: Mapping[str, Any] | None = None,
) -> dict:
    """Verify the adapter's bridge + Trust Record with only agentrust_trace + rfc8785.

    Delegates to `verify_authorization_artifacts` for the bridge checks (no duplicated
    logic), then adds: the record validates (`validate_json`) and its signature verifies
    against its own embedded confirmation key; the supplied `bridge` is cited by the
    record's single signed `authorized-intent` reference by id and JCS digest (the
    function does not contact the reference `resolver`); the `subject` `did:key` decodes
    to `cnf.jwk.x`; and, if `transcript` (the preimage) is supplied, its bindings and the
    signed `tool_transcript.hash`. Raises `AdapterVerifyError` on any failure.
    """
    try:
        checked = dict(
            verify_authorization_artifacts(
                bridge=bridge,
                pic_decision_raw=pic_decision_raw,
                declaration=declaration,
                pic_intent_digest=pic_intent_digest,
                pic_args_digest=pic_args_digest,
                tool_call=tool_call,
                authorizer_jwk=authorizer_jwk,
            )
        )
        authz = bridge["authorization"]
        expected_authorization_id = "urn:sha256:" + hashlib.sha256(pic_decision_raw).hexdigest()

        # Record: schema + signature against its own embedded confirmation key.
        validate_json(record)
        verify_record(record, record["cnf"]["jwk"])
        checked["record_signature"] = True

        # Record -> bridge linkage: source_event_id + exactly one authorized-intent
        # reference citing this bridge by id and JCS digest. Other references compose.
        _require(record["origin"]["source_event_id"] == expected_authorization_id, "origin.source_event_id")
        refs = record.get("references") or []
        matching = [r for r in refs if r.get("id") == authz["authorization_id"]]
        _require(len(matching) == 1, "expected exactly one reference citing the bridge")
        bridge_ref = matching[0]
        _require(bridge_ref.get("rel") == BRIDGE_REFERENCE_REL, "bridge reference rel is not authorized-intent")
        _require(bridge_ref["digest"] == _digest_jcs(bridge), "bridge reference digest mismatch")
        checked["reference_matches_supplied_bridge"] = True

        # Subject did:key binds the record's confirmation key (both exactly 32 bytes).
        _require(
            _did_key_public_bytes(record["subject"]) == _b64url_decode_32(record["cnf"]["jwk"]["x"]),
            "subject did:key does not decode to cnf.jwk.x",
        )
        checked["subject_binds_cnf_jwk"] = True

        # Optional transcript preimage: bindings first, then the signed hash.
        if transcript is not None:
            _require(transcript.get("profile") == TRANSCRIPT_PROFILE, "transcript profile")
            _require(transcript.get("pic_decision_digest") == sha256_prefixed(pic_decision_raw), "transcript pic_decision_digest")
            _require(transcript.get("authorization_bridge_digest") == _digest_jcs(bridge), "transcript authorization_bridge_digest")
            _require(transcript.get("tool_call") == dict(tool_call), "transcript tool_call")
            _require(
                record["tool_transcript"]["hash"] == sha256_prefixed(rfc8785.dumps(dict(transcript))),
                "tool_transcript.hash does not match the supplied transcript preimage",
            )
            checked["transcript_bound_and_hashed"] = True

        return checked
    except AdapterVerifyError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize to the module's error, keep cause, hide detail
        raise AdapterVerifyError("adapter artifact verification failed") from exc
