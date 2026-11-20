"""Relying-party verification for the WIMSE CTA MCP guard TRACE adapter.

This module imports only `agentrust_trace`, `rfc8785`, `cryptography`, and the
standard library; it does not import `agentrust_trace_adapters` or `cta_trace_guard`
(a test enforces that). The producer side, which tracks taint, gates the tool call,
signs the bridge, and builds the Trust Record, lives in `cta_trace_guard`.

Everything signed here is Ed25519 over the RFC 8785 (JCS) bytes of
`{"profile": <profile>, "<body field>": <body>}`, carried as unpadded canonical
base64url. A key identifier is `sha256:` plus the lowercase hex SHA-256 of the raw
32-byte public key.

Public entry points: `verify_step_up_receipt`, `verify_bridge`, `verify_observation`,
`verify_authorization_artifacts` (the bridge-only outcome, where no Trust Record was
emitted), and `verify_adapter_artifacts` (the bridge, receipt, transcript, and record).
Each raises `CtaVerifyError` on the first failed check; messages carry no input values.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any

import rfc8785
from agentrust_trace import verify_record
from agentrust_trace.validate import validate_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CTA_VERSION = "1.0"
BRIDGE_PROFILE = "cta-trace-bridge-v1"
RECEIPT_PROFILE = "cta-step-up-receipt-v1"
TRANSCRIPT_PROFILE = "cta-trace-transcript/v1"
DECLARATION_PROFILE = "cta-tool-declaration/v1"
POLICY_PROFILE = "cta-gate-policy/v1"
BRIDGE_REFERENCE_REL = "authorized-intent"

TRUSTED_ONLY = "TRUSTED_ONLY"
UNTRUSTED_INGESTED = "UNTRUSTED_INGESTED"
TAINT_LEVELS = (TRUSTED_ONLY, UNTRUSTED_INGESTED)

READ_ONLY = "READ_ONLY"
STATE_MUTATING = "STATE_MUTATING"
EFFECT_CLASSES = (READ_ONLY, STATE_MUTATING)

OUTPUT_TRUST_VALUES = ("trusted", "untrusted")

BASIS_READ_ONLY = "read-only"
BASIS_TRUSTED_CONTEXT = "trusted-context"
BASIS_STEP_UP = "step-up-receipt"

SAFE_INT_MAX = 2**53 - 1
MAX_CLOCK_SKEW_SECONDS = 60
MAX_RECEIPT_WINDOW_SECONDS = 3600
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth")

RECEIPT_FIELDS = (
    "receipt_id", "session_id", "request_id", "tool_name", "args_digest",
    "approver", "kid", "iat", "exp",
)
AUTHORIZATION_REQUIRED = (
    "cta_version", "authorization_id", "decision", "decision_basis", "authorizer",
    "authorizer_key_id", "authorized_at", "expires_at", "session_id", "request_id",
    "tool_name", "tool_effect_class", "taint_lattice_level", "args_digest",
    "declaration_digest", "tool_call_digest",
)
AUTHORIZATION_OPTIONAL = ("step_up_receipt_hash",)
_AUTHORIZATION_ID_EXCLUDED = (
    "authorization_id", "authorizer", "authorizer_key_id", "authorized_at", "expires_at",
)
OBSERVATION_FIELDS = ("observation", "observer", "observed_at")
OBSERVATION_BINDINGS = ("request_id", "tool_name", "args_digest", "tool_call_count")
TRANSCRIPT_FIELDS = (
    "profile", "authorization_bridge_digest", "step_up_receipt_digest", "tool_call",
    "tool_response", "observation",
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_IDENTIFIER = re.compile(r"[\x21-\x7e]{1,512}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_AUTHORIZATION_ID = re.compile(r"urn:sha256:[0-9a-f]{64}")
_PUBLIC_JWK_MEMBERS = frozenset({"kty", "crv", "x", "kid"})


class CtaVerifyError(Exception):
    """A relying-party verification check failed (no input values in the message)."""


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise CtaVerifyError(message)


def loads_unique(data: Any) -> Any:
    """Parse JSON from bytes or str, rejecting duplicate keys and non-finite numbers.

    Non-finite means the `NaN`, `Infinity`, and `-Infinity` constants and any number
    literal that overflows to infinity (`1e999`). Invalid UTF-8, malformed JSON, and
    nesting that exhausts the parser all raise `CtaVerifyError`.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CtaVerifyError("JSON input is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise CtaVerifyError("JSON input must be bytes or str")

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise CtaVerifyError("duplicate key in JSON object")
            out[key] = value
        return out

    def _reject_constant(token: str) -> Any:
        raise CtaVerifyError("non-finite JSON constant")

    def _finite_float(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            raise CtaVerifyError("non-finite JSON number")
        return value

    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except RecursionError as exc:
        raise CtaVerifyError("JSON nesting is too deep") from exc
    except ValueError as exc:
        raise CtaVerifyError("malformed JSON") from exc


def canonical_bytes(value: Any) -> bytes:
    """RFC 8785 bytes for `value`, or `CtaVerifyError` when it has no canonical form."""
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, ValueError, RecursionError) as exc:
        raise CtaVerifyError("value has no RFC 8785 canonical form") from exc


def sha256_prefixed(data: bytes) -> str:
    """SHA-256 of `data` in TRACE's `sha256:<hex>` form."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_jcs(value: Any) -> str:
    """`sha256:<hex>` of the RFC 8785 canonical bytes of `value`."""
    return sha256_prefixed(canonical_bytes(value))


def require_timestamp(value: Any, name: str) -> int:
    """A non-negative integer within the JCS safe range; `bool` is not an integer here."""
    _require(
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= SAFE_INT_MAX,
        f"{name} must be a non-negative integer Unix timestamp in the JCS safe range",
    )
    return value


def require_identifier(value: Any, name: str) -> str:
    """1-512 printable ASCII characters, no whitespace."""
    _require(
        isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None,
        f"{name} must be 1-512 printable ASCII characters without whitespace",
    )
    return value


def require_digest(value: Any, name: str) -> str:
    _require(
        isinstance(value, str) and _DIGEST.fullmatch(value) is not None,
        f"{name} must be sha256: followed by 64 lowercase hex characters",
    )
    return value


def b64url_decode(value: Any, *, field: str, length: int | None = None) -> bytes:
    """Decode canonical unpadded base64url; each byte string has one accepted spelling.

    Rejects non-strings, any character outside `A-Z a-z 0-9 - _` (so no padding, no
    whitespace, no `+` or `/`), lengths no byte string can have, and a final character
    whose unused low bits are non-zero.
    """
    _require(isinstance(value, str), f"{field} must be a base64url string")
    _require(_B64URL.fullmatch(value) is not None, f"{field} is not unpadded base64url")
    _require(len(value) % 4 != 1, f"{field} has an impossible base64url length")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    _require(canonical == value, f"{field} is not canonical base64url")
    if length is not None:
        _require(len(decoded) == length, f"{field} must decode to {length} bytes")
    return decoded


def key_id(raw_public_key: bytes) -> str:
    """`sha256:` plus the lowercase hex SHA-256 of the raw public key bytes."""
    return sha256_prefixed(raw_public_key)


def public_key_from_jwk(jwk: Any) -> tuple[Ed25519PublicKey, bytes]:
    """The Ed25519 public key and raw bytes from a public OKP JWK.

    Refuses private members (`d p q dp dq qi oth`), members other than
    `kty crv x kid`, a non-canonical `x`, and a `kid` that is not `key_id(raw)`.
    """
    _require(isinstance(jwk, Mapping), "JWK must be an object")
    _require(not any(member in jwk for member in PRIVATE_JWK_MEMBERS), "JWK carries private key members")
    _require(set(jwk) <= _PUBLIC_JWK_MEMBERS, "JWK carries unsupported members")
    _require(
        jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519",
        "JWK is not an OKP Ed25519 public key",
    )
    raw = b64url_decode(jwk.get("x"), field="JWK x", length=32)
    if "kid" in jwk:
        _require(jwk["kid"] == key_id(raw), "JWK kid is not the SHA-256 of the raw public key")
    return Ed25519PublicKey.from_public_bytes(raw), raw


def signing_preimage(profile: str, field: str, body: Any) -> bytes:
    """The bytes a CTA envelope signature covers."""
    return canonical_bytes({"profile": profile, field: body})


def _verify_signature(public_key: Ed25519PublicKey, signature: Any, preimage: bytes, what: str) -> None:
    raw = b64url_decode(signature, field=f"{what} signature", length=64)
    try:
        public_key.verify(raw, preimage)
    except InvalidSignature as exc:
        raise CtaVerifyError(f"{what} signature is invalid") from exc


def _as_object(value: Any, what: str) -> dict:
    """A detached JSON object with an RFC 8785 form, from bytes, str, or a mapping.

    A mapping keeps its Python types: a `float` or `bool` where an integer is required
    stays one and is refused by the field checks, exactly as the same value in JSON text
    is. Canonicalizing first would turn `1.0` into `1` and hide it.
    """
    if isinstance(value, (bytes, bytearray, str)):
        parsed = loads_unique(value)
        canonical_bytes(parsed)
    elif isinstance(value, Mapping):
        canonical_bytes(dict(value))
        parsed = copy.deepcopy(dict(value))
    else:
        raise CtaVerifyError(f"{what} must be a JSON object")
    _require(isinstance(parsed, dict), f"{what} must be a JSON object")
    return parsed


def _check_keys(obj: Any, required: tuple, name: str, optional: tuple = ()) -> None:
    _require(isinstance(obj, dict), f"{name} must be an object")
    _require(set(required) <= set(obj), f"{name} is missing required fields")
    _require(set(obj) <= set(required) | set(optional), f"{name} has unknown fields")


def authorization_id_for(authorization: Mapping[str, Any]) -> str:
    """The content identifier of a gate decision.

    The hash of the canonical authorization without the identifier, the authorizer
    identity, and the validity window, so it names the decision (session, request,
    tool, arguments, taint, basis, declaration) and not who signed it or when.
    """
    preimage = {k: v for k, v in authorization.items() if k not in _AUTHORIZATION_ID_EXCLUDED}
    return "urn:sha256:" + hashlib.sha256(canonical_bytes(preimage)).hexdigest()


def expected_basis(effect_class: str, taint: str) -> str:
    """The only `decision_basis` a bridge may carry for this effect class and taint."""
    if effect_class == READ_ONLY:
        return BASIS_READ_ONLY
    return BASIS_TRUSTED_CONTEXT if taint == TRUSTED_ONLY else BASIS_STEP_UP


def verify_step_up_receipt(
    receipt: Any,
    *,
    policy_jwk: Mapping[str, Any],
    session_id: str,
    request_id: str,
    tool_name: str,
    args_digest: str,
    now: int,
) -> dict:
    """Verify a policy-engine StepUpReceipt for exactly one call, as of `now`.

    The receipt is `{"profile", "receipt", "signature"}`; the Ed25519 signature is by
    the pinned policy-engine key, whose `kid` the receipt must carry. It must be bound to
    this `(session_id, request_id, tool_name, args_digest)`, have a validity window
    longer than the 60-second skew allowance and no longer than one hour, have started
    no later than `now` plus the skew, and not have expired. Returns the parsed
    `envelope`, `receipt` body, and `digest` (JCS digest of the whole envelope).
    """
    require_timestamp(now, "now")
    envelope = _as_object(receipt, "step-up receipt")
    _check_keys(envelope, ("profile", "receipt", "signature"), "step-up receipt")
    _require(envelope["profile"] == RECEIPT_PROFILE, "unknown step-up receipt profile")
    body = envelope["receipt"]
    _check_keys(body, RECEIPT_FIELDS, "step-up receipt body")
    public_key, raw = public_key_from_jwk(policy_jwk)
    _verify_signature(
        public_key, envelope["signature"], signing_preimage(RECEIPT_PROFILE, "receipt", body),
        "step-up receipt",
    )
    _require(body["kid"] == key_id(raw), "step-up receipt kid does not identify the trusted policy-engine key")
    require_identifier(body["receipt_id"], "receipt_id")
    require_identifier(body["approver"], "approver")
    require_digest(body["args_digest"], "receipt args_digest")
    iat = require_timestamp(body["iat"], "receipt iat")
    exp = require_timestamp(body["exp"], "receipt exp")
    _require(exp > iat + MAX_CLOCK_SKEW_SECONDS, "receipt validity window must exceed the 60-second skew allowance")
    _require(exp - iat <= MAX_RECEIPT_WINDOW_SECONDS, "receipt validity window exceeds one hour")
    _require(iat <= now + MAX_CLOCK_SKEW_SECONDS, "receipt is not yet valid")
    _require(now < exp, "receipt has expired")
    _require(body["session_id"] == session_id, "receipt is bound to a different session")
    _require(body["request_id"] == request_id, "receipt is bound to a different request")
    _require(body["tool_name"] == tool_name, "receipt is bound to a different tool")
    _require(body["args_digest"] == args_digest, "receipt is bound to different arguments")
    return {"envelope": envelope, "receipt": body, "digest": digest_jcs(envelope)}


def _verify_bridge_object(
    bridge: Any,
    *,
    authorizer_jwk: Mapping[str, Any],
    declaration: Any,
    tool_call: Any,
    now: int | None,
) -> tuple[dict, dict]:
    obj = _as_object(bridge, "bridge")
    _check_keys(obj, ("profile", "authorization", "signature"), "bridge")
    _require(obj["profile"] == BRIDGE_PROFILE, "unknown bridge profile")
    authorization = obj["authorization"]
    _check_keys(authorization, AUTHORIZATION_REQUIRED, "authorization", AUTHORIZATION_OPTIONAL)
    public_key, raw = public_key_from_jwk(authorizer_jwk)
    _verify_signature(
        public_key, obj["signature"], signing_preimage(BRIDGE_PROFILE, "authorization", authorization),
        "bridge",
    )

    _require(authorization["cta_version"] == CTA_VERSION, "unsupported cta_version")
    _require(authorization["decision"] == "allow", "the signed decision is not allow")
    require_identifier(authorization["authorizer"], "authorizer")
    _require(authorization["authorizer_key_id"] == key_id(raw), "authorizer_key_id does not identify the trusted key")
    authorized_at = require_timestamp(authorization["authorized_at"], "authorized_at")
    expires_at = require_timestamp(authorization["expires_at"], "expires_at")
    _require(expires_at > authorized_at, "expires_at must be after authorized_at")
    instant = authorized_at if now is None else require_timestamp(now, "now")
    _require(instant >= authorized_at, "authorization is not yet valid")
    _require(instant < expires_at, "authorization has expired")

    for name in ("session_id", "request_id", "tool_name"):
        require_identifier(authorization[name], name)
    effect_class = authorization["tool_effect_class"]
    taint = authorization["taint_lattice_level"]
    _require(effect_class in EFFECT_CLASSES, "tool_effect_class is not a known effect class")
    _require(taint in TAINT_LEVELS, "taint_lattice_level is not a known level")
    for name in ("args_digest", "declaration_digest", "tool_call_digest"):
        require_digest(authorization[name], name)

    basis = authorization["decision_basis"]
    _require(basis == expected_basis(effect_class, taint), "decision_basis is inconsistent with effect class and taint")
    has_receipt = "step_up_receipt_hash" in authorization
    _require(has_receipt == (basis == BASIS_STEP_UP), "step_up_receipt_hash must be present exactly for a step-up basis")
    if has_receipt:
        require_digest(authorization["step_up_receipt_hash"], "step_up_receipt_hash")

    authorization_id = authorization["authorization_id"]
    _require(
        isinstance(authorization_id, str) and _AUTHORIZATION_ID.fullmatch(authorization_id) is not None,
        "authorization_id is malformed",
    )
    _require(authorization_id == authorization_id_for(authorization), "authorization_id does not match the decision")

    decl = _as_object(declaration, "declaration")
    _check_keys(decl, ("profile", "tool", "effect_class", "output_trust"), "declaration")
    _require(decl["profile"] == DECLARATION_PROFILE, "unknown declaration profile")
    _require(decl["tool"] == authorization["tool_name"], "declaration is for a different tool")
    _require(decl["effect_class"] == effect_class, "declaration effect class differs from the authorization")
    _require(decl["output_trust"] in OUTPUT_TRUST_VALUES, "declaration output_trust is not a known value")
    _require(digest_jcs(decl) == authorization["declaration_digest"], "declaration_digest does not match the declaration")

    call = _as_object(tool_call, "tool_call")
    _check_keys(call, ("name", "arguments"), "tool_call")
    _require(call["name"] == authorization["tool_name"], "tool_call names a different tool")
    _require(isinstance(call["arguments"], dict), "tool_call arguments must be an object")
    _require(digest_jcs(call) == authorization["tool_call_digest"], "tool_call_digest does not match the tool call")
    _require(digest_jcs(call["arguments"]) == authorization["args_digest"], "args_digest does not match the arguments")
    return obj, authorization


def verify_bridge(
    bridge: Any,
    *,
    authorizer_jwk: Mapping[str, Any],
    declaration: Any,
    tool_call: Any,
    now: int | None = None,
) -> dict:
    """Verify the detached `cta-trace-bridge-v1` envelope and return its authorization.

    Checks the strict structure, the signature by the pinned authorizer key, that
    `authorizer_key_id` is that key's `kid`, that `authorization_id` is the hash of the
    decision, the validity window at `now` (the authorization's own `authorized_at` when
    `now` is None), the declaration and tool-call digests, and that the decision basis
    is the only one its effect class and taint allow.
    """
    return _verify_bridge_object(
        bridge, authorizer_jwk=authorizer_jwk, declaration=declaration, tool_call=tool_call, now=now,
    )[1]


def verify_observation(document: Any, *, authorization: Mapping[str, Any]) -> dict:
    """Verify the post-dispatch observation document against the verified authorization.

    The document is `{"observation", "observer", "observed_at"}`. The inner
    `observation` must name the exact call it observed (`request_id`, `tool_name`,
    `args_digest`) and report `tool_call_count == 1`; further domain facts are allowed.
    `observed_at` must not precede `authorized_at`.
    """
    obj = _as_object(document, "observation document")
    _check_keys(obj, OBSERVATION_FIELDS, "observation document")
    require_identifier(obj["observer"], "observer")
    observed_at = require_timestamp(obj["observed_at"], "observed_at")
    _require(observed_at >= authorization["authorized_at"], "observed_at precedes the authorization")
    inner = obj["observation"]
    _require(isinstance(inner, dict), "observation must be an object")
    _require(set(OBSERVATION_BINDINGS) <= set(inner), "observation does not name the observed call")
    _require(inner["request_id"] == authorization["request_id"], "observation is for a different request")
    _require(inner["tool_name"] == authorization["tool_name"], "observation is for a different tool")
    _require(inner["args_digest"] == authorization["args_digest"], "observation is for different arguments")
    count = inner["tool_call_count"]
    _require(
        isinstance(count, int) and not isinstance(count, bool) and count == 1,
        "observation tool_call_count is not exactly 1",
    )
    return obj


def build_transcript(
    *,
    bridge: Mapping[str, Any],
    step_up_receipt_digest: str | None,
    tool_call: Mapping[str, Any],
    tool_response: Any,
    observation: Mapping[str, Any],
) -> dict:
    """The transcript preimage hashed into `tool_transcript.hash` (JCS-canonical)."""
    return {
        "profile": TRANSCRIPT_PROFILE,
        "authorization_bridge_digest": digest_jcs(dict(bridge)),
        "step_up_receipt_digest": step_up_receipt_digest,
        "tool_call": dict(tool_call),
        "tool_response": tool_response,
        "observation": dict(observation),
    }


def did_key_public_bytes(did: Any) -> bytes:
    """The raw Ed25519 public key inside a base58btc `did:key` (multicodec 0xed01)."""
    prefix = "did:key:z"
    _require(
        isinstance(did, str) and did.startswith(prefix) and len(did) <= 128,
        "subject is not a base58btc did:key",
    )
    n = 0
    for ch in did[len(prefix):]:
        index = _B58.find(ch)
        _require(index >= 0, "invalid base58btc character in did:key")
        n = n * 58 + index
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    _require(body[:2] == b"\xed\x01", "did:key multicodec is not Ed25519 (0xed01)")
    _require(len(body) - 2 == 32, "did:key does not hold a 32-byte Ed25519 key")
    return body[2:]


def _verify_authorization(
    *,
    bridge: Any,
    declaration: Any,
    tool_call: Any,
    authorizer_jwk: Mapping[str, Any],
    receipt: Any,
    policy_jwk: Mapping[str, Any] | None,
    now: int | None,
) -> tuple[dict, dict, dict]:
    bridge_obj, authorization = _verify_bridge_object(
        bridge, authorizer_jwk=authorizer_jwk, declaration=declaration, tool_call=tool_call, now=now,
    )
    checked = {
        "bridge_signature": True,
        "authorization_id_bound_to_decision": True,
        "declaration_bound": True,
        "tool_call_bound": True,
    }
    if authorization["decision_basis"] == BASIS_STEP_UP:
        _require(
            receipt is not None and policy_jwk is not None,
            "a step-up basis needs the receipt and the policy-engine key",
        )
        verified = verify_step_up_receipt(
            receipt, policy_jwk=policy_jwk, session_id=authorization["session_id"],
            request_id=authorization["request_id"], tool_name=authorization["tool_name"],
            args_digest=authorization["args_digest"], now=authorization["authorized_at"],
        )
        _require(
            verified["digest"] == authorization["step_up_receipt_hash"],
            "step_up_receipt_hash does not match the receipt",
        )
        checked["step_up_receipt_bound"] = True
    else:
        _require(receipt is None, "a receipt was supplied but the bridge cites none")
    return checked, bridge_obj, authorization


def verify_authorization_artifacts(
    *,
    bridge: Any,
    declaration: Any,
    tool_call: Any,
    authorizer_jwk: Mapping[str, Any],
    receipt: Any = None,
    policy_jwk: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> dict:
    """Verify the detached bridge, and the step-up receipt it cites, without a record.

    This is the public verifier for the bridge-only outcome (the gate allowed and signed
    a bridge, but no Trust Record was emitted). With a step-up basis the receipt and the
    pinned `policy_jwk` are required: the receipt must verify as of the authorization
    instant and its JCS digest must equal `step_up_receipt_hash`. A receipt supplied for
    a bridge that cites none is refused.
    """
    return _verify_authorization(
        bridge=bridge, declaration=declaration, tool_call=tool_call,
        authorizer_jwk=authorizer_jwk, receipt=receipt, policy_jwk=policy_jwk, now=now,
    )[0]


def verify_adapter_artifacts(
    *,
    record: Mapping[str, Any],
    bridge: Any,
    declaration: Any,
    tool_call: Any,
    authorizer_jwk: Mapping[str, Any],
    record_jwk: Mapping[str, Any],
    verification_time: int,
    receipt: Any = None,
    policy_jwk: Mapping[str, Any] | None = None,
    policy_bundle: bytes | None = None,
    transcript: Any = None,
    max_record_age_seconds: int | None = None,
) -> dict:
    """Verify the bridge, receipt, and Trust Record with only agentrust_trace + rfc8785.

    Runs the bridge-only checks, then: the record validates against the TRACE schema;
    its signature verifies against the pinned `record_jwk` (not merely its own embedded
    key) and `cnf.jwk` is that key; `origin.source_event_id` and exactly one
    `authorized-intent` reference carry the `authorization_id` and the bridge's JCS
    digest; `subject` is the `did:key` of `cnf.jwk.x`; the record states
    `software-only`, `third-party-control-plane`, `enforce`, and appraisal `none`. When
    `policy_bundle` is supplied, `policy.bundle_hash` and `runtime.measurement` must
    recompute from those exact bytes. When `transcript` is supplied, its bindings, the
    observation, and the signed `tool_transcript.hash` must hold.
    """
    try:
        require_timestamp(verification_time, "verification_time")
        checked, bridge_obj, authorization = _verify_authorization(
            bridge=bridge, declaration=declaration, tool_call=tool_call,
            authorizer_jwk=authorizer_jwk, receipt=receipt, policy_jwk=policy_jwk, now=None,
        )
        authorization_id = authorization["authorization_id"]

        validate_json(dict(record))
        _, record_raw = public_key_from_jwk(record_jwk)
        pinned = {"kty": "OKP", "crv": "Ed25519", "x": record_jwk["x"]}
        _require(record["cnf"]["jwk"] == pinned, "record cnf.jwk is not the pinned record key")
        verify_record(
            dict(record), pinned, now=verification_time, max_age_seconds=max_record_age_seconds,
        )
        checked["record_signature"] = True

        _require(record["origin"]["kind"] == "third-party-control-plane", "origin.kind is not third-party-control-plane")
        _require(record["origin"]["source_event_id"] == authorization_id, "origin.source_event_id is not the authorization_id")
        _require(record["runtime"]["platform"] == "software-only", "runtime.platform is not software-only")
        _require(record["appraisal"]["status"] == "none", "appraisal.status is not none")
        _require(record["policy"]["enforcement_mode"] == "enforce", "policy.enforcement_mode is not enforce")
        matching = [r for r in (record.get("references") or []) if r.get("id") == authorization_id]
        _require(len(matching) == 1, "expected exactly one reference citing the bridge")
        _require(matching[0].get("rel") == BRIDGE_REFERENCE_REL, "bridge reference rel is not authorized-intent")
        _require(matching[0].get("digest") == digest_jcs(bridge_obj), "bridge reference digest mismatch")
        checked["reference_matches_supplied_bridge"] = True

        _require(did_key_public_bytes(record["subject"]) == record_raw, "subject did:key does not decode to cnf.jwk.x")
        checked["subject_binds_cnf_jwk"] = True

        if policy_bundle is not None:
            bundle_hash = sha256_prefixed(policy_bundle)
            _require(record["policy"]["bundle_hash"] == bundle_hash, "policy.bundle_hash does not match the supplied policy bytes")
            measurement = sha256_prefixed(
                "\n".join([record["origin"]["producer"], record["subject"], bundle_hash]).encode("utf-8")
            )
            _require(record["runtime"]["measurement"] == measurement, "runtime.measurement does not recompute from the supplied policy bytes")
            checked["policy_bytes_bound"] = True

        if transcript is not None:
            body = _as_object(transcript, "transcript")
            _check_keys(body, TRANSCRIPT_FIELDS, "transcript")
            _require(body["profile"] == TRANSCRIPT_PROFILE, "unknown transcript profile")
            _require(body["authorization_bridge_digest"] == digest_jcs(bridge_obj), "transcript authorization_bridge_digest does not match the bridge")
            _require(
                digest_jcs(body["tool_call"]) == digest_jcs(_as_object(tool_call, "tool_call")),
                "transcript tool_call does not match the executed call",
            )
            _require(
                body["step_up_receipt_digest"] == authorization.get("step_up_receipt_hash"),
                "transcript step_up_receipt_digest does not match the bridge",
            )
            observation = verify_observation(body["observation"], authorization=authorization)
            _require(observation["observed_at"] <= record["iat"], "observation postdates the record")
            _require(
                record["tool_transcript"]["hash"] == sha256_prefixed(canonical_bytes(body)),
                "tool_transcript.hash does not match the supplied transcript preimage",
            )
            _require(record["tool_transcript"].get("call_count") == 1, "tool_transcript.call_count is not 1")
            checked["transcript_bound_and_hashed"] = True
        return checked
    except CtaVerifyError:
        raise
    except Exception as exc:  # normalize to the module's error, hide detail
        raise CtaVerifyError("adapter artifact verification failed") from exc
