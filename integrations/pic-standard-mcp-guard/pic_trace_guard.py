"""PIC Standard MCP guard allow decisions as signed TRACE Level 0 Trust Records.

Producer side (synchronous; wraps the released synchronous `guard_mcp_tool`, not
`guard_mcp_tool_async`). An outer `PicTraceCoordinator` requires a PIC proposal and the
reserved `__pic_request_id`, owns a `reserved -> bridged -> consumed` lifecycle in a
process-local store that tombstones recently used ids, and drives PIC's released
`on_allow` hook. Hook entry is proven by a coordinator-local `threading.Event` set
before any store write, so a store failure cannot be misread as a PIC block. The hook
builds and `verify_bridge`'s a detached authorization bridge before dispatch. After
dispatch a caller-supplied observation verifier returns a three-state verdict; only
`established` yields a record. The coordinator self-verifies with
`pic_trace_verify.verify_adapter_artifacts` before returning detached artifacts: an
`AuthorizationArtifacts` bundle whenever a bridge was produced (including later
failures), and the full `RecordArtifacts` bundle only for `record-emitted`. It does not
persist; the caller writes the artifacts.

Imports `pic_standard`, `agentrust_trace`, and `agentrust_trace_adapters`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Optional, Protocol

import rfc8785
from agentrust_trace.intent_bridge import digest_jcs, sign_bridge, verify_bridge
from agentrust_trace.sign import key_to_jwk, sign_record
from agentrust_trace_adapters import build_record
from agentrust_trace_adapters.evidence import PolicyEvidence, SourceSystem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pic_standard.config import policy_from_dict
from pic_standard.integrations import MCPAllowDecision, MCPToolCall
from pic_standard.integrations.mcp_pic_guard import evaluate_pic_for_tool_call, guard_mcp_tool

from pic_trace_verify import BRIDGE_REFERENCE_REL, build_transcript, verify_adapter_artifacts

_SAFE_INT_MAX = 2**53 - 1
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_DEFAULT_MAX_TRANSCRIPT_BYTES = 262144
_DEFAULT_MAX_REQUEST_ID_LEN = 512
_RESERVED_KEYS = ("__pic", "__pic_request_id")
_OBSERVATION_VERDICTS = ("established", "contradicted", "not-established")

AdapterStatus = Literal[
    "precondition-failed", "pic-blocked", "post-allow-error", "observation-failed",
    "record-emitted", "adapter-error",
]
PicDecision = Literal["not-evaluated", "blocked", "allowed"]
ObservationVerdict = Literal["established", "contradicted", "not-established"]
Clock = Callable[[], int]


class AdapterError(RuntimeError):
    """A coordinator/hook fail-closed condition; surfaced as a no-record outcome."""


def _positive_int(value: Any, name: str) -> int:
    """Require a strictly positive int (rejecting bool and float)."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise AdapterError(f"{name} must be a positive integer")
    return value


def _snapshot(value: Any) -> Any:
    """A JCS-canonical detached copy; requires `value` to be JSON/JCS serializable."""
    return json.loads(rfc8785.dumps(value))


def _reject_constant(token: str) -> Any:
    raise AdapterError(f"non-finite JSON constant in policy bundle: {token}")


def _strict_json_object(data: bytes) -> dict:
    """Parse `data` as a JSON object, rejecting duplicate keys and NaN/Infinity."""

    def _no_dupes(pairs: list[tuple[str, Any]]) -> dict:
        out: dict[str, Any] = {}
        for key, val in pairs:
            if key in out:
                raise AdapterError("duplicate key in policy bundle JSON object")
            out[key] = val
        return out

    obj = json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_reject_constant)
    if not isinstance(obj, dict):
        raise AdapterError("policy bundle must be a top-level JSON object")
    return obj


def _load_policy(policy_bundle: bytes) -> Any:
    """Parse a policy bundle to a PICPolicy, normalizing every malformed-input failure
    (bad UTF-8, malformed JSON, NaN/Infinity, duplicate keys, non-object, or a
    structurally invalid policy that `policy_from_dict` rejects) to AdapterError. Shared
    by the coordinator constructor and replay so the contract is identical."""
    if not isinstance(policy_bundle, bytes):
        raise AdapterError("policy_bundle must be bytes")
    try:
        obj = _strict_json_object(policy_bundle)
        return policy_from_dict(obj)
    except AdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AdapterError("invalid policy bundle") from exc


def _error_code(envelope: Any) -> Optional[str]:
    if not isinstance(envelope, Mapping):
        return None
    error = envelope.get("error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("code")
    return code if isinstance(code, str) else None


@dataclass(frozen=True)
class Observation:
    verdict: ObservationVerdict
    document: Mapping[str, Any]
    response_projection: Any  # bound into the transcript instead of the full envelope


@dataclass(frozen=True)
class AuthorizationArtifacts:
    """The verified pre-dispatch authorization; retained even when no record is emitted."""

    pic_decision_raw: bytes
    bridge: dict
    tool_call: dict
    pic_intent_digest: str
    pic_args_digest: str
    declaration: dict
    authorizer_jwk: dict


@dataclass(frozen=True)
class RecordArtifacts:
    authorization: AuthorizationArtifacts
    transcript: dict
    record: dict


@dataclass(frozen=True)
class AdapterOutcome:
    status: AdapterStatus
    pic_decision: PicDecision
    envelope: Any  # runtime value from the guard; not signed or guaranteed immutable
    authorization: Optional[AuthorizationArtifacts] = None
    record_artifacts: Optional[RecordArtifacts] = None
    absence: Optional[dict] = None


ObserveFn = Callable[[Any], Observation]


@dataclass(frozen=True)
class PicTraceConfig:
    """Explicit provenance inputs; no value is invented. `subject` is derived from
    `record_key`; the enforced PIC policy is parsed strictly from `policy_bundle`;
    `declaration` is snapshotted once at construction."""

    authorizer: str
    authorizer_key_id: str
    bridge_key: Ed25519PrivateKey
    record_key: Ed25519PrivateKey
    model_provider: str
    model_id: str
    data_class: str
    policy_bundle: bytes
    workload_digest: str
    declaration: Mapping[str, Any]
    resolver: str
    bridge_validity_seconds: int = 300
    max_transcript_bytes: int = _DEFAULT_MAX_TRANSCRIPT_BYTES
    max_request_id_len: int = _DEFAULT_MAX_REQUEST_ID_LEN


class ContextStore(Protocol):
    """Request-context lifecycle store. Implementations MUST make every operation
    atomic and thread-safe; `transition`/`consume` enforce the expected prior state.

    Contract:
    - `reserve()` is atomic and must leave no context behind when it raises; a rejected
      reservation (id already active or recently used) raises `AdapterError`.
    - `transition()` / `consume()` enforce the expected prior state and raise
      `AdapterError` otherwise.
    - `abandon_if_active()` is idempotent and must not raise; it removes only an active
      context for exactly this id, never another request's.
    - The store owns detached transition data and returns detached snapshots, so callers
      cannot mutate stored context and peek/consume results cannot mutate the store.

    The default store is process-local: its tombstones reject only recently used ids
    (bounded, so eviction eventually allows reuse). Durable global uniqueness across
    workers or restarts requires a shared persistent implementation."""

    def reserve(self, request_id: str) -> None: ...
    def transition(self, request_id: str, expected: str, new: str, **data: Any) -> None: ...
    def peek(self, request_id: str) -> Mapping[str, Any]: ...
    def consume(self, request_id: str, expected: str = "bridged") -> Mapping[str, Any]: ...
    def abandon_if_active(self, request_id: str) -> None: ...


class InMemoryContextStore:
    """Process-local store with bounded recent tombstones that reject reuse of a
    request id (until a tombstone is evicted). Not durable across workers or restarts."""

    def __init__(self, tombstone_capacity: int = 4096, max_request_id_len: int = _DEFAULT_MAX_REQUEST_ID_LEN) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, dict[str, Any]] = {}
        self._tombstones: "OrderedDict[str, str]" = OrderedDict()
        self._cap = _positive_int(tombstone_capacity, "tombstone_capacity")
        self._max_rid_len = _positive_int(max_request_id_len, "max_request_id_len")

    def reserve(self, request_id: str) -> None:
        if not isinstance(request_id, str) or not (0 < len(request_id) <= self._max_rid_len):
            raise AdapterError("request id missing or too long")
        with self._lock:
            if request_id in self._active or request_id in self._tombstones:
                raise AdapterError("request id already used")
            self._active[request_id] = {"state": "reserved"}

    def transition(self, request_id: str, expected: str, new: str, **data: Any) -> None:
        if "state" in data:
            raise AdapterError("transition data cannot override state")
        detached = copy.deepcopy(data)
        with self._lock:
            c = self._active.get(request_id)
            if c is None or c["state"] != expected:
                raise AdapterError(f"illegal transition {expected} -> {new}")
            c["state"] = new
            c.update(detached)

    def peek(self, request_id: str) -> Mapping[str, Any]:
        with self._lock:
            return copy.deepcopy(self._active.get(request_id) or {})

    def _tombstone(self, request_id: str, reason: str) -> None:
        self._tombstones[request_id] = reason
        while len(self._tombstones) > self._cap:
            self._tombstones.popitem(last=False)

    def consume(self, request_id: str, expected: str = "bridged") -> Mapping[str, Any]:
        with self._lock:
            c = self._active.get(request_id)
            if c is None or c["state"] != expected:
                raise AdapterError("cannot consume: not in expected state")
            self._active.pop(request_id)
            self._tombstone(request_id, "consumed")
            return copy.deepcopy(c)

    def abandon_if_active(self, request_id: str) -> None:
        with self._lock:
            if request_id in self._active:
                self._active.pop(request_id)
                self._tombstone(request_id, "abandoned")


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _base58btc(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def did_key(key: Ed25519PrivateKey) -> str:
    """did:key for an Ed25519 key: multicodec 0xed01 + raw key, base58btc, 'z'."""
    return "did:key:z" + _base58btc(b"\xed\x01" + _raw_public(key))


class PicTraceCoordinator:
    def __init__(
        self,
        config: PicTraceConfig,
        *,
        store: Optional[ContextStore] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        _positive_int(config.bridge_validity_seconds, "bridge_validity_seconds")
        _positive_int(config.max_transcript_bytes, "max_transcript_bytes")
        _positive_int(config.max_request_id_len, "max_request_id_len")
        if not isinstance(config.declaration, Mapping):
            raise AdapterError("declaration must be a mapping")
        if not isinstance(config.policy_bundle, bytes):
            raise AdapterError("policy_bundle must be bytes")
        self._cfg = config
        self._policy_bundle = config.policy_bundle  # immutable; the enforced and recorded bytes
        self._declaration = _snapshot(dict(config.declaration))  # frozen JCS copy
        self._subject = did_key(config.record_key)
        self._policy = _load_policy(self._policy_bundle)
        self._authorizer_jwk = {**key_to_jwk(config.bridge_key), "kid": config.authorizer_key_id}
        self._store: ContextStore = store or InMemoryContextStore(max_request_id_len=config.max_request_id_len)
        self._clock: Clock = clock or (lambda: int(time.time()))

    def _safe_timestamp(self) -> int:
        t = self._clock()
        if not isinstance(t, int) or isinstance(t, bool) or t < 0 or t > _SAFE_INT_MAX:
            raise AdapterError("clock returned an invalid timestamp")
        return t

    def _make_hook(
        self, rid: str, hook_entered: threading.Event
    ) -> Callable[[MCPAllowDecision, MCPToolCall], None]:
        cfg = self._cfg

        def on_allow(decision: MCPAllowDecision, tool_call: MCPToolCall) -> None:
            hook_entered.set()  # prove hook entry before any store write
            if not (decision.proposal_present and decision.intent_digest and decision.args_digest):
                raise AdapterError("adapter requires a proposal-backed allow")
            if decision.request_id != rid:
                raise AdapterError("decision.request_id does not match the reserved id")
            if not isinstance(decision.impact, str) or not decision.impact:
                raise AdapterError("proposal-backed decision has no impact")
            if decision.args_digest != tool_call.arguments_digest:
                raise AdapterError("args digest mismatch")
            call = tool_call.to_dict()
            if digest_jcs(call) != "sha256:" + tool_call.tool_call_digest:
                raise AdapterError("tool call digest mismatch")
            raw = decision.to_audit_bytes()
            authorized_at = self._safe_timestamp()
            expires_at = authorized_at + cfg.bridge_validity_seconds
            if not (authorized_at < expires_at <= _SAFE_INT_MAX):
                raise AdapterError("bridge expiry out of range")
            authorization = {
                "authorization_id": "urn:sha256:" + hashlib.sha256(raw).hexdigest(),
                "decision": "allow",
                "authorizer": cfg.authorizer,
                "authorizer_key_id": cfg.authorizer_key_id,
                "authorized_at": authorized_at,
                "expires_at": expires_at,
                "scope": {"tools": [decision.tool], "impacts": [decision.impact]},
                "pic": {
                    "profile": "PIC-CJSON/1.0",
                    "intent_digest": "sha256:" + decision.intent_digest,
                    "args_digest": "sha256:" + decision.args_digest,
                },
                "declaration_digest": digest_jcs(self._declaration),
                "tool_call_digest": digest_jcs(call),
                "transcript_required": False,
            }
            bridge = sign_bridge(authorization, cfg.bridge_key)
            verify_bridge(
                bridge, self._authorizer_jwk,
                declaration=self._declaration,
                pic_intent_digest="sha256:" + decision.intent_digest,
                pic_args_digest="sha256:" + decision.args_digest,
                tool_call=call, now=authorized_at,
            )
            self._store.transition(
                rid, "reserved", "bridged",
                raw=raw, bridge=bridge, tool_call=call,
                intent_digest=decision.intent_digest, args_digest=decision.args_digest,
            )

        return on_allow

    def _authz_from_ctx(self, ctx: Mapping[str, Any]) -> AuthorizationArtifacts:
        return AuthorizationArtifacts(
            pic_decision_raw=ctx["raw"],
            bridge=_snapshot(ctx["bridge"]),
            tool_call=_snapshot(ctx["tool_call"]),
            pic_intent_digest=ctx["intent_digest"],
            pic_args_digest=ctx["args_digest"],
            declaration=_snapshot(self._declaration),
            authorizer_jwk=_snapshot(self._authorizer_jwk),
        )

    def _safe_authz(self, rid: str) -> Optional[AuthorizationArtifacts]:
        """Best-effort authorization extraction that never escapes the fail-closed path."""
        try:
            ctx = self._store.peek(rid)
            if ctx.get("state") != "bridged":
                return None
            return self._authz_from_ctx(ctx)
        except Exception:  # noqa: BLE001
            return None

    def _validate_observation(self, observation: Any) -> None:
        if not isinstance(observation, Observation):
            raise AdapterError("observe did not return an Observation")
        if observation.verdict not in _OBSERVATION_VERDICTS:
            raise AdapterError("invalid observation verdict")
        if not isinstance(observation.document, Mapping):
            raise AdapterError("observation document must be a mapping")

    def run(
        self,
        *,
        tool_name: str,
        tool_fn: Callable[..., Any],
        kwargs: Mapping[str, Any],
        observe: ObserveFn,
        verify_evidence: bool = True,
        proposal_base_dir: Any = None,
        evidence_root_dir: Any = None,
        limits: Any = None,
        key_resolver: Any = None,
        strict_trust: bool = True,
    ) -> AdapterOutcome:
        cfg = self._cfg
        if kwargs.get("__pic") is None:
            return AdapterOutcome("precondition-failed", "not-evaluated", None, absence={"reason": "no_proposal"})
        rid = kwargs.get("__pic_request_id")
        if not isinstance(rid, str) or not rid or rid != rid.strip() or len(rid) > cfg.max_request_id_len:
            return AdapterOutcome("precondition-failed", "not-evaluated", None, absence={"reason": "bad_request_id"})
        try:
            self._store.reserve(rid)
        except AdapterError:
            return AdapterOutcome("precondition-failed", "not-evaluated", None, absence={"reason": "request_id_unavailable"})

        hook_entered = threading.Event()
        envelope: Any = None
        try:
            guarded = guard_mcp_tool(
                tool_name, tool_fn, policy=self._policy, limits=limits,
                verify_evidence=verify_evidence, proposal_base_dir=proposal_base_dir,
                evidence_root_dir=evidence_root_dir, strict_trust=strict_trust,
                key_resolver=key_resolver, on_allow=self._make_hook(rid, hook_entered),
            )
            envelope = guarded(**dict(kwargs))
            state = self._store.peek(rid).get("state")
            entered = hook_entered.is_set()

            if state == "bridged":
                ctx = self._store.peek(rid)
                authz = self._authz_from_ctx(ctx)
                if isinstance(envelope, Mapping) and envelope.get("isError"):  # tool failed after allow
                    return AdapterOutcome(
                        "post-allow-error", "allowed", envelope, authorization=authz,
                        absence={"reason": "tool_error_after_allow", "error_code": _error_code(envelope)},
                    )
                observation = observe(envelope)  # trusted callback; raw runtime envelope
                self._validate_observation(observation)
                if observation.verdict != "established":
                    return AdapterOutcome(
                        "observation-failed", "allowed", envelope, authorization=authz,
                        absence={"reason": "observation_" + observation.verdict},
                    )
                try:
                    record_artifacts = self._finalize(ctx, authz, observation)
                except Exception:  # noqa: BLE001 - keep the verified authorization bundle
                    return AdapterOutcome(
                        "post-allow-error", "allowed", envelope, authorization=authz,
                        absence={"reason": "finalization_failed"},
                    )
                self._store.consume(rid, expected="bridged")
                return AdapterOutcome(
                    "record-emitted", "allowed", envelope,
                    authorization=record_artifacts.authorization, record_artifacts=record_artifacts,
                )

            if entered:  # PIC allowed and the hook ran, but no bridge was produced; no dispatch
                return AdapterOutcome(
                    "post-allow-error", "allowed", envelope,
                    absence={"reason": "hook_failed_before_bridge", "error_code": _error_code(envelope)},
                )

            # Hook never entered.
            if isinstance(envelope, Mapping) and envelope.get("isError"):  # PIC blocked/refused before the hook
                return AdapterOutcome(
                    "pic-blocked", "blocked", envelope,
                    absence={"reason": "pic_blocked", "error_code": _error_code(envelope)},
                )
            # A non-error envelope with no hook entry is an inconsistent adapter condition.
            return AdapterOutcome("adapter-error", "not-evaluated", envelope, absence={"reason": "no_hook_entry"})
        except Exception:  # noqa: BLE001 - fail closed; never emit a record on error
            authz = self._safe_authz(rid)
            if authz is not None:
                return AdapterOutcome("post-allow-error", "allowed", envelope, authorization=authz, absence={"reason": "adapter_error"})
            if hook_entered.is_set():
                return AdapterOutcome("post-allow-error", "allowed", envelope, absence={"reason": "adapter_error"})
            return AdapterOutcome("adapter-error", "not-evaluated", envelope, absence={"reason": "adapter_error"})
        finally:
            self._store.abandon_if_active(rid)  # idempotent; no-op after consume()

    def _finalize(
        self, ctx: Mapping[str, Any], authz: AuthorizationArtifacts, observation: Observation
    ) -> RecordArtifacts:
        cfg = self._cfg
        raw, bridge, call = ctx["raw"], ctx["bridge"], ctx["tool_call"]
        authorization_id = bridge["authorization"]["authorization_id"]
        authorized_at = bridge["authorization"]["authorized_at"]
        # The record timestamp comes from the injected clock too, and cannot precede the
        # authorization. Bridge validity is still checked at authorized_at; execution may
        # legitimately finish after the bridge expires.
        record_iat = self._safe_timestamp()
        if record_iat < authorized_at:
            raise AdapterError("record iat precedes authorization")

        transcript = build_transcript(
            pic_decision_raw=raw, bridge=bridge, tool_call=call,
            tool_response=_snapshot(observation.response_projection),
            observation=_snapshot(dict(observation.document)),
        )
        transcript_bytes = rfc8785.dumps(transcript)
        if len(transcript_bytes) > cfg.max_transcript_bytes:
            raise AdapterError("transcript exceeds max_transcript_bytes")

        record = build_record(
            source=SourceSystem(producer=cfg.authorizer, source_event_id=authorization_id),
            subject=self._subject,
            model_provider=cfg.model_provider, model_id=cfg.model_id,
            policy=PolicyEvidence(bundle=self._policy_bundle, enforcement_mode="enforce"),
            data_class=cfg.data_class, jwk=key_to_jwk(cfg.record_key),
            transcript_bytes=transcript_bytes, tool_call_count=1,
            workload_digest=cfg.workload_digest, iat=record_iat,
        )
        record["references"] = [{
            "rel": BRIDGE_REFERENCE_REL, "id": authorization_id,
            "resolver": cfg.resolver, "digest": digest_jcs(bridge),
        }]
        signed = sign_record(record, cfg.record_key)
        # Self-verify the complete bundle before returning (raises on any failure).
        verify_adapter_artifacts(
            record=signed, bridge=bridge, pic_decision_raw=raw,
            declaration=self._declaration,
            pic_intent_digest=ctx["intent_digest"], pic_args_digest=ctx["args_digest"],
            tool_call=call, authorizer_jwk=self._authorizer_jwk, transcript=transcript,
        )
        return RecordArtifacts(
            authorization=authz,
            transcript=_snapshot(transcript),
            record=_snapshot(signed),
        )


def replay_pic_verification(
    *,
    proposal: Mapping[str, Any],
    policy_bundle: bytes,
    tool_args: Mapping[str, Any],
    limits: Any = None,
    verify_evidence: bool = True,
    proposal_base_dir: Any = None,
    evidence_root_dir: Any = None,
    key_resolver: Any = None,
    strict_trust: bool = True,
    request_id: Optional[str] = None,
) -> Any:
    """Re-evaluate `proposal` against the PIC pipeline NOW, from the exact policy bytes.

    This is a CURRENT re-evaluation, not proof of the historical trust state: faithful
    historical reproduction requires the original trust and key snapshot, policy bytes,
    evidence bytes, `limits`, and verification configuration as they were at decision
    time. `tool_args` must be the sanitized business arguments; the reserved `__pic` /
    `__pic_request_id` keys are supplied by this function, not by the caller. Returns
    `evaluate_pic_for_tool_call`'s 2-tuple or raises `PICError`.
    """
    for reserved in _RESERVED_KEYS:
        if reserved in tool_args:
            raise AdapterError("tool_args must be sanitized business arguments without reserved keys")
    if request_id is not None:
        if not isinstance(request_id, str) or not request_id or request_id != request_id.strip() \
                or len(request_id) > _DEFAULT_MAX_REQUEST_ID_LEN:
            raise AdapterError("invalid request_id")
    policy = _load_policy(policy_bundle)
    call_args = {**dict(tool_args), "__pic": dict(proposal)}
    if request_id is not None:
        call_args["__pic_request_id"] = request_id
    return evaluate_pic_for_tool_call(
        tool_name=proposal["action"]["tool"], tool_args=call_args, policy=policy, limits=limits,
        verify_evidence=verify_evidence, proposal_base_dir=proposal_base_dir,
        evidence_root_dir=evidence_root_dir, key_resolver=key_resolver, strict_trust=strict_trust,
    )
