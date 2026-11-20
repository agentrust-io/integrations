"""WIMSE Context Taint Attestation (CTA) MCP guard: signed TRACE Level 0 Trust Records.

Producer side. `CtaGuard.run` gates one tool call before it dispatches, then records
what happened:

1. Session taint is sticky. `ingest_untrusted` (and any tool whose pinned declaration
   says its output is untrusted) moves a session from `TRUSTED_ONLY` to
   `UNTRUSTED_INGESTED`; nothing moves it back, and a caller-supplied taint claim can
   only raise it.
2. Tool effect class comes from the pinned declaration in the policy bundle. Runtime
   annotations such as `readOnlyHint` are accepted and never read. A tool with no
   declaration is `STATE_MUTATING` with untrusted output.
3. A `STATE_MUTATING` call in an `UNTRUSTED_INGESTED` session is refused with
   `CTA_TAINTED_CONTROL_PLANE` before the tool is entered, unless a policy-engine
   `StepUpReceipt` bound to `(session_id, request_id, tool_name, args_digest)` verifies.
4. On allow, a detached `cta-trace-bridge-v1` bridge is signed and verified before
   dispatch. After dispatch a caller-supplied observer returns a verdict; only
   `established`, with a document that names this exact call, yields a Trust Record,
   built with `agentrust_trace_adapters.build_record`, signed with
   `agentrust_trace.sign_record`, and self-verified by `cta_trace_verify`.

State is process-local. The guard does not persist anything; the caller writes the
returned artifacts. Imports `agentrust_trace` and `agentrust_trace_adapters`.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from agentrust_trace import key_to_jwk, sign_record
from agentrust_trace_adapters import build_record
from agentrust_trace_adapters.evidence import PolicyEvidence, SourceSystem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cta_trace_verify import (
    BRIDGE_PROFILE,
    BRIDGE_REFERENCE_REL,
    CTA_VERSION,
    DECLARATION_PROFILE,
    EFFECT_CLASSES,
    OUTPUT_TRUST_VALUES,
    POLICY_PROFILE,
    READ_ONLY,
    SAFE_INT_MAX,
    STATE_MUTATING,
    TAINT_LEVELS,
    TRUSTED_ONLY,
    UNTRUSTED_INGESTED,
    CtaVerifyError,
    authorization_id_for,
    build_transcript,
    canonical_bytes,
    digest_jcs,
    expected_basis,
    key_id,
    loads_unique,
    public_key_from_jwk,
    require_digest,
    require_identifier,
    require_timestamp,
    signing_preimage,
    verify_adapter_artifacts,
    verify_bridge,
    verify_observation,
    verify_step_up_receipt,
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_DEFAULT_MAX_TRANSCRIPT_BYTES = 262144
_MIN_PLAUSIBLE_TIMESTAMP = 1_700_000_000  # the TRACE v0.2 schema minimum for iat
_OBSERVATION_VERDICTS = ("established", "contradicted", "not-established")

Clock = Callable[[], int]
ObserveFn = Callable[[Any], "Observation"]


class CtaGuardError(RuntimeError):
    """A configuration, policy, or internal fail-closed condition."""


class _Stop(Exception):
    """Internal: end a run with a no-record outcome."""

    def __init__(self, status: str, code: str, reason: str, detail: str | None = None) -> None:
        super().__init__(reason)
        self.status = status
        self.code = code
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ToolDeclaration:
    """A pinned tool declaration. `effect_class` is what the gate enforces."""

    tool: str
    effect_class: str
    output_trust: str

    def to_dict(self) -> dict:
        return {
            "profile": DECLARATION_PROFILE,
            "tool": self.tool,
            "effect_class": self.effect_class,
            "output_trust": self.output_trust,
        }


@dataclass(frozen=True)
class GatePolicy:
    step_up_key_id: str
    tools: Mapping[str, ToolDeclaration]


def _exact_fields(obj: Any, fields: tuple, name: str) -> None:
    if not isinstance(obj, dict) or set(obj) != set(fields):
        raise CtaVerifyError(f"{name} must have exactly the fields {sorted(fields)}")


def load_policy(policy_bundle: bytes) -> GatePolicy:
    """Parse the exact policy bytes the guard enforces and records.

    The bundle is a strict JSON object (duplicate keys and non-finite numbers refused):
    `{"profile": "cta-gate-policy/v1", "step_up_key_id": "sha256:<hex>", "tools":
    {<name>: {"effect_class": "READ_ONLY"|"STATE_MUTATING", "output_trust":
    "trusted"|"untrusted"}}}`. Raises `CtaGuardError` on anything else.
    """
    if not isinstance(policy_bundle, bytes) or not policy_bundle:
        raise CtaGuardError("policy_bundle must be non-empty bytes")
    try:
        obj = loads_unique(policy_bundle)
        _exact_fields(obj, ("profile", "step_up_key_id", "tools"), "policy bundle")
        if obj["profile"] != POLICY_PROFILE:
            raise CtaVerifyError("unknown policy profile")
        require_digest(obj["step_up_key_id"], "step_up_key_id")
        if not isinstance(obj["tools"], dict):
            raise CtaVerifyError("tools must be an object")
        tools: dict[str, ToolDeclaration] = {}
        for name, entry in obj["tools"].items():
            require_identifier(name, "tool name")
            _exact_fields(entry, ("effect_class", "output_trust"), f"tool entry {name}")
            if entry["effect_class"] not in EFFECT_CLASSES:
                raise CtaVerifyError("tool effect_class is not a known effect class")
            if entry["output_trust"] not in OUTPUT_TRUST_VALUES:
                raise CtaVerifyError("tool output_trust is not a known value")
            tools[name] = ToolDeclaration(name, entry["effect_class"], entry["output_trust"])
    except CtaVerifyError as exc:
        raise CtaGuardError(f"invalid policy bundle: {exc}") from exc
    return GatePolicy(step_up_key_id=obj["step_up_key_id"], tools=tools)


@dataclass(frozen=True)
class Observation:
    """A caller-supplied post-dispatch observation.

    `document` is `{"observation": {...}, "observer": str, "observed_at": int}` and its
    inner object must name the call (`request_id`, `tool_name`, `args_digest`) and carry
    `tool_call_count == 1`. `response_projection` is bound into the transcript instead
    of the raw tool return value.
    """

    verdict: str
    document: Mapping[str, Any]
    response_projection: Any


@dataclass(frozen=True)
class AuthorizationArtifacts:
    """The verified pre-dispatch authorization; retained even when no record is emitted."""

    bridge: dict
    declaration: dict
    tool_call: dict
    authorizer_jwk: dict
    step_up_receipt: dict | None = None
    policy_engine_jwk: dict | None = None


@dataclass(frozen=True)
class RecordArtifacts:
    authorization: AuthorizationArtifacts
    transcript: dict
    record: dict


@dataclass(frozen=True)
class CtaOutcome:
    """The result of one `CtaGuard.run`.

    `status` is one of `precondition-failed`, `blocked`, `authorization-failed`,
    `dispatch-error`, `observation-failed`, `adapter-error`, `record-emitted`. `events`
    is the guard's own ordered log. `result` is the raw tool return value: it is not
    signed and not guaranteed immutable.
    """

    status: str
    code: str | None
    reason: str | None
    taint: str | None
    effect_class: str | None
    tool_entered: bool
    events: tuple
    result: Any = None
    detail: str | None = None
    taint_claim_ignored: bool = False
    authorization: AuthorizationArtifacts | None = None
    record_artifacts: RecordArtifacts | None = None


@dataclass(frozen=True)
class CtaConfig:
    """Explicit inputs; no value is invented.

    `policy_engine_jwk` is the public key whose signatures on a StepUpReceipt the gate
    accepts; its `kid` must equal the `step_up_key_id` inside `policy_bundle`, so the
    recorded policy bytes commit to which approver key was trusted. The bridge, record,
    and policy-engine keys must be pairwise distinct.
    """

    authorizer: str
    bridge_key: Ed25519PrivateKey
    record_key: Ed25519PrivateKey
    policy_engine_jwk: Mapping[str, Any]
    policy_bundle: bytes
    model_provider: str
    model_id: str
    data_class: str
    workload_digest: str
    resolver: str
    bridge_validity_seconds: int = 300
    max_transcript_bytes: int = _DEFAULT_MAX_TRANSCRIPT_BYTES
    tombstone_capacity: int = 4096


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise CtaGuardError(f"{name} must be a positive integer")
    return value


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CtaGuardError(f"{name} must be a non-empty string")
    return value


def _snapshot(value: Any) -> Any:
    """A detached, RFC 8785-canonical copy of a JSON value."""
    return json.loads(canonical_bytes(value))


def _is_identifier(value: Any) -> bool:
    try:
        require_identifier(value, "value")
    except CtaVerifyError:
        return False
    return True


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


def sign_envelope(profile: str, field: str, body: Mapping[str, Any], key: Ed25519PrivateKey) -> dict:
    """`{"profile", field: body, "signature"}` signed over `signing_preimage`."""
    signature = base64.urlsafe_b64encode(key.sign(signing_preimage(profile, field, dict(body))))
    return {"profile": profile, field: _snapshot(dict(body)), "signature": signature.rstrip(b"=").decode("ascii")}


class _RequestStore:
    """Request ids are single-use: active ones and a bounded set of recent ones are refused.

    Tombstones are bounded, so eviction eventually allows an id to be reused; durable
    uniqueness across workers or restarts needs a shared persistent store.
    """

    def __init__(self, capacity: int) -> None:
        self._lock = threading.Lock()
        self._active: set[str] = set()
        self._tombstones: OrderedDict[str, None] = OrderedDict()
        self._capacity = capacity

    def reserve(self, request_id: str) -> bool:
        with self._lock:
            if request_id in self._active or request_id in self._tombstones:
                return False
            self._active.add(request_id)
            return True

    def finish(self, request_id: str) -> None:
        with self._lock:
            self._active.discard(request_id)
            self._tombstones[request_id] = None
            while len(self._tombstones) > self._capacity:
                self._tombstones.popitem(last=False)


class _ReceiptLedger:
    """Verified receipt ids are spent until they expire, independent of request-id eviction."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._spent: dict[str, int] = {}

    def spend(self, receipt_id: str, exp: int, now: int) -> bool:
        with self._lock:
            for old in [r for r, e in self._spent.items() if e <= now]:
                del self._spent[old]
            if receipt_id in self._spent:
                return False
            self._spent[receipt_id] = exp
            return True


class _RunState:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.taint: str | None = None
        self.effect_class: str | None = None
        self.tool_entered = False
        self.claim_ignored = False
        self.result: Any = None
        self.authorization: AuthorizationArtifacts | None = None

    def outcome(
        self, status: str, code: str | None, reason: str | None, detail: str | None = None,
        record_artifacts: RecordArtifacts | None = None,
    ) -> CtaOutcome:
        return CtaOutcome(
            status=status, code=code, reason=reason, taint=self.taint, effect_class=self.effect_class,
            tool_entered=self.tool_entered, events=tuple(self.events), result=self.result,
            detail=detail, taint_claim_ignored=self.claim_ignored,
            authorization=self.authorization, record_artifacts=record_artifacts,
        )


class CtaGuard:
    def __init__(self, config: CtaConfig, *, clock: Clock | None = None) -> None:
        self._policy = load_policy(config.policy_bundle)
        try:
            if not isinstance(config.bridge_key, Ed25519PrivateKey) or not isinstance(config.record_key, Ed25519PrivateKey):
                raise CtaGuardError("bridge_key and record_key must be Ed25519PrivateKey")
            _positive_int(config.bridge_validity_seconds, "bridge_validity_seconds")
            _positive_int(config.max_transcript_bytes, "max_transcript_bytes")
            _positive_int(config.tombstone_capacity, "tombstone_capacity")
            for name in ("model_provider", "model_id", "data_class"):
                _nonempty(getattr(config, name), name)
            require_identifier(config.authorizer, "authorizer")
            require_identifier(config.resolver, "resolver")
            require_digest(config.workload_digest, "workload_digest")
            _, policy_raw = public_key_from_jwk(config.policy_engine_jwk)
        except CtaVerifyError as exc:
            raise CtaGuardError(f"invalid configuration: {exc}") from exc
        if key_id(policy_raw) != self._policy.step_up_key_id:
            raise CtaGuardError("policy_engine_jwk is not the step_up_key_id pinned in the policy bundle")
        raws = {_raw_public(config.bridge_key), _raw_public(config.record_key), policy_raw}
        if len(raws) != 3:
            raise CtaGuardError("bridge, record, and policy-engine keys must be pairwise distinct")

        self._cfg = config
        self._policy_bundle = config.policy_bundle
        self._authorizer_jwk = {**key_to_jwk(config.bridge_key), "kid": key_id(_raw_public(config.bridge_key))}
        self._record_jwk = key_to_jwk(config.record_key)
        self._policy_jwk = {**config.policy_engine_jwk}
        self._subject = did_key(config.record_key)
        self._clock: Clock = clock or (lambda: int(time.time()))
        self._lock = threading.Lock()
        self._sessions: dict[str, str] = {}
        self._requests = _RequestStore(config.tombstone_capacity)
        self._receipts = _ReceiptLedger()

    @property
    def authorizer_jwk(self) -> dict:
        """The public bridge-verification key, with its `kid`."""
        return dict(self._authorizer_jwk)

    @property
    def record_jwk(self) -> dict:
        """The public record-verification key."""
        return dict(self._record_jwk)

    def ingest_untrusted(self, session_id: str) -> str:
        """Record that the session ingested untrusted data. Sticky; returns the new level."""
        if not _is_identifier(session_id):
            raise CtaGuardError("session_id must be 1-512 printable ASCII characters without whitespace")
        return self._mark_untrusted(session_id)

    def taint_level(self, session_id: str) -> str:
        """The session's tracked level; a session never seen is `TRUSTED_ONLY`."""
        with self._lock:
            return self._sessions.get(session_id, TRUSTED_ONLY)

    def declaration_for(self, tool_name: str) -> ToolDeclaration:
        """The pinned declaration; a tool without one is `STATE_MUTATING`, untrusted output."""
        return self._policy.tools.get(tool_name) or ToolDeclaration(tool_name, STATE_MUTATING, "untrusted")

    def _mark_untrusted(self, session_id: str) -> str:
        with self._lock:
            self._sessions[session_id] = UNTRUSTED_INGESTED
            return UNTRUSTED_INGESTED

    def _effective_taint(self, session_id: str, claimed: str | None) -> tuple[str, bool]:
        with self._lock:
            level = self._sessions.get(session_id, TRUSTED_ONLY)
            if claimed == UNTRUSTED_INGESTED:
                level = UNTRUSTED_INGESTED
            self._sessions[session_id] = level
            return level, claimed == TRUSTED_ONLY and level == UNTRUSTED_INGESTED

    def _now(self) -> int:
        now = require_timestamp(self._clock(), "clock value")
        if now < _MIN_PLAUSIBLE_TIMESTAMP:
            raise CtaGuardError("clock value precedes the TRACE schema minimum for iat")
        return now

    def run(
        self,
        *,
        session_id: str,
        request_id: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        arguments: Mapping[str, Any],
        observe: ObserveFn,
        step_up_receipt: Any = None,
        claimed_taint: str | None = None,
        runtime_annotations: Mapping[str, Any] | None = None,
    ) -> CtaOutcome:
        """Gate, dispatch, observe, and record one tool call; never raises for a bad call.

        `claimed_taint` models a caller-supplied taint claim: it can raise the session to
        `UNTRUSTED_INGESTED` and can never lower it. `runtime_annotations` (for example a
        server's `readOnlyHint`) is accepted so a host can pass tool metadata through; it
        is never read. `step_up_receipt` is read only when the gate requires one.
        """
        st = _RunState()
        reason = self._precondition_failure(
            session_id, request_id, tool_name, tool_fn, arguments, observe, claimed_taint,
        )
        if reason is not None:
            return st.outcome("precondition-failed", "CTA_BAD_REQUEST", reason)
        if not self._requests.reserve(request_id):
            return st.outcome("precondition-failed", "CTA_REQUEST_ID_REUSED", "request_id_reused")
        st.events.append("request_reserved")
        try:
            return self._run_reserved(
                st, session_id, request_id, tool_name, tool_fn, _snapshot(dict(arguments)),
                observe, step_up_receipt, claimed_taint,
            )
        except _Stop as stop:
            return st.outcome(stop.status, stop.code, stop.reason, stop.detail)
        except Exception:  # noqa: BLE001 - fail closed; never emit a record on error
            return st.outcome("adapter-error", "CTA_ADAPTER_ERROR", "adapter_error")
        finally:
            self._requests.finish(request_id)

    @staticmethod
    def _precondition_failure(
        session_id: Any, request_id: Any, tool_name: Any, tool_fn: Any, arguments: Any,
        observe: Any, claimed_taint: Any,
    ) -> str | None:
        for name, value in (("session_id", session_id), ("request_id", request_id), ("tool_name", tool_name)):
            if not _is_identifier(value):
                return "bad_" + name
        if not isinstance(arguments, Mapping):
            return "bad_arguments"
        try:
            _snapshot(dict(arguments))
        except CtaVerifyError:
            return "bad_arguments"
        if not callable(tool_fn) or not callable(observe):
            return "bad_callable"
        if claimed_taint is not None and claimed_taint not in TAINT_LEVELS:
            return "bad_taint_claim"
        return None

    def _run_reserved(
        self, st: _RunState, session_id: str, request_id: str, tool_name: str,
        tool_fn: Callable[..., Any], args: dict, observe: ObserveFn, receipt: Any,
        claimed_taint: str | None,
    ) -> CtaOutcome:
        cfg = self._cfg
        declaration = self.declaration_for(tool_name)
        st.effect_class = declaration.effect_class
        st.taint, st.claim_ignored = self._effective_taint(session_id, claimed_taint)
        st.events.append("taint_evaluated")
        args_digest = digest_jcs(args)

        receipt_info = None
        if declaration.effect_class != READ_ONLY and st.taint != TRUSTED_ONLY:
            receipt_info = self._check_step_up(st, receipt, session_id, request_id, tool_name, args_digest)

        call = {"name": tool_name, "arguments": args}
        decl_dict = declaration.to_dict()
        authorized_at = self._now()
        expires_at = authorized_at + cfg.bridge_validity_seconds
        if expires_at > SAFE_INT_MAX:
            raise CtaGuardError("bridge expiry out of range")
        authorization: dict[str, Any] = {
            "cta_version": CTA_VERSION,
            "decision": "allow",
            "decision_basis": expected_basis(declaration.effect_class, st.taint),
            "session_id": session_id,
            "request_id": request_id,
            "tool_name": tool_name,
            "tool_effect_class": declaration.effect_class,
            "taint_lattice_level": st.taint,
            "args_digest": args_digest,
            "declaration_digest": digest_jcs(decl_dict),
            "tool_call_digest": digest_jcs(call),
        }
        if receipt_info is not None:
            authorization["step_up_receipt_hash"] = receipt_info["digest"]
        authorization["authorization_id"] = authorization_id_for(authorization)
        authorization.update(
            authorizer=cfg.authorizer, authorizer_key_id=self._authorizer_jwk["kid"],
            authorized_at=authorized_at, expires_at=expires_at,
        )
        bridge = sign_envelope(BRIDGE_PROFILE, "authorization", authorization, cfg.bridge_key)
        st.events.append("bridge_signed")
        try:
            verify_bridge(
                bridge, authorizer_jwk=self._authorizer_jwk, declaration=decl_dict, tool_call=call,
                now=self._now(),
            )
        except CtaVerifyError as exc:
            raise _Stop("authorization-failed", "CTA_AUTHORIZATION_FAILED", "bridge_verification_failed", str(exc)) from exc
        st.events.append("bridge_verified")
        st.authorization = AuthorizationArtifacts(
            bridge=_snapshot(bridge), declaration=decl_dict, tool_call=_snapshot(call),
            authorizer_jwk=dict(self._authorizer_jwk),
            step_up_receipt=_snapshot(receipt_info["envelope"]) if receipt_info else None,
            policy_engine_jwk=dict(self._policy_jwk) if receipt_info else None,
        )

        st.events.append("tool_entered")
        st.tool_entered = True
        try:
            st.result = tool_fn(**_snapshot(args))
        except Exception as exc:
            if declaration.output_trust == "untrusted":
                self._mark_untrusted(session_id)
            st.events.append("tool_raised")
            raise _Stop("dispatch-error", "CTA_DISPATCH_ERROR", "tool_raised") from exc
        if declaration.output_trust == "untrusted":
            self._mark_untrusted(session_id)
        st.events.append("tool_returned")

        observation = self._observe(st, observe, authorization)
        try:
            artifacts = self._finalize(st, authorization, bridge, decl_dict, call, receipt_info, observation)
        except Exception as exc:
            raise _Stop("adapter-error", "CTA_ADAPTER_ERROR", "finalization_failed") from exc
        return st.outcome("record-emitted", None, None, record_artifacts=artifacts)

    def _check_step_up(
        self, st: _RunState, receipt: Any, session_id: str, request_id: str, tool_name: str,
        args_digest: str,
    ) -> dict:
        if receipt is None:
            raise _Stop("blocked", "CTA_TAINTED_CONTROL_PLANE", "no_step_up_receipt")
        now = self._now()
        try:
            info = verify_step_up_receipt(
                receipt, policy_jwk=self._policy_jwk, session_id=session_id, request_id=request_id,
                tool_name=tool_name, args_digest=args_digest, now=now,
            )
        except CtaVerifyError as exc:
            raise _Stop("blocked", "CTA_TAINTED_CONTROL_PLANE", "step_up_receipt_invalid", str(exc)) from exc
        body = info["receipt"]
        if not self._receipts.spend(body["receipt_id"], body["exp"], now):
            raise _Stop("blocked", "CTA_TAINTED_CONTROL_PLANE", "step_up_receipt_replayed")
        st.events.append("step_up_verified")
        return info

    def _observe(self, st: _RunState, observe: ObserveFn, authorization: Mapping[str, Any]) -> Observation:
        try:
            observation = observe(st.result)
        except Exception as exc:
            raise _Stop("observation-failed", "CTA_OBSERVATION_FAILED", "observer_error") from exc
        if (
            not isinstance(observation, Observation)
            or observation.verdict not in _OBSERVATION_VERDICTS
            or not isinstance(observation.document, Mapping)
        ):
            raise _Stop("observation-failed", "CTA_OBSERVATION_FAILED", "observation_invalid")
        if observation.verdict != "established":
            raise _Stop("observation-failed", "CTA_OBSERVATION_FAILED", "observation_" + observation.verdict)
        try:
            verify_observation(observation.document, authorization=authorization)
        except CtaVerifyError as exc:
            raise _Stop("observation-failed", "CTA_OBSERVATION_FAILED", "observation_binding_mismatch", str(exc)) from exc
        st.events.append("observation_verified")
        return observation

    def _finalize(
        self, st: _RunState, authorization: Mapping[str, Any], bridge: dict, decl_dict: dict,
        call: dict, receipt_info: dict | None, observation: Observation,
    ) -> RecordArtifacts:
        cfg = self._cfg
        record_iat = self._now()
        if record_iat < authorization["authorized_at"]:
            raise CtaGuardError("record iat precedes authorization")
        transcript = build_transcript(
            bridge=bridge,
            step_up_receipt_digest=receipt_info["digest"] if receipt_info else None,
            tool_call=call,
            tool_response=_snapshot(observation.response_projection),
            observation=_snapshot(dict(observation.document)),
        )
        transcript_bytes = canonical_bytes(transcript)
        if len(transcript_bytes) > cfg.max_transcript_bytes:
            raise CtaGuardError("transcript exceeds max_transcript_bytes")

        record = build_record(
            source=SourceSystem(producer=cfg.authorizer, source_event_id=authorization["authorization_id"]),
            subject=self._subject,
            model_provider=cfg.model_provider, model_id=cfg.model_id,
            policy=PolicyEvidence(bundle=self._policy_bundle, enforcement_mode="enforce"),
            data_class=cfg.data_class, jwk=self._record_jwk,
            transcript_bytes=transcript_bytes, tool_call_count=1,
            workload_digest=cfg.workload_digest, iat=record_iat,
        )
        record["references"] = [{
            "rel": BRIDGE_REFERENCE_REL, "id": authorization["authorization_id"],
            "resolver": cfg.resolver, "digest": digest_jcs(bridge),
        }]
        signed = sign_record(record, cfg.record_key)
        st.events.append("record_signed")
        verify_adapter_artifacts(
            record=signed, bridge=bridge, declaration=decl_dict, tool_call=call,
            authorizer_jwk=self._authorizer_jwk, record_jwk=self._record_jwk,
            verification_time=record_iat,
            receipt=receipt_info["envelope"] if receipt_info else None,
            policy_jwk=self._policy_jwk if receipt_info else None,
            policy_bundle=self._policy_bundle, transcript=transcript,
        )
        st.events.append("record_verified")
        return RecordArtifacts(
            authorization=st.authorization, transcript=_snapshot(transcript), record=_snapshot(signed),
        )

