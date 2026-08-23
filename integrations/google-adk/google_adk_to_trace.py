#!/usr/bin/env python3
"""Google ADK plugin -> TRACE v0.2 Trust Record.

The plugin observes the released Google ADK callback lifecycle from inside the
runner. It records only invocation identity, model identity, available tool
identity, and callback-visible lifecycle outcomes. User content, model contents
and responses, tool arguments and results, and exception messages are
deliberately never read into evidence.

Google ADK does not evaluate a TRACE policy. Records therefore default to
``policy.enforcement_mode: declared`` and ``appraisal.status: none``. They have
no ``origin`` block because this is first-party, in-process observation.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from google.adk.plugins.base_plugin import BasePlugin as _GoogleAdkBasePlugin
else:
    try:
        from google.adk.plugins.base_plugin import BasePlugin as _GoogleAdkBasePlugin
    except ModuleNotFoundError as exc:
        if exc.name not in {"google", "google.adk", "google.adk.plugins"}:
            raise

        class _GoogleAdkBasePlugin:
            """Fallback for framework-free evidence tests."""

            def __init__(self, name: str) -> None:
                self.name = name


__all__ = ["GoogleAdkTracePlugin", "MissingEvidence", "ToolCall", "build_record"]

_DIGEST_PREFIX = "sha256:"
TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
ENFORCEMENT_MODES = ("enforce", "advisory", "silent", "declared")


class MissingEvidence(ValueError):
    """Raised rather than inventing a required TRACE claim."""


@dataclass(frozen=True)
class ToolCall:
    """One allow-listed tool observation, without arguments or results."""

    name: str | None
    function_call_fingerprint: str | None
    outcome: str  # "ok" | "error" | "incomplete"
    observed_start: bool = True
    observed_outcomes: tuple[str, ...] = ()


@dataclass
class _ObservedInvocation:
    model_ids: set[str] = field(default_factory=set)
    tools: list[ToolCall] = field(default_factory=list)
    pending: dict[str, list[int]] = field(default_factory=dict)
    finished_by_id: dict[str, int] = field(default_factory=dict)
    uncorrelated_completions: list[ToolCall] = field(default_factory=list)
    outcome: str = "incomplete"
    root_agent_name: str | None = None
    root_completed: bool = False


def _nonempty_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _invocation_id(context: Any) -> str:
    value = _nonempty_string(getattr(context, "invocation_id", None))
    if value is None:
        raise MissingEvidence("Google ADK did not expose a non-empty invocation_id.")
    return value


def _tool_name(tool: Any) -> str | None:
    return _nonempty_string(getattr(tool, "name", None))


def _function_call_fingerprint(tool_context: Any) -> str | None:
    raw_id = _nonempty_string(getattr(tool_context, "function_call_id", None))
    if raw_id is None:
        return None
    return _DIGEST_PREFIX + hashlib.sha256(raw_id.encode()).hexdigest()


def _pending_key(function_call_fingerprint: str | None, name: str | None) -> str:
    if function_call_fingerprint is not None:
        return "id:" + function_call_fingerprint
    return "name:" + (name or "<unavailable>")


class GoogleAdkTracePlugin(_GoogleAdkBasePlugin):
    """Observe independent Google ADK invocations through ``BasePlugin``.

    One plugin may be shared by concurrent runner invocations. State is keyed
    by ADK's invocation id and tool lifecycle events are correlated by the
    function-call id when the SDK supplies one.

    Every callback is observational. Callbacks that may replace framework
    values explicitly return ``None`` so execution is never short-circuited.
    """

    def __init__(self, name: str = "agentrust_trace") -> None:
        super().__init__(name=name)
        self._observed: dict[str, _ObservedInvocation] = {}
        self._lock = threading.RLock()

    async def before_run_callback(self, *, invocation_context: Any) -> None:
        invocation_id = _invocation_id(invocation_context)
        root_agent = getattr(invocation_context, "agent", None)
        with self._lock:
            self._observed[invocation_id] = _ObservedInvocation(
                root_agent_name=_nonempty_string(getattr(root_agent, "name", None))
            )
        return None

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        invocation_id = _invocation_id(invocation_context)
        with self._lock:
            state = self._observed.setdefault(invocation_id, _ObservedInvocation())
            if state.outcome != "error" and state.root_completed:
                state.outcome = "ok"
        return None

    async def before_agent_callback(self, *, agent: Any, callback_context: Any) -> None:  # noqa: ARG002
        return None

    async def after_agent_callback(self, *, agent: Any, callback_context: Any) -> None:
        invocation_id = _invocation_id(callback_context)
        agent_name = _nonempty_string(getattr(agent, "name", None))
        parent_agent = getattr(agent, "parent_agent", None)
        with self._lock:
            state = self._observed.setdefault(invocation_id, _ObservedInvocation())
            if (
                parent_agent is None
                and agent_name is not None
                and agent_name == state.root_agent_name
            ):
                state.root_completed = True
        return None

    async def on_run_error_callback(
        self,
        *,
        invocation_context: Any,
        error: Exception,  # noqa: ARG002 - exception payload is excluded
    ) -> None:
        self._mark_run_error(_invocation_id(invocation_context))
        return None

    async def on_agent_error_callback(
        self,
        *,
        agent: Any,  # noqa: ARG002
        callback_context: Any,  # noqa: ARG002 - later plugins may recover
        error: Exception,  # noqa: ARG002
    ) -> None:
        return None

    async def before_model_callback(
        self, *, callback_context: Any, llm_request: Any
    ) -> None:
        invocation_id = _invocation_id(callback_context)
        model_id = _nonempty_string(getattr(llm_request, "model", None))
        if model_id is not None:
            with self._lock:
                state = self._observed.setdefault(invocation_id, _ObservedInvocation())
                state.model_ids.add(model_id)
        return None

    async def after_model_callback(
        self,
        *,
        callback_context: Any,  # noqa: ARG002 - no response fields are evidence
        llm_response: Any,  # noqa: ARG002 - model payload is excluded
    ) -> None:
        return None

    async def on_model_error_callback(
        self,
        *,
        callback_context: Any,  # noqa: ARG002 - later plugins may recover
        llm_request: Any,  # noqa: ARG002
        error: Exception,  # noqa: ARG002
    ) -> None:
        return None

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],  # noqa: ARG002
        tool_context: Any,
    ) -> None:
        invocation_id = _invocation_id(tool_context)
        name = _tool_name(tool)
        function_call_fingerprint = _function_call_fingerprint(tool_context)
        call = ToolCall(
            name=name,
            function_call_fingerprint=function_call_fingerprint,
            outcome="incomplete",
        )
        with self._lock:
            state = self._observed.setdefault(invocation_id, _ObservedInvocation())
            index = len(state.tools)
            state.tools.append(call)
            state.pending.setdefault(
                _pending_key(function_call_fingerprint, name), []
            ).append(index)
        return None

    async def after_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],  # noqa: ARG002
        tool_context: Any,
        result: dict[str, Any],  # noqa: ARG002
    ) -> None:
        self._finish_tool(tool, tool_context, "ok")
        return None

    async def on_tool_error_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],  # noqa: ARG002
        tool_context: Any,
        error: Exception,  # noqa: ARG002
    ) -> None:
        self._finish_tool(tool, tool_context, "error")
        return None

    def _mark_run_error(self, invocation_id: str) -> None:
        with self._lock:
            state = self._observed.setdefault(invocation_id, _ObservedInvocation())
            state.outcome = "error"

    def _finish_tool(self, tool: Any, tool_context: Any, outcome: str) -> None:
        invocation_id = _invocation_id(tool_context)
        name = _tool_name(tool)
        function_call_fingerprint = _function_call_fingerprint(tool_context)
        key = _pending_key(function_call_fingerprint, name)
        with self._lock:
            state = self._observed.setdefault(invocation_id, _ObservedInvocation())
            indexes = state.pending.get(key)
            if indexes and len(indexes) == 1:
                index = indexes.pop(0)
                state.pending.pop(key, None)
                call = state.tools[index]
                state.tools[index] = replace(
                    call,
                    outcome=outcome,
                    observed_outcomes=call.observed_outcomes + (outcome,),
                )
                if function_call_fingerprint is not None:
                    state.finished_by_id[key] = index
                return

            if indexes:
                # More than one start has the same correlation key. Assigning
                # this completion by FIFO would invent which call finished.
                state.uncorrelated_completions.append(
                    ToolCall(
                        name=name,
                        function_call_fingerprint=function_call_fingerprint,
                        outcome=outcome,
                        observed_start=False,
                        observed_outcomes=(outcome,),
                    )
                )
                return

            if function_call_fingerprint is not None and key in state.finished_by_id:
                index = state.finished_by_id[key]
                call = state.tools[index]
                state.tools[index] = replace(
                    call,
                    outcome=outcome,
                    observed_outcomes=call.observed_outcomes + (outcome,),
                )
                return

            # A plugin attached after the start still records the completion.
            state.tools.append(
                ToolCall(
                    name=name,
                    function_call_fingerprint=function_call_fingerprint,
                    outcome=outcome,
                    observed_start=False,
                    observed_outcomes=(outcome,),
                )
            )

    @property
    def invocation_ids(self) -> list[str]:
        with self._lock:
            return list(self._observed)

    def tool_calls(self, invocation_id: str) -> list[ToolCall]:
        with self._lock:
            return list(self._require_invocation(invocation_id).tools)

    def transcript_bytes(self, invocation_id: str) -> bytes:
        """Canonical lifecycle evidence over an allow-list of non-payload fields."""
        with self._lock:
            state = self._require_invocation(invocation_id)
            body = {
                "invocation_id": invocation_id,
                "outcome": state.outcome,
                "tools": [
                    {
                        "function_call_fingerprint": call.function_call_fingerprint,
                        "observed_start": call.observed_start,
                        "observed_outcomes": list(call.observed_outcomes),
                        "outcome": call.outcome,
                        "tool": call.name,
                    }
                    for call in state.tools
                ],
                "uncorrelated_completions": [
                    {
                        "function_call_fingerprint": call.function_call_fingerprint,
                        "observed_outcomes": list(call.observed_outcomes),
                        "outcome": call.outcome,
                        "tool": call.name,
                    }
                    for call in state.uncorrelated_completions
                ],
            }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def discard(self, invocation_id: str) -> bool:
        """Remove retained evidence after the caller has persisted its record."""
        with self._lock:
            return self._observed.pop(invocation_id, None) is not None

    def build_record(
        self,
        invocation_id: str,
        *,
        subject: str,
        policy_bundle: bytes,
        enforcement_mode: str = "declared",
        workload_digest: str,
        data_class: str,
        model_provider: str | None = None,
        model_id: str | None = None,
        attestation: dict[str, str] | None = None,
        iat: int | None = None,
    ) -> dict[str, Any]:
        """Build an unsigned record for one retained ADK invocation."""
        with self._lock:
            state = self._require_invocation(invocation_id)
            if len(state.model_ids) > 1:
                raise MissingEvidence(
                    "the invocation used multiple model ids; one TRACE record cannot "
                    "truthfully relabel them as a single model"
                )
            observed_model = (
                next(iter(state.model_ids)) if len(state.model_ids) == 1 else None
            )
            if observed_model is not None and model_id not in {None, observed_model}:
                raise MissingEvidence(
                    f"model_id {model_id!r} conflicts with observed model "
                    f"{observed_model!r}"
                )
            transcript = self.transcript_bytes(invocation_id)
            tool_count = len(state.tools)
        return build_record(
            subject=subject,
            policy_bundle=policy_bundle,
            enforcement_mode=enforcement_mode,
            workload_digest=workload_digest,
            data_class=data_class,
            model_provider=model_provider,
            model_id=observed_model or model_id,
            transcript=transcript,
            tool_count=tool_count,
            attestation=attestation,
            iat=iat,
        )

    def _require_invocation(self, invocation_id: str) -> _ObservedInvocation:
        try:
            return self._observed[invocation_id]
        except KeyError as exc:
            raise MissingEvidence(
                f"no evidence retained for invocation {invocation_id!r}"
            ) from exc


def _digest(data: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def build_record(
    *,
    subject: str,
    policy_bundle: bytes,
    enforcement_mode: str = "declared",
    workload_digest: str,
    data_class: str,
    model_provider: str | None,
    model_id: str | None,
    transcript: bytes,
    tool_count: int,
    attestation: dict[str, str] | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Construct a TRACE record without importing Google ADK."""
    if not re.match(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$", subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID; "
            "the adapter may not invent identity."
        )
    if not policy_bundle:
        raise MissingEvidence(
            "policy_bundle must contain the policy bytes being declared."
        )
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise MissingEvidence(
            f"enforcement_mode must be one of {', '.join(ENFORCEMENT_MODES)}."
        )
    if not model_provider or not model_id:
        raise MissingEvidence(
            "model_provider and model_id are required. Google ADK exposes the "
            "model id, but its model can come from different providers, so the "
            "adapter will not guess."
        )
    if not re.match(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$", workload_digest or ""):
        raise MissingEvidence(
            "workload_digest must be a sha256:/sha384: artifact digest."
        )

    if attestation:
        platform = attestation.get("platform")
        measurement = attestation.get("measurement", "")
        if platform == "software-only":
            raise MissingEvidence("omit attestation for a software-only run")
        if not platform or not re.match(
            r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$", measurement
        ):
            raise MissingEvidence("attestation requires a platform and measured digest")
        runtime = {"platform": platform, "measurement": measurement}
    else:
        runtime = {
            "platform": "software-only",
            "measurement": _digest(
                workload_digest.encode() + b"\n" + _digest(policy_bundle).encode()
            ),
        }

    record: dict[str, Any] = {
        "eat_profile": TRACE_PROFILE,
        "iat": int(iat if iat is not None else time.time()),
        "subject": subject,
        "model": {"provider": model_provider, "model_id": model_id},
        "runtime": runtime,
        "policy": {
            "bundle_hash": _digest(policy_bundle),
            "enforcement_mode": enforcement_mode,
        },
        "data_class": data_class,
        "build_provenance": {"slsa_level": 0, "digest": workload_digest},
        "appraisal": {"status": "none", "verifier": "google-adk-adapter"},
    }
    if tool_count:
        record["tool_transcript"] = {
            "hash": _digest(transcript),
            "call_count": tool_count,
        }
    return record
