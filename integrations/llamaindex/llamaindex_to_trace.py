#!/usr/bin/env python3
"""LlamaIndex instrumentation or workflow events -> TRACE v0.2 Trust Record.

Same shape as the LangChain adapter and for the same reason: a
``BaseEventHandler`` runs in the agent's own process, so what it sees is
first-party evidence about the operator's own agent. The record carries no
``origin`` block, because absence means ``self``.

LlamaIndex has one entry point rather than a dozen callbacks: ``handle(event)``,
with events distinguished by ``class_name()``. That is easier to consume and
harder to consume *safely*, because every event arrives at the same method and
several of them carry payloads. ``AgentToolCallEvent`` has an ``arguments``
field. ``LLMChatStartEvent`` carries the whole message list. ``LLMCompletionEndEvent``
carries the prompt and the response.

So this handler works from an explicit allow-list of fields rather than from the
event object: it reads the tool name, the event id and the span id, and nothing
else. Anything LlamaIndex adds in a future version is ignored by default, which
is the right direction for a component whose output is meant to be shareable.

Events read (``llama_index.core.instrumentation.events``):
  AgentToolCallEvent   -> tool identity
  LLMChatStartEvent    -> model identity from ``model_dict``
  LLMCompletionStartEvent -> same

Modern ``FunctionAgent`` tool requests arrive on its per-run workflow stream,
not as ``AgentToolCallEvent`` instrumentation. Pass those events explicitly to
``observe_workflow``. Only ``ToolCall`` name and a fingerprint of its call id
are retained; observing a request does not establish execution or success.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = ["MissingEvidence", "ToolCall", "TraceEventHandler", "build_record"]

TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
ENFORCEMENT_MODES = ("enforce", "advisory", "silent", "declared")
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
_SUBJECT_RE = re.compile(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")

#: The only fields read off any event. Everything else, present or future, is
#: ignored rather than filtered, so a new payload-bearing field cannot leak by
#: being added upstream.
TOOL_FIELDS = ("id_", "span_id")
PAYLOAD_FIELDS_NOT_READ = (
    "arguments",
    "messages",
    "prompt",
    "response",
    "output",
    "template_args",
)


class MissingEvidence(ValueError):
    """Raised rather than filling a required field with something invented."""


@dataclass(frozen=True)
class ToolCall:
    name: str
    event_id: str
    span_id: str | None


@dataclass
class _Observed:
    tools: list[ToolCall] = field(default_factory=list)
    provider: str | None = None
    model_id: str | None = None


def _tool_name(event: Any) -> str:
    """The tool's name from ``ToolMetadata``, without touching its arguments."""
    meta = getattr(event, "tool", None)
    name = getattr(meta, "name", None)
    return name if isinstance(name, str) and name else "<unnamed>"


def _model_from_dict(model_dict: Any) -> tuple[str | None, str | None]:
    """Provider and model id from ``model_dict``, read defensively.

    LlamaIndex serializes the LLM object, so the shape varies by integration.
    ``class_name`` is the one key that is reliably present; the model name lives
    under ``model`` or ``model_name`` depending on the integration. Neither is
    guaranteed, so a missing value is reported as missing rather than guessed at.
    """
    if not isinstance(model_dict, dict):
        return None, None
    model = model_dict.get("model") or model_dict.get("model_name")
    cls = str(model_dict.get("class_name", "")).lower()
    provider = None
    for known in (
        "anthropic",
        "openai",
        "bedrock",
        "vertex",
        "azure",
        "ollama",
        "mistral",
        "gemini",
    ):
        if known in cls:
            provider = known
            break
    return provider, model if isinstance(model, str) else None


class TraceEventHandler:
    """Accumulates one run's tool calls and model identity.

    Subclass ``llama_index.core.instrumentation.event_handlers.BaseEventHandler``
    in your application and delegate to :meth:`observe`; this class does not
    import LlamaIndex, so the honesty rules stay testable without it.
    """

    def __init__(self) -> None:
        self._observed = _Observed()
        self._tool_source: str | None = None
        self._workflow_observed = False

    def handle(self, event: Any, **kwargs: Any) -> None:
        """The ``BaseEventHandler`` surface."""
        self.observe(event)

    def observe(self, event: Any) -> None:
        name = getattr(type(event), "class_name", lambda: type(event).__name__)()
        if name == "AgentToolCallEvent":
            self._select_tool_source("instrumentation")
            self._observed.tools.append(
                ToolCall(
                    name=_tool_name(event),
                    event_id=str(getattr(event, "id_", "")),
                    span_id=(str(getattr(event, "span_id", "")) or None),
                )
            )
        elif name in ("LLMChatStartEvent", "LLMCompletionStartEvent"):
            provider, model = _model_from_dict(getattr(event, "model_dict", None))
            self._observed.provider = self._observed.provider or provider
            self._observed.model_id = self._observed.model_id or model

    def observe_workflow(self, event: Any) -> None:
        """Observe one run's workflow stream without registering global hooks.

        ``ToolCall`` precedes tool lookup/execution. ``ToolCallResult`` and all
        other events are ignored, so results cannot double-count requests or
        leak outputs. Model identity must be supplied separately by the caller.
        The model-supplied tool id is fingerprinted rather than copied into the
        transcript. Neither that fingerprint nor the name is authenticated.

        Use one fresh tracker per stream. Do not mix workflow and legacy tool
        events: their identifiers do not support reliable cross-source dedup.
        """
        # Even a no-tool workflow must not inherit identity from process-global
        # LLM instrumentation. Calling this API opts into explicit run identity.
        self._workflow_observed = True
        if type(event).__name__ != "ToolCall":
            return
        name = getattr(event, "tool_name", None)
        tool_id = getattr(event, "tool_id", None)
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(tool_id, str)
            or not tool_id
        ):
            raise MissingEvidence(
                "workflow ToolCall requires non-empty string tool_name and tool_id"
            )
        call = ToolCall(name=name, event_id=_digest(tool_id.encode()), span_id=None)
        self._select_tool_source("workflow")
        self._observed.tools.append(call)

    def _select_tool_source(self, source: str) -> None:
        if self._tool_source is not None and self._tool_source != source:
            raise MissingEvidence(
                "use separate trackers for workflow and instrumentation tool events"
            )
        self._tool_source = source

    @property
    def tool_calls(self) -> list[ToolCall]:
        return list(self._observed.tools)

    def transcript_bytes(self) -> bytes:
        """Tool identity only; workflow event ids are call-id fingerprints.

        Workflow entries describe requests, not successful handler invocations.
        No arguments or results are read into this transcript.
        """
        return json.dumps(
            [
                {"tool": c.name, "event_id": c.event_id, "span_id": c.span_id}
                for c in self._observed.tools
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def build_record(
        self,
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
        if self._workflow_observed and (not model_provider or not model_id):
            raise MissingEvidence(
                "workflow records require explicit model_provider and model_id"
            )
        return build_record(
            subject=subject,
            policy_bundle=policy_bundle,
            enforcement_mode=enforcement_mode,
            workload_digest=workload_digest,
            data_class=data_class,
            model_provider=model_provider or self._observed.provider,
            model_id=model_id or self._observed.model_id,
            transcript=self.transcript_bytes(),
            tool_count=len(self._observed.tools),
            attestation=attestation,
            iat=iat,
        )


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
    """Assemble the unsigned record. Raises rather than inventing a field.

    ``enforcement_mode`` defaults to ``declared``: the policy is named and bound
    into the signed record and nothing evaluated it, which is what a LlamaIndex
    run is. TRACE 0.9.0 added that value; before it, every available value
    overstated a bare run and this adapter refused to default the field.
    """
    if not _SUBJECT_RE.match(subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID. The identity of the "
            "workload is not something an adapter may invent."
        )
    if not policy_bundle:
        raise MissingEvidence(
            "policy_bundle is the bytes of the policy this deployment declares. "
            "LlamaIndex does not supply one, so you must: policy.bundle_hash is a "
            "digest of a bundle, not of its name."
        )
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise MissingEvidence(
            f"enforcement_mode must be one of {', '.join(ENFORCEMENT_MODES)}. The default "
            "is 'declared', which is what a LlamaIndex run actually is: the policy is named "
            "and bound, and nothing evaluated it."
        )
    if not model_provider or not model_id:
        raise MissingEvidence(
            "the model was not identified. LlamaIndex reports it through model_dict, "
            "whose shape varies by integration, so pass model_provider and model_id "
            "explicitly rather than shipping a record that names no model."
        )
    if not _DIGEST_RE.match(workload_digest or ""):
        raise MissingEvidence(
            "workload_digest must be a sha256:/sha384: digest of the artifact that ran. "
            "There is nothing truthful to default it to."
        )

    if attestation:
        platform = attestation.get("platform")
        measurement = attestation.get("measurement", "")
        if platform == "software-only":
            raise MissingEvidence(
                "an attestation may not name 'software-only'. Omit the attestation "
                "entirely for an unattested run; an attestation that attests nothing "
                "is a contradiction."
            )
        if not _DIGEST_RE.match(measurement):
            raise MissingEvidence(
                "attestation.measurement must be the digest the platform reported."
            )
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
        "appraisal": {"status": "none", "verifier": "llamaindex-adapter"},
    }
    if tool_count:
        record["tool_transcript"] = {
            "hash": _digest(transcript),
            "call_count": tool_count,
        }
    return record
