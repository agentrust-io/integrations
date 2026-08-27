#!/usr/bin/env python3
"""OpenAI Agents SDK tracing -> TRACE v0.2 Trust Record.

The SDK ships ``agents.tracing.TracingProcessor``, an interface that receives
``on_trace_start``, ``on_span_start`` and ``on_span_end`` as a run proceeds. A
processor runs **in the agent's own process**, so what it observes is the
operator's own agent.

That makes this a first-party adapter, like the LangChain one and unlike the
transcription adapters in ``packages/agentrust-trace-adapters``. Records carry
**no ``origin`` block**: absence means ``self``, and self is the truth. Routing
this through the transcription library would force
``origin.kind: third-party-control-plane`` and ``runtime.platform:
software-only`` onto a record about the operator's own execution, which is a
worse description, not a safer one.

**The honest limit, stated where you cannot miss it.** The Agents SDK enforces
no policy of its own. Guardrails exist and can stop a run, but they are the
operator's code, not a policy engine evaluating a bundle. So
``enforcement_mode`` defaults to ``declared``: the policy is named and bound
into the signed record, and nothing evaluated it. Override that only when a
real enforcement layer sat in front of the tools. A record claiming ``enforce``
from a bare Agents SDK run describes enforcement that did not happen.

**Payloads never enter the record.** ``FunctionSpanData`` carries ``input`` and
``output``, and ``GenerationSpanData`` carries the full message list. None of it
is hashed into the transcript. A Trust Record exists to be handed to a third
party, and handing over tool arguments defeats that. What goes in is identity:
which tools ran, in what order, and which agents handed off to which.

Span types are taken from ``agents.tracing.span_data`` and are the SDK's public
surface. ``UNMAPPED_SPANS`` records the ones deliberately not used and why.

Usage::

    pip install agentrust-trace openai-agents

    from agents import add_trace_processor
    from openai_agents_to_trace import TraceRecordProcessor

    processor = TraceRecordProcessor()
    add_trace_processor(processor)

    Runner.run_sync(agent, "...")

    record = processor.build_record(
        subject="spiffe://example.org/agent/support-bot",
        policy_bundle=open("policy.cedar", "rb").read(),
        workload_digest="sha256:...",
        data_class="internal",
        model_provider="openai",
        model_id="gpt-5",
    )
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents.tracing import TracingProcessor as _TracingProcessor
else:
    try:
        from agents.tracing import TracingProcessor as _TracingProcessor
    except ModuleNotFoundError as exc:
        if exc.name not in {"agents", "agents.tracing"}:
            raise

        class _TracingProcessor:  # type: ignore[no-redef]
            """Fallback so record construction stays testable without the SDK."""


__all__ = [
    "TRACE_PROFILE",
    "ENFORCEMENT_MODES",
    "UNMAPPED_SPANS",
    "MissingEvidence",
    "ToolCall",
    "TraceRecordProcessor",
    "build_record",
]

TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
ENFORCEMENT_MODES = ("enforce", "advisory", "silent", "declared")

#: Span types deliberately not folded into the transcript, and why. Read this
#: before adding one.
UNMAPPED_SPANS = {
    "GenerationSpanData": (
        "carries the full input and output message list. That is payload, and a "
        "record meant to be handed to a third party should not carry the "
        "conversation. Model identity comes from the caller instead, which is "
        "the one thing here a verifier can check against a deployment."
    ),
    "FunctionSpanData.input/output": (
        "tool arguments and results, same reason. The tool's name and call id go "
        "in; what was passed to it does not."
    ),
    "GuardrailSpanData": (
        "a guardrail is the operator's own code, not a policy engine evaluating a "
        "bundle. Recording a tripwire as if it were policy enforcement is exactly "
        "the overclaim enforcement_mode: declared exists to prevent."
    ),
    "MCPListToolsSpanData": (
        "the tool roster belongs in an Agent Manifest, where it is signed at "
        "deploy time, not in a per-session record. See integrations/wcm-agent-manifest "
        "for the binding this repository already uses for that."
    ),
}

_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
_SUBJECT_RE = re.compile(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")


class MissingEvidence(ValueError):
    """Raised rather than filling a required field with something invented."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ToolCall:
    """Identity of one tool invocation. Deliberately not its arguments."""

    name: str
    call_id: str | None = None
    kind: str = "function"


@dataclass
class _Run:
    tools: list[ToolCall] = field(default_factory=list)
    handoffs: list[tuple[str, str]] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    errors: int = 0


class TraceRecordProcessor(_TracingProcessor):
    """Collects run identity from the SDK's tracing callbacks.

    Thread-safe: the SDK may run agents concurrently, and a processor that let
    two runs interleave into one transcript would produce a record describing
    several executions while naming one.

    Spans are read on ``on_span_end`` rather than start, because a span that
    errored is only known to have errored once it closes, and a tool that raised
    is a different fact from a tool that ran.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[str, _Run] = {}
        self._completed: list[str] = []

    # -- TracingProcessor ---------------------------------------------------

    def on_trace_start(self, trace: Any) -> None:
        with self._lock:
            self._runs.setdefault(trace.trace_id, _Run())

    def on_trace_end(self, trace: Any) -> None:
        with self._lock:
            if trace.trace_id in self._runs:
                self._completed.append(trace.trace_id)

    def on_span_start(self, span: Any) -> None:
        return None

    def on_span_end(self, span: Any) -> None:
        data = getattr(span, "span_data", None)
        if data is None:
            return
        kind = type(data).__name__
        with self._lock:
            run = self._runs.setdefault(getattr(span, "trace_id", ""), _Run())
            if getattr(span, "error", None):
                run.errors += 1
            if kind == "FunctionSpanData":
                run.tools.append(
                    ToolCall(
                        name=str(getattr(data, "name", "")),
                        call_id=getattr(span, "span_id", None),
                        kind="mcp" if getattr(data, "mcp_data", None) else "function",
                    )
                )
            elif kind == "AgentSpanData":
                name = getattr(data, "name", None)
                if name:
                    run.agents.append(str(name))
            elif kind == "HandoffSpanData":
                run.handoffs.append(
                    (str(getattr(data, "from_agent", "")), str(getattr(data, "to_agent", "")))
                )

    def force_flush(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    # -- record ------------------------------------------------------------

    @property
    def tool_calls(self) -> tuple[ToolCall, ...]:
        with self._lock:
            run = self._latest()
            return tuple(run.tools) if run else ()

    def _latest(self) -> _Run | None:
        if self._completed:
            return self._runs.get(self._completed[-1])
        return next(iter(self._runs.values()), None)

    def build_record(self, *, trace_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Build a Trust Record for one run.

        ``trace_id`` selects which run when several have been observed. Without
        it the most recently completed run is used, and mixing two runs is
        refused rather than silently concatenated: a record whose transcript
        describes several executions and whose subject names one is wrong rather
        than incomplete.
        """
        with self._lock:
            run = self._runs.get(trace_id) if trace_id else self._latest()
        if run is None:
            raise MissingEvidence(
                "no run has been observed. Register this processor with "
                "add_trace_processor() before running the agent."
            )
        return build_record(
            tools=tuple(run.tools),
            handoffs=tuple(run.handoffs),
            agents=tuple(run.agents),
            **kwargs,
        )


def _transcript(tools: tuple[ToolCall, ...], handoffs: tuple[tuple[str, str], ...]) -> bytes:
    """Canonical bytes over run identity. Names and order, never payloads.

    Handoffs are included because in a multi-agent run the order tools ran in is
    not the whole story: which agent was holding the run when a tool fired is
    part of what a reader is trying to reconstruct.
    """
    return json.dumps(
        {
            "tools": [{"tool": t.name, "call_id": t.call_id, "type": t.kind} for t in tools],
            "handoffs": [{"from": a, "to": b} for a, b in handoffs],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def build_record(
    *,
    subject: str,
    policy_bundle: bytes,
    workload_digest: str,
    data_class: str,
    model_provider: str,
    model_id: str,
    tools: tuple[ToolCall, ...] = (),
    handoffs: tuple[tuple[str, str], ...] = (),
    agents: tuple[str, ...] = (),
    enforcement_mode: str = "declared",
    attestation: dict[str, str] | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """The record shape, separated from the processor so it can be tested alone."""
    if not _SUBJECT_RE.match(subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID. The identity of the "
            "workload is not something an adapter may invent."
        )
    if not policy_bundle:
        raise MissingEvidence(
            "policy_bundle is the bytes of the policy this deployment declares. The "
            "Agents SDK does not supply one, so you must: policy.bundle_hash is a "
            "digest of a bundle, not of its name."
        )
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise MissingEvidence(
            f"enforcement_mode must be one of {', '.join(ENFORCEMENT_MODES)}. The "
            "default is 'declared', which is what a bare Agents SDK run is: the policy "
            "is named and bound, and nothing evaluated it."
        )
    if not model_provider or not model_id:
        raise MissingEvidence(
            "model_provider and model_id are required. The SDK reports the model on "
            "GenerationSpanData, which this adapter does not read because that span "
            "also carries the message payloads, so pass them explicitly."
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
        # Derived from what the operator does hold, and labelled software-only so
        # it is never mistaken for a hardware measurement. Same construction as
        # the LangChain adapter and the agentrust-trace sandbox.
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
        "policy": {"bundle_hash": _digest(policy_bundle), "enforcement_mode": enforcement_mode},
        "data_class": data_class,
        "build_provenance": {"slsa_level": 0, "digest": workload_digest},
        # Building a record does not appraise it, and "affirming" would put a
        # verdict in the field a consumer reads to find out whether anybody
        # checked.
        "appraisal": {"status": "none", "verifier": "openai-agents-adapter"},
    }
    if tools or handoffs:
        record["tool_transcript"] = {
            "hash": _digest(_transcript(tools, handoffs)),
            "call_count": len(tools),
        }
    # transparency is omitted, not empty: the record is unanchored until
    # something anchors it, and "" is not a URI.
    return record
