#!/usr/bin/env python3
"""LangChain callbacks -> TRACE v0.2 Trust Record.

A callback handler runs **in the agent's own process**, so what it observes is
first-party evidence about the operator's own agent. That is a different thing
from the third-party adapters in ``packages/agentrust-trace-adapters``, which
transcribe somebody else's control-plane output and are forced to
``origin.kind: third-party-control-plane`` and ``software-only``.

This one emits an ordinary Trust Record with **no ``origin`` block**, because
absence means ``self`` and self is the truth: the operator ran the agent, and the
operator is signing the record. Where the deployment runs inside a TEE, passing
an attestation lifts the same record from Level 0 to Level 1, the way the sandbox
adapter in ``agentrust-trace`` does. Nothing else about the call changes.

**The honest limit, stated where you cannot miss it.** LangChain enforces no
policy. It has no policy engine, and this handler is an observer with no ability
to block anything. So ``enforcement_mode`` has no truthful default here and this
module refuses to pick one: the caller states it, and the README explains why
even ``advisory`` overstates a bare LangChain run. A record claiming ``enforce``
from this adapter would be describing enforcement that did not happen.

Callback signatures are taken from ``langchain_core.callbacks.base`` and are the
public, documented API. Payloads never enter the record: ``on_tool_start``
receives ``input_str`` and ``inputs``, and ``on_tool_end`` receives the output,
and none of it is hashed into the transcript. A Trust Record exists to be handed
to a third party, and handing over tool arguments defeats that.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

__all__ = ["TraceCallbackHandler", "ToolCall", "build_record"]

_DIGEST_PREFIX = "sha256:"
TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
ENFORCEMENT_MODES = ("enforce", "advisory", "silent")


class MissingEvidence(ValueError):
    """Raised rather than filling a required field with something invented."""


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation, identity only.

    Deliberately no arguments and no result. Those are payloads, and the
    transcript hash travels to whoever receives the record.
    """

    name: str
    run_id: str
    parent_run_id: str | None
    outcome: str  # "ok" | "error"


@dataclass
class _Observed:
    tools: list[ToolCall] = field(default_factory=list)
    provider: str | None = None
    model_id: str | None = None
    pending: dict[str, str] = field(default_factory=dict)


def _name_from_serialized(serialized: dict[str, Any]) -> str | None:
    """LangChain's serialized dict, read defensively.

    ``name`` is present on current versions; ``id`` is a dotted path whose last
    element is the class name, which is what older versions carried. Neither is
    guaranteed, so a missing name is reported as missing rather than guessed at.
    """
    if not isinstance(serialized, dict):
        return None
    name = serialized.get("name")
    if isinstance(name, str) and name:
        return name
    path = serialized.get("id")
    if isinstance(path, list) and path:
        return str(path[-1])
    return None


class TraceCallbackHandler:
    """Accumulates what a LangChain run did, for one record per run.

    Subclasses ``langchain_core.callbacks.base.BaseCallbackHandler`` when
    LangChain is installed. The import is deferred so the module can be read,
    tested and reviewed without it, which also keeps the honesty rules testable
    without pulling a framework into CI.
    """

    def __init__(self) -> None:
        self._observed = _Observed()

    # --- LangChain callback surface ---------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,  # noqa: ARG002 - payload, deliberately unused
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        name = _name_from_serialized(serialized) or "<unnamed>"
        self._observed.pending[str(run_id)] = name

    def on_tool_end(self, output: Any, *, run_id: UUID, parent_run_id: UUID | None = None, **kwargs: Any) -> None:  # noqa: ARG002
        self._finish(run_id, parent_run_id, "ok")

    def on_tool_error(self, error: BaseException, *, run_id: UUID, parent_run_id: UUID | None = None, **kwargs: Any) -> None:  # noqa: ARG002
        # The failure is recorded, its message is not: an exception string is a
        # payload as surely as a tool argument is.
        self._finish(run_id, parent_run_id, "error")

    def on_chat_model_start(self, serialized: dict[str, Any], messages: Any, **kwargs: Any) -> None:  # noqa: ARG002
        self._note_model(serialized, kwargs)

    def on_llm_start(self, serialized: dict[str, Any], prompts: Any, **kwargs: Any) -> None:  # noqa: ARG002
        self._note_model(serialized, kwargs)

    # --- accumulation ------------------------------------------------------

    def _finish(self, run_id: UUID, parent_run_id: UUID | None, outcome: str) -> None:
        name = self._observed.pending.pop(str(run_id), None)
        if name is None:
            # An end with no start means the handler was attached mid-run. The
            # call is still recorded, named as unknown rather than dropped: a
            # transcript that silently omits a call is worse than one that says
            # it could not name it.
            name = "<unobserved-start>"
        self._observed.tools.append(
            ToolCall(
                name=name,
                run_id=str(run_id),
                parent_run_id=str(parent_run_id) if parent_run_id else None,
                outcome=outcome,
            )
        )

    def _note_model(self, serialized: dict[str, Any], kwargs: dict[str, Any]) -> None:
        params = kwargs.get("invocation_params") or {}
        model = None
        if isinstance(params, dict):
            model = params.get("model") or params.get("model_name") or params.get("model_id")
        self._observed.model_id = self._observed.model_id or (
            model if isinstance(model, str) else None
        )
        cls = _name_from_serialized(serialized)
        if cls and self._observed.provider is None:
            # ChatAnthropic -> anthropic, ChatOpenAI -> openai. A best-effort
            # normalization of a class name is not model identity, so a caller
            # that knows better overrides it in build_record.
            lowered = cls.lower()
            for known in ("anthropic", "openai", "bedrock", "vertex", "azure", "ollama", "mistral"):
                if known in lowered:
                    self._observed.provider = known
                    break

    # --- record ------------------------------------------------------------

    @property
    def tool_calls(self) -> list[ToolCall]:
        return list(self._observed.tools)

    def transcript_bytes(self) -> bytes:
        """Canonical bytes over tool identity: name, ids and outcome. No payloads."""
        return json.dumps(
            [
                {
                    "tool": c.name,
                    "run_id": c.run_id,
                    "parent_run_id": c.parent_run_id,
                    "outcome": c.outcome,
                }
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
        enforcement_mode: str,
        workload_digest: str,
        data_class: str,
        model_provider: str | None = None,
        model_id: str | None = None,
        attestation: dict[str, str] | None = None,
        iat: int | None = None,
    ) -> dict[str, Any]:
        """Assemble the unsigned Trust Record for this run.

        ``enforcement_mode`` has no default. LangChain enforces nothing, so every
        available value overstates a bare run to some degree and the caller has to
        choose knowingly. See the README.

        ``attestation`` is ``{"platform": ..., "measurement": ...}`` when the
        deployment runs in a TEE, which lifts the record to Level 1. Absent, the
        record is Level 0 and says ``software-only``, which is what an
        unattested framework run is.
        """
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
    return _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def build_record(
    *,
    subject: str,
    policy_bundle: bytes,
    enforcement_mode: str,
    workload_digest: str,
    data_class: str,
    model_provider: str | None,
    model_id: str | None,
    transcript: bytes,
    tool_count: int,
    attestation: dict[str, str] | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """The record shape, separated from the handler so it can be tested alone."""
    import re
    import time

    if not re.match(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$", subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID. The identity of the "
            "workload is not something an adapter may invent."
        )
    if not policy_bundle:
        raise MissingEvidence(
            "policy_bundle is the bytes of the policy this deployment declares. "
            "LangChain does not supply one, so you must: policy.bundle_hash is a "
            "digest of a bundle, not of its name."
        )
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise MissingEvidence(
            f"enforcement_mode must be one of {', '.join(ENFORCEMENT_MODES)} and is "
            "not defaulted here, because LangChain enforces nothing and every value "
            "overstates a bare run. Choose knowingly."
        )
    if not model_provider or not model_id:
        raise MissingEvidence(
            "the model was not identified. LangChain reports it through "
            "invocation_params, which not every integration populates, so pass "
            "model_provider and model_id explicitly rather than shipping a record "
            "that names no model."
        )
    if not re.match(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$", workload_digest or ""):
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
        if not re.match(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$", measurement):
            raise MissingEvidence(
                "attestation.measurement must be the digest the platform reported."
            )
        runtime = {"platform": platform, "measurement": measurement}
    else:
        # Derived from the inputs the operator does hold, and labelled
        # software-only so it is never mistaken for a hardware measurement. Same
        # construction as the sandbox adapter in agentrust-trace.
        runtime = {
            "platform": "software-only",
            "measurement": _digest(workload_digest.encode() + b"\n" + _digest(policy_bundle).encode()),
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
        # checked. Same call the sandbox adapter makes.
        "appraisal": {"status": "none", "verifier": "langchain-adapter"},
    }
    if tool_count:
        record["tool_transcript"] = {"hash": _digest(transcript), "call_count": tool_count}
    # transparency is omitted, not empty: the record is unanchored until
    # something anchors it, and "" is not a URI.
    return record
