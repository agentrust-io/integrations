"""Tests for the LlamaIndex adapter.

The risk here is structurally different from LangChain's. LlamaIndex delivers
every event to one method, and several event types carry payloads:
``AgentToolCallEvent`` has ``arguments``, ``LLMChatStartEvent`` has the whole
message list, the completion events carry prompt and response. So the tests that
matter are the ones proving the handler reads an allow-list rather than the
event.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from llamaindex_to_trace import (  # noqa: E402
    MissingEvidence,
    TraceEventHandler,
    build_record,
)

DIGEST = "sha256:" + "f" * 64
SUBJECT = "spiffe://example.org/agent/index-bot"
IBAN = "GB33BUKB20201555555555"


class _Event:
    """Stands in for a LlamaIndex event: a class_name() plus attributes."""

    def __init__(self, class_name: str, **attrs):
        self._class_name = class_name
        for k, v in attrs.items():
            setattr(self, k, v)
        type(self).class_name = classmethod(lambda cls, n=class_name: n)


class _ToolMeta:
    def __init__(self, name: str):
        self.name = name


def _tool_event(name: str, event_id: str, *, arguments: str = "{}"):
    return _Event(
        "AgentToolCallEvent",
        tool=_ToolMeta(name),
        arguments=arguments,
        id_=event_id,
        span_id="span-1",
    )


def _chat_event(model_dict: dict, messages=None):
    return _Event(
        "LLMChatStartEvent",
        model_dict=model_dict,
        messages=messages or [],
        additional_kwargs={},
        id_="e-llm",
        span_id="span-1",
    )


def _handler():
    h = TraceEventHandler()
    h.handle(_chat_event({"class_name": "Anthropic_LLM", "model": "claude-sonnet-4-6"}))
    h.handle(_tool_event("search", "e-1"))
    h.handle(_tool_event("send_email", "e-2"))
    return h


def _kwargs(**over):
    base = {
        "subject": SUBJECT,
        "policy_bundle": b'{"rules":["no-egress"]}',
        "enforcement_mode": "advisory",
        "workload_digest": DIGEST,
        "data_class": "internal",
    }
    base.update(over)
    return base


# --- the allow-list, which is this adapter's whole safety story ------------


def test_tool_arguments_never_reach_the_transcript() -> None:
    h = TraceEventHandler()
    h.handle(_tool_event("pay", "e-1", arguments=f'{{"iban":"{IBAN}"}}'))
    body = h.transcript_bytes().decode()
    assert IBAN not in body
    assert "pay" in body


def test_chat_messages_never_reach_the_record() -> None:
    h = TraceEventHandler()
    h.handle(
        _chat_event(
            {"class_name": "OpenAI", "model": "gpt-4"},
            messages=[{"role": "user", "content": f"wire to {IBAN}"}],
        )
    )
    h.handle(_tool_event("noop", "e-1"))
    record = h.build_record(**_kwargs())
    assert IBAN not in str(record)


def test_an_unknown_future_field_is_ignored_not_captured() -> None:
    """The handler reads an allow-list, so an added payload field cannot leak."""
    h = TraceEventHandler()
    event = _tool_event("pay", "e-1")
    event.new_upstream_field = f"secret {IBAN}"  # a field a later version might add
    h.handle(event)
    assert IBAN not in h.transcript_bytes().decode()


def test_unrelated_event_types_are_ignored() -> None:
    h = TraceEventHandler()
    h.handle(
        _Event(
            "LLMCompletionEndEvent", prompt=f"pay {IBAN}", response="done", id_="e-9"
        )
    )
    assert h.tool_calls == []
    assert IBAN not in h.transcript_bytes().decode()


# --- observation -----------------------------------------------------------


def test_tool_calls_are_captured_in_order() -> None:
    assert [c.name for c in _handler().tool_calls] == ["search", "send_email"]


def test_model_is_read_from_model_dict() -> None:
    record = _handler().build_record(**_kwargs())
    assert record["model"] == {"provider": "anthropic", "model_id": "claude-sonnet-4-6"}


def test_caller_overrides_a_guessed_provider() -> None:
    record = _handler().build_record(
        **_kwargs(), model_provider="bedrock", model_id="x"
    )
    assert record["model"]["provider"] == "bedrock"


def test_unnamed_tool_is_labelled_not_dropped() -> None:
    h = TraceEventHandler()
    h.handle(
        _Event("AgentToolCallEvent", tool=None, arguments="{}", id_="e-1", span_id=None)
    )
    assert h.tool_calls[0].name == "<unnamed>"


def test_transcript_is_order_sensitive() -> None:
    a = _handler().transcript_bytes()
    h = TraceEventHandler()
    h.handle(_tool_event("send_email", "e-2"))
    h.handle(_tool_event("search", "e-1"))
    assert h.transcript_bytes() != a


# --- refusals --------------------------------------------------------------


def test_enforcement_mode_defaults_to_declared() -> None:
    """TRACE 0.9.0 added the value that is actually true of a framework run."""
    kwargs = _kwargs()
    del kwargs["enforcement_mode"]
    assert _handler().build_record(**kwargs)["policy"]["enforcement_mode"] == "declared"


def test_unknown_enforcement_mode_is_still_refused() -> None:
    with pytest.raises(MissingEvidence, match="enforcement_mode must be one of"):
        _handler().build_record(**_kwargs(enforcement_mode="monitor"))


def test_policy_bundle_bytes_are_required() -> None:
    with pytest.raises(MissingEvidence, match="digest of a bundle"):
        _handler().build_record(**_kwargs(policy_bundle=b""))


def test_subject_must_be_spiffe_or_did() -> None:
    with pytest.raises(MissingEvidence, match="may invent"):
        _handler().build_record(**_kwargs(subject="index-bot"))


def test_workload_digest_is_checked() -> None:
    with pytest.raises(MissingEvidence, match="nothing truthful to default"):
        _handler().build_record(**_kwargs(workload_digest="sha256:placeholder"))


def test_unidentified_model_is_refused() -> None:
    h = TraceEventHandler()
    h.handle(_tool_event("search", "e-1"))
    with pytest.raises(MissingEvidence, match="names no model"):
        h.build_record(**_kwargs())


def test_attestation_may_not_claim_software_only() -> None:
    with pytest.raises(MissingEvidence, match="attests nothing"):
        _handler().build_record(
            **_kwargs(),
            attestation={"platform": "software-only", "measurement": DIGEST},
        )


# --- the record ------------------------------------------------------------


def test_record_validates_after_signing() -> None:
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    sign = pytest.importorskip("agentrust_trace.sign")
    record = sign.sign_record(_handler().build_record(**_kwargs()), sign.generate_key())
    parsed = TrustRecord.model_validate(record)
    assert parsed.runtime.platform == "software-only"
    assert parsed.tool_transcript.call_count == 2


def test_first_party_records_carry_no_origin_block() -> None:
    assert "origin" not in _handler().build_record(**_kwargs())


def test_attestation_lifts_the_same_record_to_hardware() -> None:
    record = _handler().build_record(
        **_kwargs(), attestation={"platform": "intel-tdx", "measurement": DIGEST}
    )
    assert record["runtime"] == {"platform": "intel-tdx", "measurement": DIGEST}


def test_no_tools_omits_the_transcript_block() -> None:
    h = TraceEventHandler()
    record = h.build_record(**_kwargs(), model_provider="openai", model_id="gpt-4")
    assert "tool_transcript" not in record


def test_build_record_is_usable_without_the_handler() -> None:
    record = build_record(
        subject=SUBJECT,
        policy_bundle=b"{}",
        enforcement_mode="advisory",
        workload_digest=DIGEST,
        data_class="internal",
        model_provider="openai",
        model_id="gpt-4",
        transcript=b"[]",
        tool_count=0,
    )
    assert record["appraisal"]["status"] == "none"


# Workflow unit tests protect the field allow-list. The separate interop suite
# proves these events are actually delivered by a released FunctionAgent.
class ToolCall:
    def __init__(self, tool_name="search", tool_id="request-1"):
        self.tool_name = tool_name
        self.tool_id = tool_id

    @property
    def tool_kwargs(self):
        raise AssertionError("workflow arguments must not be read")

    @property
    def span_id(self):
        raise AssertionError("a workflow event does not supply an instrumentation span")

    @property
    def future_payload(self):
        raise AssertionError("unknown fields must not be read")


class ToolCallResult:
    def __getattr__(self, name):
        raise AssertionError("result fields must not be read")


def test_workflow_records_only_request_name_and_fingerprinted_id() -> None:
    h = TraceEventHandler()
    h.observe_workflow(ToolCall(tool_id=IBAN))
    h.observe_workflow(ToolCallResult())
    assert len(h.tool_calls) == 1
    assert h.tool_calls[0].name == "search"
    assert (
        h.tool_calls[0].event_id
        == "sha256:" + hashlib.sha256(IBAN.encode()).hexdigest()
    )
    assert h.tool_calls[0].span_id is None
    assert IBAN not in h.transcript_bytes().decode()


def test_workflow_preserves_repeated_requests_even_with_same_id() -> None:
    # Model ids are not guaranteed unique. Do not erase a second request by
    # treating the call-id fingerprint as an exactly-once execution identifier.
    h = TraceEventHandler()
    h.observe_workflow(ToolCall())
    h.observe_workflow(ToolCall())
    assert len(h.tool_calls) == 2


@pytest.mark.parametrize("field", ["tool_name", "tool_id"])
@pytest.mark.parametrize("value", [None, "", 42, [], {"payload": IBAN}])
def test_workflow_missing_identity_is_refused_without_mutation(field, value) -> None:
    h = TraceEventHandler()
    event = ToolCall()
    setattr(event, field, value)
    with pytest.raises(MissingEvidence, match="non-empty string") as exc:
        h.observe_workflow(event)
    assert IBAN not in str(exc.value)
    assert h.tool_calls == []
    # Invalid evidence must not select a source either.
    h.observe(_tool_event("search", "legacy-1"))
    assert len(h.tool_calls) == 1


@pytest.mark.parametrize("workflow_first", [True, False])
def test_mixing_tool_sources_is_refused_before_append(workflow_first) -> None:
    h = TraceEventHandler()

    def workflow():
        h.observe_workflow(ToolCall())

    def legacy():
        h.observe(_tool_event("search", "legacy-1"))

    first, second = (workflow, legacy) if workflow_first else (legacy, workflow)
    first()
    before = h.transcript_bytes()
    with pytest.raises(MissingEvidence, match="separate trackers"):
        second()
    assert h.transcript_bytes() == before


def test_irrelevant_workflow_events_do_not_read_fields_or_select_source() -> None:
    h = TraceEventHandler()
    h.observe_workflow(ToolCallResult())
    h.observe_workflow(_chat_event({"model": IBAN}))
    assert h.tool_calls == []
    h.observe(_tool_event("legacy", "e-1"))
    assert h.tool_calls[0].name == "legacy"


def test_workflow_requests_preserve_order_and_require_model_identity() -> None:
    h = TraceEventHandler()
    h.observe_workflow(ToolCall("first", "one"))
    h.observe_workflow(ToolCall("second", "two"))
    assert [c.name for c in h.tool_calls] == ["first", "second"]
    with pytest.raises(MissingEvidence, match="explicit model_provider and model_id"):
        h.build_record(**_kwargs())
    record = h.build_record(**_kwargs(), model_provider="local", model_id="test-model")
    assert record["tool_transcript"]["call_count"] == 2


@pytest.mark.parametrize("model_first", [True, False])
@pytest.mark.parametrize("has_tool_request", [True, False])
@pytest.mark.parametrize(
    "explicit", [{}, {"model_provider": "local"}, {"model_id": "local"}]
)
def test_workflow_never_inherits_global_model_identity(
    model_first, has_tool_request, explicit
):
    h = TraceEventHandler()
    model_event = _chat_event({"class_name": "OpenAI", "model": "unrelated-model"})
    event = ToolCall() if has_tool_request else ToolCallResult()
    if model_first:
        h.observe(model_event)
    h.observe_workflow(event)
    if not model_first:
        h.observe(model_event)
    with pytest.raises(MissingEvidence, match="explicit model_provider and model_id"):
        h.build_record(**_kwargs(), **explicit)
    record = h.build_record(
        **_kwargs(), model_provider="run-provider", model_id="run-model"
    )
    assert record["model"] == {"provider": "run-provider", "model_id": "run-model"}
