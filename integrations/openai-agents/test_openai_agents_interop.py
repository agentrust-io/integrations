"""Regression coverage against the released openai-agents package.

The unit tests use fakes shaped like the SDK's span data, which is the right way
to test the honesty rules and the wrong way to find out that the SDK renamed a
field. This runs a real released `Agent` through a real `TracingProcessor` and
asserts the adapter still sees what it expects.

No network. The run uses a stub model that returns a tool call and then a final
message, so the tracing path is exercised end to end without an API key.

CI pins the SDK version; see the workflow. A rename upstream should fail here
with a specific assertion rather than silently producing a record whose
transcript is empty.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

agents = pytest.importorskip("agents", reason="openai-agents is not installed")

from agents import Agent, Runner, function_tool  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.tracing import add_trace_processor, set_trace_processors  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from openai_agents_to_trace import TraceRecordProcessor  # noqa: E402

POLICY = b'permit(principal, action, resource) when { context.ok };'
WORKLOAD = "sha256:" + "ab" * 32
SUBJECT = "spiffe://example.org/agent/interop"


@function_tool
def count_characters(text: str) -> int:
    """Count the characters in some text."""
    return len(text)


@pytest.fixture
def processor():
    """Install our processor as the only one, and restore afterwards.

    set_trace_processors replaces the default exporter too, which matters: the
    default one posts traces to OpenAI, and a test suite should not.
    """
    collector = TraceRecordProcessor()
    set_trace_processors([collector])
    try:
        yield collector
    finally:
        set_trace_processors([])


def test_the_processor_interface_still_matches_the_sdk() -> None:
    """The four callbacks the adapter implements are the ones the SDK calls."""
    from agents.tracing import TracingProcessor

    for method in ("on_trace_start", "on_trace_end", "on_span_start", "on_span_end"):
        assert hasattr(TracingProcessor, method), method
    assert issubclass(TraceRecordProcessor, TracingProcessor)


def test_span_data_field_names_the_adapter_reads_still_exist() -> None:
    """The adapter reads these by name. A rename upstream breaks the transcript
    silently, so it is asserted rather than discovered."""
    from agents.tracing.span_data import (
        AgentSpanData,
        FunctionSpanData,
        HandoffSpanData,
    )

    assert "name" in FunctionSpanData.__slots__
    assert "mcp_data" in FunctionSpanData.__slots__
    assert "name" in AgentSpanData.__slots__
    assert "from_agent" in HandoffSpanData.__slots__
    assert "to_agent" in HandoffSpanData.__slots__


def test_add_trace_processor_is_still_the_registration_entry_point() -> None:
    assert callable(add_trace_processor)


def test_a_real_run_produces_a_valid_record(processor) -> None:
    agent = Agent(
        name="interop-agent",
        instructions="Count characters when asked.",
        tools=[count_characters],
        model=_stub_model(),
    )

    Runner.run_sync(agent, "count the characters in hello")

    record = processor.build_record(
        subject=SUBJECT,
        policy_bundle=POLICY,
        workload_digest=WORKLOAD,
        data_class="internal",
        model_provider="openai",
        model_id="stub",
    )

    assert record["subject"] == SUBJECT
    assert record["policy"]["enforcement_mode"] == "declared"
    assert record["runtime"]["platform"] == "software-only"
    assert "origin" not in record


def test_a_real_tool_call_reaches_the_transcript_without_its_arguments(processor) -> None:
    agent = Agent(
        name="interop-agent",
        instructions="Count characters when asked.",
        tools=[count_characters],
        model=_stub_model(),
    )

    Runner.run_sync(agent, "count the characters in SECRETVALUE")

    import json

    record = processor.build_record(
        subject=SUBJECT,
        policy_bundle=POLICY,
        workload_digest=WORKLOAD,
        data_class="internal",
        model_provider="openai",
        model_id="stub",
    )

    assert record["tool_transcript"]["call_count"] >= 1
    assert "count_characters" not in json.dumps(record), "names are hashed, not carried"
    assert "SECRETVALUE" not in json.dumps(record)


class _ScriptedModel(Model):
    """Returns a tool call, then a final message. No network, no API key.

    Implemented against the SDK's own `Model` interface rather than borrowing a
    fixture from its test suite, which is not shipped in the wheel. That is the
    point of an interop test: it uses only what a user of the released package
    can reach.
    """

    def __init__(self, tool_name: str) -> None:
        self._tool_name = tool_name
        self._turn = 0

    async def get_response(self, *args: object, **kwargs: object) -> ModelResponse:
        self._turn += 1
        if self._turn == 1:
            output = [
                ResponseFunctionToolCall(
                    id="call-1",
                    call_id="call-1",
                    name=self._tool_name,
                    arguments='{"text": "hello"}',
                    type="function_call",
                )
            ]
        else:
            output = [
                ResponseOutputMessage(
                    id="msg-1",
                    role="assistant",
                    status="completed",
                    type="message",
                    content=[ResponseOutputText(annotations=[], text="5", type="output_text")],
                )
            ]
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    def stream_response(self, *args: object, **kwargs: object):  # pragma: no cover
        raise NotImplementedError("the adapter does not exercise streaming")


def _stub_model() -> Model:
    return _ScriptedModel("count_characters")
