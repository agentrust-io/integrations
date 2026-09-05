"""Released LlamaIndex FunctionAgent workflow interoperability.

The real workflow executes local tools using the SDK's shipped scripted model.
The observer consumes the real per-run stream, never fabricated events. CI pins
llama-index-core, workflows and instrumentation; no provider API is required.
ToolCall is a request emitted before dispatch, not a proof of successful work.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import socket
import sys

import pytest
from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import generate_key, sign_record, verify_record
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.core.instrumentation import get_dispatcher
from llama_index.core.instrumentation.event_handlers import BaseEventHandler
from llama_index.core.llms import ChatMessage
from llama_index.core.llms.mock import MockFunctionCallingLLM
from llama_index.core.tools import ToolSelection
from trace_tests import runner as conformance_runner
from trace_tests.result import Status
from workflows.errors import WorkflowCancelledByUser

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from llamaindex_to_trace import TraceEventHandler  # noqa: E402

PAYLOAD = "private-customer-reference-must-not-enter-trace"
MODEL_OUTPUT = "private-model-output-must-not-enter-trace"
SUBJECT = "spiffe://example.org/agent/llamaindex-interop"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Model/provider calls and accidental telemetry are outside this test."""

    def refuse(*args, **kwargs):
        raise AssertionError("the released-framework test must remain offline")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def model_for_calls(calls):
    responses = [
        ChatMessage(
            role="assistant",
            content=MODEL_OUTPUT,
            additional_kwargs={
                "tool_calls": [
                    ToolSelection(
                        tool_id=call_id,
                        tool_name=name,
                        tool_kwargs=arguments,
                    )
                ]
            },
        )
        for name, call_id, arguments in calls
    ]
    responses.append(ChatMessage(role="assistant", content=MODEL_OUTPUT))
    sequence = iter(responses)
    return MockFunctionCallingLLM(
        response_generator=lambda messages, **kwargs: next(sequence),
    )


async def observe_run(agent, tracker):
    handler = agent.run(user_msg=PAYLOAD)
    events = []
    try:
        async for event in handler.stream_events():
            events.append(event)
            tracker.observe_workflow(event)
        return await handler, events
    finally:
        if not handler.is_done():
            await handler.cancel_run()


def signed_record(tracker, *, subject=SUBJECT):
    key = generate_key()
    signed = sign_record(
        tracker.build_record(
            subject=subject,
            policy_bundle=b'{"declared-policy":true}',
            workload_digest="sha256:" + "a" * 64,
            data_class="internal",
            model_provider="local-test-double",
            model_id="MockFunctionCallingLLM",
        ),
        key,
    )
    verify_record(signed, key.public_key())
    TrustRecord.model_validate(signed)
    return signed


@pytest.mark.parametrize("streaming", [False, True])
def test_real_function_agent_tool_stream_produces_signed_record(streaming):
    invocations = []

    def measure_payload(payload: str) -> str:
        """Measure one input in a local tool."""
        invocations.append(payload)
        return f"received {payload}"

    tracker = TraceEventHandler()
    agent = FunctionAgent(
        tools=[measure_payload],
        llm=model_for_calls([("measure_payload", "call-1", {"payload": PAYLOAD})]),
        streaming=streaming,
        timeout=15,
    )
    result, events = asyncio.run(observe_run(agent, tracker))

    assert invocations == [PAYLOAD]
    assert result.response.content == MODEL_OUTPUT
    assert [type(event).__name__ for event in events].count("ToolCall") == 1
    assert [type(event).__name__ for event in events].count("ToolCallResult") == 1
    assert len(tracker.tool_calls) == 1
    call = tracker.tool_calls[0]
    assert call.name == "measure_payload"
    assert call.event_id == "sha256:" + hashlib.sha256(b"call-1").hexdigest()
    assert call.span_id is None

    transcript = tracker.transcript_bytes()
    signed = signed_record(tracker)
    assert signed["tool_transcript"]["call_count"] == 1
    assert (
        signed["tool_transcript"]["hash"]
        == "sha256:" + hashlib.sha256(transcript).hexdigest()
    )
    assert signed["runtime"]["platform"] == "software-only"
    assert signed["policy"]["enforcement_mode"] == "declared"
    assert signed["appraisal"]["status"] == "none"
    assert "origin" not in signed
    assert "transparency" not in signed
    assert PAYLOAD not in transcript.decode()
    assert MODEL_OUTPUT not in transcript.decode()
    assert PAYLOAD not in json.dumps(signed)
    assert MODEL_OUTPUT not in json.dumps(signed)
    # The framework really did carry both request and result payloads.
    request = next(event for event in events if type(event).__name__ == "ToolCall")
    outcome = next(
        event for event in events if type(event).__name__ == "ToolCallResult"
    )
    assert request.tool_kwargs["payload"] == PAYLOAD
    assert PAYLOAD in outcome.tool_output.content


def test_real_function_agent_records_sequential_requests_once_in_order():
    invocations = []

    def visit(label: str) -> str:
        """Record a local visit."""
        invocations.append(label)
        return label

    tracker = TraceEventHandler()
    agent = FunctionAgent(
        tools=[visit],
        llm=model_for_calls(
            [
                ("visit", "first", {"label": "one"}),
                ("visit", "second", {"label": "two"}),
            ]
        ),
        streaming=False,
        timeout=15,
    )
    asyncio.run(observe_run(agent, tracker))
    assert invocations == ["one", "two"]
    assert [call.event_id for call in tracker.tool_calls] == [
        "sha256:" + hashlib.sha256(value.encode()).hexdigest()
        for value in ["first", "second"]
    ]
    assert signed_record(tracker)["tool_transcript"]["call_count"] == 2


def test_real_function_agent_model_only_run_omits_transcript():
    tracker = TraceEventHandler()
    agent = FunctionAgent(llm=model_for_calls([]), streaming=False, timeout=15)
    result, events = asyncio.run(observe_run(agent, tracker))
    assert result.response.content == MODEL_OUTPUT
    assert not any(type(event).__name__ == "ToolCall" for event in events)
    assert tracker.tool_calls == []
    assert "tool_transcript" not in signed_record(tracker)


def test_real_declared_workflow_passes_released_level_zero_conformance():
    """The released 0.5.1 suite accepts declared without claiming enforcement."""

    def noop() -> str:
        """Return a local response."""
        return "done"

    tracker = TraceEventHandler()
    agent = FunctionAgent(
        tools=[noop],
        llm=model_for_calls([("noop", "call-1", {})]),
        streaming=False,
        timeout=15,
    )
    asyncio.run(observe_run(agent, tracker))
    signed = signed_record(tracker)
    findings = [
        finding
        for module_findings in conformance_runner.run(signed, "trace", 0).values()
        for finding in module_findings
    ]
    assert signed["policy"]["enforcement_mode"] == "declared"
    assert signed["tool_transcript"]["call_count"] == 1
    assert findings
    assert all(finding.status == Status.PASS for finding in findings)
    assert any(finding.code == "TR-POL-002" for finding in findings)
    assert any(finding.code == "TR-SIG-005" for finding in findings)


def test_real_workflow_call_identifier_is_fingerprinted_before_retention():
    def noop() -> str:
        """Return a local response."""
        return "done"

    tracker = TraceEventHandler()
    agent = FunctionAgent(
        tools=[noop],
        llm=model_for_calls([("noop", PAYLOAD, {})]),
        streaming=False,
        timeout=15,
    )
    asyncio.run(observe_run(agent, tracker))
    assert (
        tracker.tool_calls[0].event_id
        == "sha256:" + hashlib.sha256(PAYLOAD.encode()).hexdigest()
    )
    assert PAYLOAD not in tracker.transcript_bytes().decode()
    assert PAYLOAD not in json.dumps(signed_record(tracker))


def test_concurrent_real_workflows_keep_separate_per_run_transcripts():
    async def scenario():
        started = set()
        both_started = asyncio.Event()
        invocations = []

        async def rendezvous(label: str) -> str:
            """Overlap two local tool invocations without timing assumptions."""
            started.add(label)
            if len(started) == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=5)
            invocations.append(label)
            return label

        trackers = [TraceEventHandler(), TraceEventHandler()]
        agents = [
            FunctionAgent(
                tools=[rendezvous],
                llm=model_for_calls(
                    [("rendezvous", f"call-{label}", {"label": label})]
                ),
                streaming=False,
                timeout=15,
            )
            for label in ["left", "right"]
        ]
        await asyncio.gather(
            *(observe_run(agent, tracker) for agent, tracker in zip(agents, trackers))
        )
        return trackers, invocations

    trackers, invocations = asyncio.run(scenario())
    assert sorted(invocations) == ["left", "right"]
    for label, tracker in zip(["left", "right"], trackers):
        assert len(tracker.tool_calls) == 1
        assert (
            tracker.tool_calls[0].event_id
            == "sha256:" + hashlib.sha256(f"call-{label}".encode()).hexdigest()
        )
        signed = signed_record(tracker, subject=f"spiffe://example.org/agent/{label}")
        assert signed["tool_transcript"]["call_count"] == 1
    assert trackers[0].transcript_bytes() != trackers[1].transcript_bytes()


def test_real_failed_tool_request_does_not_gain_a_success_claim():
    invocations = []

    def fail_locally(payload: str) -> str:
        """Raise a normal local tool error."""
        invocations.append(payload)
        raise RuntimeError(f"failed {payload}")

    tracker = TraceEventHandler()
    agent = FunctionAgent(
        tools=[fail_locally],
        llm=model_for_calls([("fail_locally", "failed-call", {"payload": PAYLOAD})]),
        streaming=False,
        timeout=15,
    )
    _, events = asyncio.run(observe_run(agent, tracker))
    outcome = next(
        event for event in events if type(event).__name__ == "ToolCallResult"
    )
    assert outcome.tool_output.is_error is True
    assert invocations == [PAYLOAD]
    transcript = json.loads(tracker.transcript_bytes())
    assert len(transcript) == 1
    assert set(transcript[0]) == {"tool", "event_id", "span_id"}
    assert PAYLOAD not in json.dumps(signed_record(tracker))


def test_unknown_tool_request_is_observed_without_proving_execution():
    invocations = []

    def available_tool() -> str:
        """Record entry into an available local tool."""
        invocations.append("available_tool")
        return "done"

    tracker = TraceEventHandler()
    agent = FunctionAgent(
        tools=[available_tool],
        llm=model_for_calls([("unknown_tool", "unknown-call", {})]),
        streaming=False,
        timeout=15,
    )
    _, events = asyncio.run(observe_run(agent, tracker))
    outcome = next(
        event for event in events if type(event).__name__ == "ToolCallResult"
    )
    assert outcome.tool_output.is_error is True
    assert invocations == []
    assert [call.name for call in tracker.tool_calls] == ["unknown_tool"]
    assert signed_record(tracker)["tool_transcript"]["call_count"] == 1


def test_documented_legacy_bridge_does_not_observe_modern_workflow_tool_requests():
    """Keep the original normal-run mismatch visible beside the corrected path."""
    legacy = TraceEventHandler()
    workflow = TraceEventHandler()
    observed_classes = []

    class Bridge(BaseEventHandler):
        def handle(self, event, **kwargs):
            observed_classes.append(event.class_name())
            legacy.observe(event)

    def noop() -> str:
        """Return a local response."""
        return "done"

    dispatcher = get_dispatcher()
    bridge = Bridge()
    dispatcher.add_event_handler(bridge)
    try:
        agent = FunctionAgent(
            tools=[noop],
            llm=model_for_calls([("noop", "call-1", {})]),
            streaming=False,
            timeout=15,
        )
        asyncio.run(observe_run(agent, workflow))
    finally:
        dispatcher.event_handlers.remove(bridge)
    assert "LLMChatStartEvent" in observed_classes
    assert "AgentToolCallEvent" not in observed_classes
    assert legacy.tool_calls == []
    assert len(workflow.tool_calls) == 1


def test_cancelled_real_workflow_keeps_only_observed_request_then_fresh_run_works():
    async def scenario():
        entered = asyncio.Event()
        exited = asyncio.Event()
        completed = []

        async def wait_locally() -> str:
            """Wait until this local workflow is cancelled."""
            entered.set()
            try:
                await asyncio.Event().wait()
                completed.append("wait_locally")
                return "completed"
            finally:
                exited.set()

        partial = TraceEventHandler()
        agent = FunctionAgent(
            tools=[wait_locally],
            llm=model_for_calls([("wait_locally", "cancelled-call", {})]),
            streaming=False,
            timeout=15,
        )
        handler = agent.run(user_msg=PAYLOAD)
        stream = handler.stream_events()
        events = []
        try:
            async for event in stream:
                events.append(event)
                partial.observe_workflow(event)
                if type(event).__name__ == "ToolCall":
                    await asyncio.wait_for(entered.wait(), timeout=5)
                    await handler.cancel_run()
                    break
            with pytest.raises(WorkflowCancelledByUser):
                await handler
            assert handler.is_done()
            await asyncio.wait_for(exited.wait(), timeout=5)
        finally:
            await stream.aclose()
            if not handler.is_done():
                await handler.cancel_run()

        assert completed == []
        assert not any(type(event).__name__ == "ToolCallResult" for event in events)
        assert [call.name for call in partial.tool_calls] == ["wait_locally"]
        assert set(json.loads(partial.transcript_bytes())[0]) == {
            "tool",
            "event_id",
            "span_id",
        }

        later_invocations = []

        def finish_locally() -> str:
            """Complete a fresh local run after cancellation."""
            later_invocations.append("finish_locally")
            return "done"

        fresh = TraceEventHandler()
        subsequent = FunctionAgent(
            tools=[finish_locally],
            llm=model_for_calls([("finish_locally", "fresh-call", {})]),
            streaming=False,
            timeout=15,
        )
        await observe_run(subsequent, fresh)
        assert later_invocations == ["finish_locally"]
        assert [call.name for call in fresh.tool_calls] == ["finish_locally"]
        assert [call.name for call in partial.tool_calls] == ["wait_locally"]
        assert signed_record(fresh)["tool_transcript"]["call_count"] == 1

    asyncio.run(scenario())


def test_readme_workflow_example_runs_verbatim_with_released_agent():
    readme = pathlib.Path(__file__).with_name("README.md").read_text()
    snippet = readme.split("```python\n", 1)[1].split("\n```", 1)[0]
    namespace = {}
    exec(compile(snippet, "README.md:first-python-example", "exec"), namespace)
    invocations = []

    def count_payload(payload: str) -> int:
        """Count one local payload."""
        invocations.append(payload)
        return len(payload)

    agent = FunctionAgent(
        tools=[count_payload],
        llm=model_for_calls([("count_payload", "readme-call", {"payload": PAYLOAD})]),
        streaming=False,
        timeout=15,
    )
    key = generate_key()
    result, signed = asyncio.run(
        namespace["run_with_record"](
            agent,
            PAYLOAD,
            subject=SUBJECT,
            policy_bundle=b'{"declared-policy":true}',
            workload_digest="sha256:" + "a" * 64,
            model_provider="local-test-double",
            model_id="MockFunctionCallingLLM",
            signing_key=key,
        )
    )
    assert invocations == [PAYLOAD]
    assert result.response.content == MODEL_OUTPUT
    verify_record(signed, key.public_key())
    parsed = TrustRecord.model_validate(signed)
    assert parsed.tool_transcript.call_count == 1
    assert parsed.policy.enforcement_mode == "declared"
    assert parsed.runtime.platform == "software-only"
    assert PAYLOAD not in json.dumps(signed)
