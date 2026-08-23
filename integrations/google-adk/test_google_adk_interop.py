"""Released Google ADK 2.7.1 Runner interoperability regression."""

from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import sys
from collections.abc import AsyncGenerator

import pytest
from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import generate_key, sign_record
from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.apps import App
from google.adk.models import BaseLlm, LlmRequest, LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import PrivateAttr
from trace_tests import runner as trace_tests_runner
from trace_tests.result import Status

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from google_adk_to_trace import GoogleAdkTracePlugin

SECRET = "customer-account-reference-that-must-not-enter-the-record"
DIGEST = "sha256:" + "e" * 64


class SequencedModel(BaseLlm):
    model: str = "released-adk-test-model"
    responses: list[LlmResponse]
    response_index: int = 0

    async def generate_content_async(
        self,
        llm_request: LlmRequest,  # noqa: ARG002 - deterministic fixture
        stream: bool = False,  # noqa: ARG002
    ) -> AsyncGenerator[LlmResponse, None]:
        response = self.responses[self.response_index]
        self.response_index += 1
        yield response


class BlockingModel(BaseLlm):
    model: str = "released-adk-blocking-model"
    _started: asyncio.Event = PrivateAttr(default_factory=asyncio.Event)

    @property
    def started(self) -> asyncio.Event:
        return self._started

    async def generate_content_async(
        self,
        llm_request: LlmRequest,  # noqa: ARG002 - deterministic fixture
        stream: bool = False,  # noqa: ARG002
    ) -> AsyncGenerator[LlmResponse, None]:
        self._started.set()
        await asyncio.Event().wait()
        yield LlmResponse(
            content=types.Content(role="model", parts=[types.Part(text="unused")])
        )


class RecoverToolErrorPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__(name="recover_tool_error")

    async def on_tool_error_callback(
        self,
        *,
        tool,  # noqa: ARG002 - recovery fixture
        tool_args,  # noqa: ARG002 - recovery fixture
        tool_context,  # noqa: ARG002 - recovery fixture
        error,  # noqa: ARG002 - recovery fixture
    ) -> dict[str, bool]:
        return {"recovered": True}


class ShortCircuitToolPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__(name="short_circuit_tool")

    async def before_tool_callback(
        self,
        *,
        tool,  # noqa: ARG002 - short-circuit fixture
        tool_args,  # noqa: ARG002 - short-circuit fixture
        tool_context,  # noqa: ARG002 - short-circuit fixture
    ) -> dict[str, bool]:
        return {"synthetic": True}


def model_for_tool(
    tool_name: str, *, arguments: dict[str, str], call_id: str = "call-1"
) -> SequencedModel:
    return SequencedModel(
        responses=[
            LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            function_call=types.FunctionCall(
                                id=call_id,
                                name=tool_name,
                                args=arguments,
                            )
                        )
                    ],
                )
            ),
            LlmResponse(
                content=types.Content(role="model", parts=[types.Part(text="complete")])
            ),
        ]
    )


def text_model(text: str = "complete") -> SequencedModel:
    return SequencedModel(
        responses=[
            LlmResponse(
                content=types.Content(role="model", parts=[types.Part(text=text)])
            )
        ]
    )


def build_signed(plugin: GoogleAdkTracePlugin, invocation_id: str) -> dict:
    return sign_record(
        plugin.build_record(
            invocation_id,
            subject="spiffe://example.org/agent/google-adk",
            policy_bundle=b'{"rules":["no-payload-egress"]}',
            workload_digest=DIGEST,
            data_class="confidential",
            model_provider="test-provider",
            iat=1_700_000_000,
        ),
        generate_key(),
    )


def runner_for(
    agent: LlmAgent, plugin: GoogleAdkTracePlugin, name: str
) -> InMemoryRunner:
    return InMemoryRunner(app=App(name=name, root_agent=agent, plugins=[plugin]))


def measure_payload(payload: str) -> dict[str, int]:
    """Return the length without returning the input."""
    return {"length": len(payload)}


def reject_payload(payload: str) -> dict[str, str]:
    """Raise a deterministic tool failure."""
    raise RuntimeError(f"rejected {payload}")


def must_not_execute(payload: str) -> dict[str, str]:
    """Fail if a short-circuited tool reaches its function body."""
    raise AssertionError(f"tool unexpectedly executed with {payload}")


def test_released_runner_success_emits_valid_level_zero_record() -> None:
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(
        name="success_agent",
        model=model_for_tool("measure_payload", arguments={"payload": SECRET}),
        tools=[measure_payload],
    )
    runner = runner_for(agent, plugin, "success_app")

    asyncio.run(runner.run_debug(SECRET, quiet=True))

    assert isinstance(plugin, BasePlugin)
    assert len(plugin.invocation_ids) == 1
    invocation_id = plugin.invocation_ids[0]
    calls = plugin.tool_calls(invocation_id)
    assert [(call.name, call.outcome) for call in calls] == [("measure_payload", "ok")]
    assert calls[0].function_call_fingerprint == (
        "sha256:" + hashlib.sha256(b"call-1").hexdigest()
    )
    transcript = json.loads(plugin.transcript_bytes(invocation_id))
    assert transcript["outcome"] == "ok"
    assert SECRET.encode() not in plugin.transcript_bytes(invocation_id)

    signed = build_signed(plugin, invocation_id)
    assert SECRET not in str(signed)
    parsed = TrustRecord.model_validate(signed)
    assert parsed.runtime.platform == "software-only"
    assert parsed.tool_transcript is not None
    assert parsed.tool_transcript.call_count == 1
    assert parsed.appraisal.status == "none"
    assert "origin" not in signed
    assert "transparency" not in signed


def test_released_runner_model_only_run_omits_tool_transcript() -> None:
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(name="model_only_agent", model=text_model())
    runner = runner_for(agent, plugin, "model_only_app")

    asyncio.run(runner.run_debug("test", quiet=True))

    invocation_id = plugin.invocation_ids[0]
    assert plugin.tool_calls(invocation_id) == []
    assert json.loads(plugin.transcript_bytes(invocation_id))["outcome"] == "ok"

    signed = build_signed(plugin, invocation_id)
    parsed = TrustRecord.model_validate(signed)
    assert parsed.model.model_id == "released-adk-test-model"
    assert parsed.tool_transcript is None


def test_model_supplied_call_id_is_fingerprinted_before_retention() -> None:
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(
        name="secret_id_agent",
        model=model_for_tool(
            "measure_payload",
            arguments={"payload": "safe"},
            call_id=SECRET,
        ),
        tools=[measure_payload],
    )
    runner = runner_for(agent, plugin, "secret_id_app")

    asyncio.run(runner.run_debug("test", quiet=True))

    invocation_id = plugin.invocation_ids[0]
    transcript = plugin.transcript_bytes(invocation_id)
    assert SECRET.encode() not in transcript
    assert plugin.tool_calls(invocation_id)[0].function_call_fingerprint == (
        "sha256:" + hashlib.sha256(SECRET.encode()).hexdigest()
    )


def test_level_zero_conformance_with_external_advisory_enforcement() -> None:
    """The optional externally enforced path passes the released Level 0 suite."""
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(
        name="conformance_agent",
        model=model_for_tool("measure_payload", arguments={"payload": "test"}),
        tools=[measure_payload],
    )
    runner = runner_for(agent, plugin, "conformance_app")
    asyncio.run(runner.run_debug("test", quiet=True))
    invocation_id = plugin.invocation_ids[0]
    signed = sign_record(
        plugin.build_record(
            invocation_id,
            subject="spiffe://example.org/agent/google-adk",
            policy_bundle=b'{"rules":["external-advisory-layer"]}',
            enforcement_mode="advisory",
            workload_digest=DIGEST,
            data_class="internal",
            model_provider="test-provider",
        ),
        generate_key(),
    )

    findings = [
        finding
        for module_findings in trace_tests_runner.run(signed, "trace", 0).values()
        for finding in module_findings
    ]
    assert [finding.code for finding in findings if finding.status is Status.FAIL] == []


def test_recovered_tool_error_remains_one_correlated_call() -> None:
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(
        name="recovery_agent",
        model=model_for_tool("reject_payload", arguments={"payload": SECRET}),
        tools=[reject_payload],
    )
    app = App(
        name="recovery_app",
        root_agent=agent,
        plugins=[plugin, RecoverToolErrorPlugin()],
    )
    runner = InMemoryRunner(app=app)

    asyncio.run(runner.run_debug("recover", quiet=True))

    invocation_id = plugin.invocation_ids[0]
    calls = plugin.tool_calls(invocation_id)
    assert len(calls) == 1
    assert calls[0].outcome == "ok"
    assert calls[0].observed_outcomes == ("error", "ok")
    assert SECRET.encode() not in plugin.transcript_bytes(invocation_id)


def test_earlier_short_circuit_is_recorded_as_completion_without_start() -> None:
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(
        name="short_circuit_agent",
        model=model_for_tool("must_not_execute", arguments={"payload": SECRET}),
        tools=[must_not_execute],
    )
    app = App(
        name="short_circuit_app",
        root_agent=agent,
        plugins=[ShortCircuitToolPlugin(), plugin],
    )
    runner = InMemoryRunner(app=app)

    asyncio.run(runner.run_debug("short circuit", quiet=True))

    invocation_id = plugin.invocation_ids[0]
    calls = plugin.tool_calls(invocation_id)
    assert len(calls) == 1
    assert (calls[0].observed_start, calls[0].outcome) == (False, "ok")
    assert SECRET.encode() not in plugin.transcript_bytes(invocation_id)


def test_released_runner_reports_tool_failure_without_exception_payload() -> None:
    plugin = GoogleAdkTracePlugin()
    agent = LlmAgent(
        name="failure_agent",
        model=model_for_tool("reject_payload", arguments={"payload": SECRET}),
        tools=[reject_payload],
    )
    runner = runner_for(agent, plugin, "failure_app")

    with pytest.raises(RuntimeError, match="rejected"):
        asyncio.run(runner.run_debug("fail", quiet=True))

    invocation_id = plugin.invocation_ids[0]
    assert plugin.tool_calls(invocation_id)[0].outcome == "error"
    assert b'"outcome":"error"' in plugin.transcript_bytes(invocation_id)
    assert SECRET.encode() not in plugin.transcript_bytes(invocation_id)
    assert SECRET not in str(build_signed(plugin, invocation_id))


def test_released_runners_keep_concurrent_invocations_isolated() -> None:
    async def exercise() -> GoogleAdkTracePlugin:
        plugin = GoogleAdkTracePlugin()
        alpha = runner_for(
            LlmAgent(
                name="alpha_agent",
                model=model_for_tool(
                    "measure_payload", arguments={"payload": "alpha-secret"}
                ),
                tools=[measure_payload],
            ),
            plugin,
            "alpha_app",
        )
        beta = runner_for(
            LlmAgent(
                name="beta_agent",
                model=model_for_tool(
                    "measure_payload", arguments={"payload": "beta-secret"}
                ),
                tools=[measure_payload],
            ),
            plugin,
            "beta_app",
        )
        await asyncio.gather(
            alpha.run_debug("alpha", session_id="alpha-session", quiet=True),
            beta.run_debug("beta", session_id="beta-session", quiet=True),
        )
        return plugin

    plugin = asyncio.run(exercise())
    assert len(plugin.invocation_ids) == 2
    for invocation_id in plugin.invocation_ids:
        assert [
            (call.name, call.outcome) for call in plugin.tool_calls(invocation_id)
        ] == [("measure_payload", "ok")]


def test_cancelled_released_run_remains_incomplete() -> None:
    async def exercise() -> tuple[GoogleAdkTracePlugin, str]:
        plugin = GoogleAdkTracePlugin()
        model = BlockingModel()
        runner = runner_for(
            LlmAgent(name="blocking_agent", model=model),
            plugin,
            "blocking_app",
        )
        task = asyncio.create_task(runner.run_debug("wait", quiet=True))
        await model.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return plugin, plugin.invocation_ids[0]

    plugin, invocation_id = asyncio.run(exercise())
    assert b'"outcome":"incomplete"' in plugin.transcript_bytes(invocation_id)
    assert plugin.tool_calls(invocation_id) == []


def test_same_name_child_cannot_turn_cancelled_root_into_success() -> None:
    async def exercise() -> tuple[GoogleAdkTracePlugin, str]:
        plugin = GoogleAdkTracePlugin()
        blocking_model = BlockingModel()
        root = SequentialAgent(
            name="shared_name",
            sub_agents=[
                LlmAgent(name="shared_name", model=text_model()),
                LlmAgent(name="blocking_child", model=blocking_model),
            ],
        )
        runner = InMemoryRunner(
            app=App(name="same_name_app", root_agent=root, plugins=[plugin])
        )
        task = asyncio.create_task(runner.run_debug("wait", quiet=True))
        await blocking_model.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return plugin, plugin.invocation_ids[0]

    plugin, invocation_id = asyncio.run(exercise())
    transcript = json.loads(plugin.transcript_bytes(invocation_id))
    assert transcript["outcome"] == "incomplete"
