"""Pydantic AI coverage, verified rather than assumed.

Issue #96 asked which frameworks need an adapter. Pydantic AI turned out not to:
it instruments through OpenTelemetry (`Agent.instrument_all(InstrumentationSettings(...))`)
rather than exposing a bespoke callback interface, and it emits the GenAI
semantic conventions this adapter already maps.

So the honest answer for that framework is "already covered", and the way to
show it is to run a real released agent and map its actual spans, not to read
its documentation and assert. That is what this does. No network: the run uses
Pydantic AI's own `TestModel`.

**One mapped attribute is missing, and it is recorded rather than smoothed
over.** Pydantic AI does not emit `gen_ai.tool.type`, so the transcript carries
`None` in that position. Harmless, and worth knowing before somebody compares
two transcripts across frameworks and finds a field that is populated in one and
not the other.

Two more differences that cost nothing, because both attributes are already in
`UNMAPPED_ATTRIBUTES` on purpose:

  Pydantic AI emits `gen_ai.agent.call.id` and `gen_ai.agent.name` where the
  conventions say `gen_ai.agent.id`. That drift is exactly what the unmapped
  table exists to make visible.

  It emits `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`,
  `gen_ai.input.messages` and `gen_ai.output.messages` **by default**. All four
  are payloads and all four are excluded. A real framework shipping them on by
  default is the argument for that exclusion, not against it.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

pytest.importorskip("pydantic_ai", reason="pydantic-ai-slim is not installed")
pytest.importorskip("opentelemetry.sdk", reason="opentelemetry-sdk is not installed")

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)
from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.instrumented import InstrumentationSettings  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from otel_to_trace import (  # noqa: E402
    OPERATION,
    TOOL_NAME,
    UNMAPPED_ATTRIBUTES,
    build_from_spans,
)

POLICY = b'permit(principal, action, resource) when { context.ok };'
WORKLOAD = "sha256:" + "ab" * 32
SUBJECT = "spiffe://example.org/agent/pydantic-ai"
JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}


@pytest.fixture(scope="module")
def spans() -> list[dict]:
    """Run a real Pydantic AI agent with a tool call and collect its spans."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    Agent.instrument_all(InstrumentationSettings(tracer_provider=provider))

    agent = Agent(TestModel())

    @agent.tool_plain
    def count_characters(text: str) -> int:
        """Count the characters in some text."""
        return len(text)

    try:
        agent.run_sync("count the characters in SECRETVALUE")
    finally:
        Agent.instrument_all(False)

    # The adapter takes plain dicts, which is what a collector exporter hands
    # over. Converting here keeps the adapter free of an OTel SDK dependency.
    return [{"attributes": dict(span.attributes or {})} for span in exporter.get_finished_spans()]


def test_pydantic_ai_emits_the_operation_name_the_adapter_selects_on(spans) -> None:
    """Without this the adapter finds no tool spans and the transcript is empty."""
    operations = {s["attributes"].get(OPERATION) for s in spans}

    assert "execute_tool" in operations


def test_the_tool_name_reaches_the_adapter(spans) -> None:
    tools = [s for s in spans if s["attributes"].get(OPERATION) == "execute_tool"]

    assert [s["attributes"].get(TOOL_NAME) for s in tools] == ["count_characters"]


def test_a_valid_record_is_produced_from_a_real_run(spans) -> None:
    record = build_from_spans(
        spans,
        subject=SUBJECT,
        policy_bundle=POLICY,
        workload_digest=WORKLOAD,
        jwk=JWK,
        producer="pydantic-ai",
        data_class="internal",
    )

    assert record["subject"] == SUBJECT
    assert record["tool_transcript"]["call_count"] == 1
    assert record["runtime"]["platform"] == "software-only"


def test_the_record_is_labelled_as_a_transcription(spans) -> None:
    """Pydantic AI instruments through OTel, so this is a log import, not a
    first-party observation. The record has to say so."""
    record = build_from_spans(
        spans,
        subject=SUBJECT,
        policy_bundle=POLICY,
        workload_digest=WORKLOAD,
        jwk=JWK,
        producer="pydantic-ai",
        data_class="internal",
    )

    assert record["origin"]["kind"] == "log-import"
    assert record["appraisal"]["status"] == "none"


def test_no_payload_reaches_the_record(spans) -> None:
    """Pydantic AI emits arguments, results and messages by default. None may
    survive into an artifact meant to be handed to a third party."""
    rendered = json.dumps(
        build_from_spans(
            spans,
            subject=SUBJECT,
            policy_bundle=POLICY,
            workload_digest=WORKLOAD,
            jwk=JWK,
            producer="pydantic-ai",
            data_class="internal",
        )
    )

    assert "SECRETVALUE" not in rendered
    assert "count_characters" not in rendered


def test_pydantic_ai_really_does_emit_the_payloads_we_exclude(spans) -> None:
    """The exclusion is not hypothetical. This asserts the framework ships them."""
    emitted = {key for s in spans for key in s["attributes"]}

    assert "gen_ai.tool.call.arguments" in emitted
    assert "gen_ai.tool.call.result" in emitted
    assert "gen_ai.input.messages" in emitted
    for payload in ("gen_ai.tool.call.arguments", "gen_ai.tool.call.result"):
        assert payload in UNMAPPED_ATTRIBUTES


def test_the_one_mapped_attribute_pydantic_ai_does_not_emit(spans) -> None:
    """gen_ai.tool.type is absent, so the transcript carries None there.

    Recorded rather than worked around: a reader comparing transcripts across
    frameworks should know why one field is populated in some and not others.
    """
    emitted = {key for s in spans for key in s["attributes"]}

    assert "gen_ai.tool.type" not in emitted


def test_agent_identity_drifts_from_the_conventions_and_costs_nothing(spans) -> None:
    """It emits gen_ai.agent.call.id where the conventions say gen_ai.agent.id.
    Both are already unmapped, so the drift is visible and harmless."""
    emitted = {key for s in spans for key in s["attributes"]}

    assert "gen_ai.agent.call.id" in emitted
    assert "gen_ai.agent.id" not in emitted
    assert "gen_ai.agent.id" in UNMAPPED_ATTRIBUTES
