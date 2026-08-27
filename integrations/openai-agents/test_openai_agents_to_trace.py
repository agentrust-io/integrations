"""Tests for the OpenAI Agents SDK adapter.

Split in two. Everything here runs without the SDK installed, against fake spans
shaped like the real ones, because record construction is where the honesty
rules live and they should be testable on their own. The interop test that runs
a real released agent is in test_openai_agents_interop.py.
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from openai_agents_to_trace import (  # noqa: E402
    TRACE_PROFILE,
    UNMAPPED_SPANS,
    MissingEvidence,
    ToolCall,
    TraceRecordProcessor,
    build_record,
)

POLICY = b'permit(principal, action, resource) when { context.ok };'
WORKLOAD = "sha256:" + "ab" * 32
SUBJECT = "spiffe://example.org/agent/support-bot"


# --- fakes shaped like agents.tracing.span_data ---------------------------


@dataclass
class FunctionSpanData:
    name: str
    input: str | None = None
    output: str | None = None
    mcp_data: dict | None = None


@dataclass
class AgentSpanData:
    name: str


@dataclass
class HandoffSpanData:
    from_agent: str
    to_agent: str


@dataclass
class GenerationSpanData:
    input: list
    output: list
    model: str


@dataclass
class GuardrailSpanData:
    name: str
    triggered: bool = False


@dataclass
class FakeSpan:
    span_data: object
    trace_id: str = "trace-1"
    span_id: str = "span-1"
    error: dict | None = None


@dataclass
class FakeTrace:
    trace_id: str = "trace-1"


def record(**kwargs) -> dict:
    base = dict(
        subject=SUBJECT,
        policy_bundle=POLICY,
        workload_digest=WORKLOAD,
        data_class="internal",
        model_provider="openai",
        model_id="gpt-5",
    )
    base.update(kwargs)
    return build_record(**base)


# --- honesty rules --------------------------------------------------------


def test_enforcement_mode_defaults_to_declared() -> None:
    """The SDK enforces no policy. Anything else would describe enforcement that
    did not happen."""
    assert record()["policy"]["enforcement_mode"] == "declared"


def test_a_bare_run_carries_no_origin_block() -> None:
    """A processor runs in the agent's own process, so absence means self."""
    assert "origin" not in record()


def test_runtime_is_software_only_without_an_attestation() -> None:
    value = record()

    assert value["runtime"]["platform"] == "software-only"
    assert value["runtime"]["measurement"].startswith("sha256:")


def test_an_attestation_lifts_the_record_without_changing_anything_else() -> None:
    measurement = "sha256:" + "cd" * 32

    value = record(attestation={"platform": "amd-sev-snp", "measurement": measurement})

    assert value["runtime"] == {"platform": "amd-sev-snp", "measurement": measurement}
    assert value["policy"]["enforcement_mode"] == "declared"


def test_an_attestation_may_not_name_software_only() -> None:
    with pytest.raises(MissingEvidence, match="attests nothing"):
        record(attestation={"platform": "software-only", "measurement": WORKLOAD})


def test_appraisal_is_none_because_building_is_not_appraising() -> None:
    assert record()["appraisal"] == {"status": "none", "verifier": "openai-agents-adapter"}


def test_transparency_is_absent_rather_than_empty() -> None:
    assert "transparency" not in record()


# --- required evidence ----------------------------------------------------


def test_subject_must_be_a_spiffe_uri_or_did() -> None:
    with pytest.raises(MissingEvidence, match="SPIFFE URI or a DID"):
        record(subject="support-bot")


def test_policy_bundle_must_be_bytes_not_a_name() -> None:
    with pytest.raises(MissingEvidence, match="digest of a bundle"):
        record(policy_bundle=b"")


def test_model_identity_is_required_because_the_span_that_has_it_is_not_read() -> None:
    with pytest.raises(MissingEvidence, match="message payloads"):
        record(model_id="")


def test_workload_digest_must_be_a_digest() -> None:
    with pytest.raises(MissingEvidence, match="nothing truthful to default"):
        record(workload_digest="latest")


def test_unknown_enforcement_mode_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="declared"):
        record(enforcement_mode="enforced")


# --- transcript -----------------------------------------------------------


def test_transcript_is_omitted_when_nothing_ran() -> None:
    assert "tool_transcript" not in record()


def test_transcript_counts_calls_and_hashes_identity() -> None:
    value = record(tools=(ToolCall("search", "c1"), ToolCall("write", "c2")))

    assert value["tool_transcript"]["call_count"] == 2
    assert value["tool_transcript"]["hash"].startswith("sha256:")


def test_transcript_changes_when_the_order_changes() -> None:
    one = record(tools=(ToolCall("a", "1"), ToolCall("b", "2")))
    two = record(tools=(ToolCall("b", "2"), ToolCall("a", "1")))

    assert one["tool_transcript"]["hash"] != two["tool_transcript"]["hash"]


def test_handoffs_change_the_transcript() -> None:
    """Which agent held the run when a tool fired is part of the reconstruction."""
    without = record(tools=(ToolCall("a", "1"),))
    with_handoff = record(tools=(ToolCall("a", "1"),), handoffs=(("triage", "billing"),))

    assert without["tool_transcript"]["hash"] != with_handoff["tool_transcript"]["hash"]


def test_no_payload_reaches_the_record() -> None:
    """FunctionSpanData carries input and output. Neither may appear anywhere."""
    processor = TraceRecordProcessor()
    processor.on_trace_start(FakeTrace())
    processor.on_span_end(
        FakeSpan(FunctionSpanData(name="search", input="SECRET-ARGUMENT", output="SECRET-RESULT"))
    )
    processor.on_trace_end(FakeTrace())

    rendered = json.dumps(
        processor.build_record(
            subject=SUBJECT,
            policy_bundle=POLICY,
            workload_digest=WORKLOAD,
            data_class="internal",
            model_provider="openai",
            model_id="gpt-5",
        )
    )

    assert "SECRET-ARGUMENT" not in rendered
    assert "SECRET-RESULT" not in rendered


# --- processor ------------------------------------------------------------


def test_function_spans_become_tool_calls() -> None:
    processor = TraceRecordProcessor()
    processor.on_trace_start(FakeTrace())
    processor.on_span_end(FakeSpan(FunctionSpanData(name="search"), span_id="s1"))
    processor.on_span_end(FakeSpan(FunctionSpanData(name="write"), span_id="s2"))
    processor.on_trace_end(FakeTrace())

    assert [t.name for t in processor.tool_calls] == ["search", "write"]
    assert [t.call_id for t in processor.tool_calls] == ["s1", "s2"]


def test_an_mcp_tool_is_labelled_as_one() -> None:
    processor = TraceRecordProcessor()
    processor.on_trace_start(FakeTrace())
    processor.on_span_end(FakeSpan(FunctionSpanData(name="fetch", mcp_data={"server": "docs"})))

    assert processor.tool_calls[0].kind == "mcp"


def test_generation_and_guardrail_spans_are_ignored() -> None:
    """Both are in UNMAPPED_SPANS, for different reasons."""
    processor = TraceRecordProcessor()
    processor.on_trace_start(FakeTrace())
    processor.on_span_end(FakeSpan(GenerationSpanData(input=[{"m": 1}], output=[], model="gpt-5")))
    processor.on_span_end(FakeSpan(GuardrailSpanData(name="pii", triggered=True)))

    assert processor.tool_calls == ()
    assert "GenerationSpanData" in UNMAPPED_SPANS
    assert "GuardrailSpanData" in UNMAPPED_SPANS


def test_concurrent_runs_do_not_share_a_transcript() -> None:
    """A record whose transcript describes two runs and whose subject names one
    is wrong rather than incomplete."""
    processor = TraceRecordProcessor()
    processor.on_trace_start(FakeTrace("run-a"))
    processor.on_trace_start(FakeTrace("run-b"))
    processor.on_span_end(FakeSpan(FunctionSpanData(name="a-tool"), trace_id="run-a"))
    processor.on_span_end(FakeSpan(FunctionSpanData(name="b-tool"), trace_id="run-b"))
    processor.on_trace_end(FakeTrace("run-a"))
    processor.on_trace_end(FakeTrace("run-b"))

    args = dict(
        subject=SUBJECT,
        policy_bundle=POLICY,
        workload_digest=WORKLOAD,
        data_class="internal",
        model_provider="openai",
        model_id="gpt-5",
    )
    a = processor.build_record(trace_id="run-a", **args)
    b = processor.build_record(trace_id="run-b", **args)

    assert a["tool_transcript"]["call_count"] == 1
    assert b["tool_transcript"]["call_count"] == 1
    assert a["tool_transcript"]["hash"] != b["tool_transcript"]["hash"]


def test_building_before_any_run_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="add_trace_processor"):
        TraceRecordProcessor().build_record(
            subject=SUBJECT,
            policy_bundle=POLICY,
            workload_digest=WORKLOAD,
            data_class="internal",
            model_provider="openai",
            model_id="gpt-5",
        )


def test_the_module_imports_without_the_sdk_installed() -> None:
    """Record construction must be testable without openai-agents."""
    import openai_agents_to_trace

    assert openai_agents_to_trace.TRACE_PROFILE == TRACE_PROFILE


def test_record_has_the_shapes_trace_v0_2_requires() -> None:
    import re

    value = record(tools=(ToolCall("search", "c1"),))
    digest = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")

    for field in ("eat_profile", "iat", "subject", "model", "runtime", "policy",
                  "data_class", "build_provenance", "appraisal"):
        assert field in value, field
    assert digest.match(value["runtime"]["measurement"])
    assert digest.match(value["policy"]["bundle_hash"])
    assert digest.match(value["build_provenance"]["digest"])
    assert digest.match(value["tool_transcript"]["hash"])
    assert isinstance(value["iat"], int)
