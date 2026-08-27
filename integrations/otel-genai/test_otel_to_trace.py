"""Tests for the OTel GenAI adapter.

Two things are worth pinning: the mapping produces a record the real model
accepts, and the adapter refuses rather than guessing when the telemetry does not
carry what a record needs. Telemetry is lossy by design, so "refuses" is the
common path and it has to be the well-tested one.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from agentrust_trace_adapters import MissingEvidence  # noqa: E402
from otel_to_trace import UNMAPPED_ATTRIBUTES, build_from_spans  # noqa: E402

JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
DIGEST = "sha256:" + "d" * 64


def span(op, **attrs):
    return {"name": op, "attributes": {"gen_ai.operation.name": op, **attrs}}


def chat_span(**over):
    a = {
        "gen_ai.provider.name": "anthropic",
        "gen_ai.request.model": "claude-sonnet-4-6",
        "gen_ai.conversation.id": "conv-1",
    }
    a.update(over)
    return span("chat", **a)


def tool_span(name, call_id, **over):
    a = {
        "gen_ai.tool.name": name,
        "gen_ai.tool.call.id": call_id,
        "gen_ai.tool.type": "function",
        "gen_ai.conversation.id": "conv-1",
    }
    a.update(over)
    return span("execute_tool", **a)


def build(spans, **over):
    kwargs = dict(
        subject="spiffe://example.org/agent/support-bot",
        policy_bundle=b'{"rules":["deny-egress"]}',
        workload_digest=DIGEST,
        jwk=JWK,
        producer="otel-collector/1.0",
    )
    kwargs.update(over)
    return build_from_spans(spans, **kwargs)


# --- mapping ---------------------------------------------------------------


def test_record_validates_against_the_model() -> None:
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    record = build([chat_span(), tool_span("search", "c1"), tool_span("pay", "c2")])
    parsed = TrustRecord.model_validate(record)
    assert parsed.model.provider == "anthropic"
    assert parsed.model.model_id == "claude-sonnet-4-6"
    assert parsed.tool_transcript is not None
    assert parsed.tool_transcript.call_count == 2


def test_downgrade_signals_are_set() -> None:
    record = build([chat_span()])
    assert record["origin"]["kind"] == "log-import"
    assert record["origin"]["producer"] == "otel-collector/1.0"
    assert record["origin"]["source_event_id"] == "conv-1"
    assert record["runtime"]["platform"] == "software-only"
    assert record["appraisal"]["status"] == "none"


def test_origin_kind_can_name_a_control_plane() -> None:
    record = build([chat_span()], origin_kind="third-party-control-plane")
    assert record["origin"]["kind"] == "third-party-control-plane"


def test_otlp_json_attribute_lists_are_accepted() -> None:
    """OTLP-JSON writes attributes as [{"key":..,"value":{"stringValue":..}}]."""
    otlp = {
        "name": "chat",
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
            {"key": "gen_ai.provider.name", "value": {"stringValue": "openai"}},
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4"}},
            {"key": "gen_ai.conversation.id", "value": {"stringValue": "conv-9"}},
        ],
    }
    record = build([otlp])
    assert record["model"]["provider"] == "openai"
    assert record["origin"]["source_event_id"] == "conv-9"


def test_transcript_is_deterministic_and_order_sensitive() -> None:
    a = build([chat_span(), tool_span("search", "c1"), tool_span("pay", "c2")])
    b = build([chat_span(), tool_span("search", "c1"), tool_span("pay", "c2")])
    c = build([chat_span(), tool_span("pay", "c2"), tool_span("search", "c1")])
    assert a["tool_transcript"]["hash"] == b["tool_transcript"]["hash"]
    assert c["tool_transcript"]["hash"] != a["tool_transcript"]["hash"]


def test_transcript_excludes_payloads() -> None:
    """Arguments and results must not reach a record meant to be shareable."""
    with_payload = build(
        [
            chat_span(),
            tool_span(
                "pay",
                "c1",
                **{
                    "gen_ai.tool.call.arguments": '{"iban":"GB33BUKB20201555555555"}',
                    "gen_ai.tool.call.result": '{"status":"ok"}',
                },
            ),
        ]
    )
    without = build([chat_span(), tool_span("pay", "c1")])
    assert with_payload["tool_transcript"]["hash"] == without["tool_transcript"]["hash"]


def test_payload_attributes_are_documented_as_unmapped() -> None:
    for key in ("gen_ai.tool.call.arguments", "gen_ai.tool.call.result"):
        assert key in UNMAPPED_ATTRIBUTES


# --- refusals --------------------------------------------------------------


def test_no_spans_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="no spans"):
        build([])


def test_missing_model_is_refused_not_guessed() -> None:
    """gen_ai.request.model is only Conditionally Required upstream."""
    with pytest.raises(MissingEvidence, match="gen_ai.request.model"):
        build([span("chat", **{"gen_ai.provider.name": "anthropic"})])


def test_missing_provider_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="gen_ai.provider.name"):
        build([span("chat", **{"gen_ai.request.model": "gpt-4"})])


def test_mixed_conversations_are_refused() -> None:
    """One record describes one execution, or it is wrong rather than incomplete."""
    with pytest.raises(MissingEvidence, match="2 conversations"):
        build([chat_span(), chat_span(**{"gen_ai.conversation.id": "conv-2"})])


def test_no_tool_spans_omits_the_transcript_block() -> None:
    """Absent is not the same as zero calls observed."""
    record = build([chat_span()])
    assert "tool_transcript" not in record


def test_policy_bundle_is_still_required() -> None:
    with pytest.raises(MissingEvidence, match="policy bundle bytes"):
        build([chat_span()], policy_bundle=b"")


def test_conversation_id_may_be_absent() -> None:
    """Conditionally Required upstream, so a record without one is still buildable."""
    record = build([span("chat", **{"gen_ai.provider.name": "anthropic",
                                    "gen_ai.request.model": "gpt-4"})])
    assert "source_event_id" not in record["origin"]
