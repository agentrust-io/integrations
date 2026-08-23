"""Framework-free evidence and privacy tests for the Google ADK adapter."""

from __future__ import annotations

import asyncio
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from google_adk_to_trace import (  # noqa: E402
    GoogleAdkTracePlugin,
    MissingEvidence,
    build_record,
)

DIGEST = "sha256:" + "f" * 64
SUBJECT = "spiffe://example.org/agent/google-adk"
SECRET = "customer-account-reference-that-must-not-enter-the-record"


def run(awaitable):
    return asyncio.run(awaitable)


def context(invocation_id: str, function_call_id: str | None = None, agent=None):
    return SimpleNamespace(
        invocation_id=invocation_id,
        function_call_id=function_call_id,
        agent=agent,
        future_payload_field=SECRET,
    )


def kwargs(**overrides):
    values = {
        "subject": SUBJECT,
        "policy_bundle": b'{"rules":["no-payload-egress"]}',
        "workload_digest": DIGEST,
        "data_class": "confidential",
        "model_provider": "test-provider",
        "iat": 1_700_000_000,
    }
    values.update(overrides)
    return values


def observed_plugin(invocation_id: str = "inv-1") -> GoogleAdkTracePlugin:
    plugin = GoogleAdkTracePlugin()
    run(plugin.before_run_callback(invocation_context=context(invocation_id)))
    run(
        plugin.before_model_callback(
            callback_context=context(invocation_id),
            llm_request=SimpleNamespace(model="test-model", contents=[SECRET]),
        )
    )
    return plugin


def test_successful_tool_is_observed_without_payloads() -> None:
    plugin = observed_plugin()
    tool = SimpleNamespace(name="lookup")
    ctx = context("inv-1", "call-1")

    assert (
        run(
            plugin.before_tool_callback(
                tool=tool, tool_args={"secret": SECRET}, tool_context=ctx
            )
        )
        is None
    )
    assert (
        run(
            plugin.after_tool_callback(
                tool=tool,
                tool_args={"secret": SECRET},
                tool_context=ctx,
                result={"secret": SECRET},
            )
        )
        is None
    )
    run(plugin.after_run_callback(invocation_context=context("inv-1")))

    assert [(call.name, call.outcome) for call in plugin.tool_calls("inv-1")] == [
        ("lookup", "ok")
    ]
    assert SECRET.encode() not in plugin.transcript_bytes("inv-1")


def test_tool_error_records_only_the_outcome() -> None:
    plugin = observed_plugin()
    tool = SimpleNamespace(name="pay")
    ctx = context("inv-1", "call-1")
    run(
        plugin.before_tool_callback(
            tool=tool, tool_args={"iban": SECRET}, tool_context=ctx
        )
    )
    run(
        plugin.on_tool_error_callback(
            tool=tool,
            tool_args={"iban": SECRET},
            tool_context=ctx,
            error=RuntimeError(SECRET),
        )
    )

    assert plugin.tool_calls("inv-1")[0].outcome == "error"
    assert SECRET.encode() not in plugin.transcript_bytes("inv-1")


def test_ambiguous_same_name_completions_are_not_paired_by_fifo() -> None:
    plugin = observed_plugin()
    tool = SimpleNamespace(name="parallel_tool")
    first = context("inv-1")
    second = context("inv-1")
    run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=first))
    run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=second))
    run(
        plugin.after_tool_callback(
            tool=tool,
            tool_args={},
            tool_context=second,
            result={},
        )
    )
    run(
        plugin.on_tool_error_callback(
            tool=tool,
            tool_args={},
            tool_context=first,
            error=RuntimeError(SECRET),
        )
    )

    assert [call.outcome for call in plugin.tool_calls("inv-1")] == [
        "incomplete",
        "incomplete",
    ]
    transcript = plugin.transcript_bytes("inv-1")
    assert transcript.count(b'"outcome":"ok"') == 1
    assert transcript.count(b'"outcome":"error"') == 1


def test_unfinished_tool_and_run_remain_incomplete() -> None:
    plugin = observed_plugin()
    run(
        plugin.before_tool_callback(
            tool=SimpleNamespace(name="slow_tool"),
            tool_args={},
            tool_context=context("inv-1", "call-1"),
        )
    )

    assert plugin.tool_calls("inv-1")[0].outcome == "incomplete"
    assert b'"outcome":"incomplete"' in plugin.transcript_bytes("inv-1")


def test_only_root_agent_completion_marks_a_run_successful() -> None:
    root = SimpleNamespace(name="root")
    child = SimpleNamespace(name="child")
    plugin = GoogleAdkTracePlugin()
    run(plugin.before_run_callback(invocation_context=context("inv-1", agent=root)))
    run(plugin.after_agent_callback(agent=child, callback_context=context("inv-1")))
    run(plugin.after_run_callback(invocation_context=context("inv-1")))
    assert b'"outcome":"incomplete"' in plugin.transcript_bytes("inv-1")

    run(plugin.after_agent_callback(agent=root, callback_context=context("inv-1")))
    run(plugin.after_run_callback(invocation_context=context("inv-1")))
    assert b'"outcome":"ok"' in plugin.transcript_bytes("inv-1")


def test_equivalent_root_agent_instance_marks_a_run_successful() -> None:
    original = SimpleNamespace(name="root")
    runtime_copy = SimpleNamespace(name="root")
    plugin = GoogleAdkTracePlugin()
    run(plugin.before_run_callback(invocation_context=context("inv-1", agent=original)))
    run(
        plugin.after_agent_callback(
            agent=runtime_copy, callback_context=context("inv-1")
        )
    )
    run(plugin.after_run_callback(invocation_context=context("inv-1")))
    assert b'"outcome":"ok"' in plugin.transcript_bytes("inv-1")


def test_same_name_child_does_not_mark_the_root_complete() -> None:
    root = SimpleNamespace(name="shared", parent_agent=None)
    child = SimpleNamespace(name="shared", parent_agent=root)
    plugin = GoogleAdkTracePlugin()
    run(plugin.before_run_callback(invocation_context=context("inv-1", agent=root)))
    run(plugin.after_agent_callback(agent=child, callback_context=context("inv-1")))
    run(plugin.after_run_callback(invocation_context=context("inv-1")))
    assert b'"outcome":"incomplete"' in plugin.transcript_bytes("inv-1")


def test_recovered_model_error_does_not_make_the_run_error() -> None:
    root = SimpleNamespace(name="root")
    plugin = GoogleAdkTracePlugin()
    ctx = context("inv-1", agent=root)
    run(plugin.before_run_callback(invocation_context=ctx))
    run(
        plugin.on_model_error_callback(
            callback_context=ctx,
            llm_request=SimpleNamespace(model="test-model"),
            error=RuntimeError(SECRET),
        )
    )
    run(plugin.after_agent_callback(agent=root, callback_context=ctx))
    run(plugin.after_run_callback(invocation_context=ctx))
    assert b'"outcome":"ok"' in plugin.transcript_bytes("inv-1")


def test_unhandled_runner_error_marks_the_run_error() -> None:
    plugin = observed_plugin()
    run(
        plugin.on_run_error_callback(
            invocation_context=context("inv-1"),
            error=RuntimeError(SECRET),
        )
    )
    assert b'"outcome":"error"' in plugin.transcript_bytes("inv-1")


def test_completion_without_start_is_not_dropped() -> None:
    plugin = observed_plugin()
    run(
        plugin.after_tool_callback(
            tool=SimpleNamespace(name="late_tool"),
            tool_args={},
            tool_context=context("inv-1", "call-9"),
            result={},
        )
    )

    call = plugin.tool_calls("inv-1")[0]
    assert (call.name, call.outcome, call.observed_start) == ("late_tool", "ok", False)


def test_missing_tool_name_is_retained_as_unavailable() -> None:
    plugin = observed_plugin()
    ctx = context("inv-1", "call-1")
    tool = SimpleNamespace(name="")
    run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=ctx))
    run(
        plugin.after_tool_callback(tool=tool, tool_args={}, tool_context=ctx, result={})
    )
    assert plugin.tool_calls("inv-1")[0].name is None
    assert b'"tool":null' in plugin.transcript_bytes("inv-1")


def test_model_payload_and_unknown_fields_are_ignored() -> None:
    plugin = observed_plugin()
    tool = SimpleNamespace(name="lookup", future_secret=SECRET)
    ctx = context("inv-1", "call-1")
    run(
        plugin.before_tool_callback(
            tool=tool, tool_args={"secret": SECRET}, tool_context=ctx
        )
    )

    record = plugin.build_record("inv-1", **kwargs())
    assert SECRET not in str(record)
    assert SECRET.encode() not in plugin.transcript_bytes("inv-1")


def test_transcript_is_deterministic_and_order_sensitive() -> None:
    first = observed_plugin()
    second = observed_plugin()
    for plugin, names in ((first, ["a", "b"]), (second, ["b", "a"])):
        for index, name in enumerate(names):
            ctx = context("inv-1", f"call-{index}")
            tool = SimpleNamespace(name=name)
            run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=ctx))
            run(
                plugin.after_tool_callback(
                    tool=tool, tool_args={}, tool_context=ctx, result={}
                )
            )

    assert first.transcript_bytes("inv-1") == first.transcript_bytes("inv-1")
    assert first.transcript_bytes("inv-1") != second.transcript_bytes("inv-1")


def test_concurrent_invocation_state_does_not_cross_contaminate() -> None:
    async def exercise() -> GoogleAdkTracePlugin:
        plugin = GoogleAdkTracePlugin()

        async def one(invocation_id: str, tool_name: str) -> None:
            ctx = context(invocation_id, "call-1")
            tool = SimpleNamespace(name=tool_name)
            await plugin.before_run_callback(invocation_context=ctx)
            await plugin.before_model_callback(
                callback_context=ctx,
                llm_request=SimpleNamespace(model=f"model-{invocation_id}"),
            )
            await plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=ctx)
            await asyncio.sleep(0)
            await plugin.after_tool_callback(
                tool=tool,
                tool_args={},
                tool_context=ctx,
                result={},
            )
            await plugin.after_run_callback(invocation_context=ctx)

        await asyncio.gather(one("inv-a", "alpha"), one("inv-b", "beta"))
        return plugin

    plugin = asyncio.run(exercise())
    assert [call.name for call in plugin.tool_calls("inv-a")] == ["alpha"]
    assert [call.name for call in plugin.tool_calls("inv-b")] == ["beta"]


def test_multiple_observed_models_require_an_explicit_choice() -> None:
    plugin = observed_plugin()
    run(
        plugin.before_model_callback(
            callback_context=context("inv-1"),
            llm_request=SimpleNamespace(model="second-model"),
        )
    )

    with pytest.raises(MissingEvidence, match="multiple model ids"):
        plugin.build_record("inv-1", **kwargs())
    with pytest.raises(MissingEvidence, match="multiple model ids"):
        plugin.build_record("inv-1", **kwargs(model_id="router-selection"))


def test_observed_model_id_cannot_be_relabelled() -> None:
    plugin = observed_plugin()
    with pytest.raises(MissingEvidence, match="conflicts with observed model"):
        plugin.build_record("inv-1", **kwargs(model_id="different-model"))


def test_provider_is_never_guessed_from_the_model_name() -> None:
    plugin = observed_plugin()
    with pytest.raises(MissingEvidence, match="model_provider and model_id"):
        plugin.build_record("inv-1", **kwargs(model_provider=None))


def test_record_validates_after_signing() -> None:
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    sign = pytest.importorskip("agentrust_trace.sign")
    plugin = observed_plugin()
    record = sign.sign_record(
        plugin.build_record("inv-1", **kwargs()), sign.generate_key()
    )

    parsed = TrustRecord.model_validate(record)
    assert parsed.runtime.platform == "software-only"
    assert parsed.appraisal.status == "none"
    assert "origin" not in record
    assert "transparency" not in record
    assert "tool_transcript" not in record


def test_discard_removes_retained_invocation() -> None:
    plugin = observed_plugin()
    assert plugin.discard("inv-1") is True
    assert plugin.discard("inv-1") is False
    with pytest.raises(MissingEvidence, match="no evidence retained"):
        plugin.transcript_bytes("inv-1")


@pytest.mark.parametrize("subject", ["agent", "spiffe://missing-path"])
def test_invalid_subject_is_refused(subject: str) -> None:
    with pytest.raises(MissingEvidence, match="may not invent identity"):
        build_record(
            **kwargs(subject=subject, model_id="test-model"),
            transcript=b"{}",
            tool_count=0,
        )


def test_empty_policy_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="policy bytes"):
        build_record(
            **kwargs(policy_bundle=b"", model_id="test-model"),
            transcript=b"{}",
            tool_count=0,
        )


def test_invalid_workload_digest_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="artifact digest"):
        build_record(
            **kwargs(workload_digest="sha256:placeholder", model_id="test-model"),
            transcript=b"{}",
            tool_count=0,
        )


def test_invalid_enforcement_mode_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="enforcement_mode"):
        build_record(
            **kwargs(enforcement_mode="monitor", model_id="test-model"),
            transcript=b"{}",
            tool_count=0,
        )


def test_software_only_attestation_is_refused() -> None:
    with pytest.raises(MissingEvidence, match="omit attestation"):
        build_record(
            **kwargs(model_id="test-model"),
            transcript=b"{}",
            tool_count=0,
            attestation={"platform": "software-only", "measurement": DIGEST},
        )


def test_attestation_measurement_must_be_a_digest() -> None:
    with pytest.raises(MissingEvidence, match="measured digest"):
        build_record(
            **kwargs(model_id="test-model"),
            transcript=b"{}",
            tool_count=0,
            attestation={"platform": "intel-tdx", "measurement": "unknown"},
        )


def test_attestation_lifts_the_same_record_to_hardware() -> None:
    record = build_record(
        **kwargs(model_id="test-model"),
        transcript=b"{}",
        tool_count=0,
        attestation={"platform": "intel-tdx", "measurement": DIGEST},
    )
    assert record["runtime"] == {"platform": "intel-tdx", "measurement": DIGEST}
