"""Tests for the LangChain adapter.

Two things are worth pinning. The record must validate against the real model,
which is the check the first vendor adapter in this repo did not have. And
payloads must not reach the transcript, because a Trust Record is meant to be
handed to someone who should not thereby receive tool arguments.
"""

from __future__ import annotations

import pathlib
import sys
from uuid import uuid4

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from langchain_to_trace import (  # noqa: E402
    MissingEvidence,
    TraceCallbackHandler,
    build_record,
)

DIGEST = "sha256:" + "e" * 64
SUBJECT = "spiffe://example.org/agent/research-bot"


def _handler_with_two_tools():
    h = TraceCallbackHandler()
    h.on_chat_model_start(
        {"name": "ChatAnthropic", "id": ["langchain", "chat_models", "ChatAnthropic"]},
        [],
        invocation_params={"model": "claude-sonnet-4-6"},
    )
    r1, r2, parent = uuid4(), uuid4(), uuid4()
    h.on_tool_start({"name": "search"}, "query text", run_id=r1, parent_run_id=parent)
    h.on_tool_end("results", run_id=r1, parent_run_id=parent)
    h.on_tool_start({"name": "send_email"}, "to: x", run_id=r2, parent_run_id=parent)
    h.on_tool_error(RuntimeError("smtp down"), run_id=r2, parent_run_id=parent)
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


# --- observation -----------------------------------------------------------


def test_tool_calls_are_captured_with_outcomes() -> None:
    calls = _handler_with_two_tools().tool_calls
    assert [c.name for c in calls] == ["search", "send_email"]
    assert [c.outcome for c in calls] == ["ok", "error"]


def test_model_is_read_from_invocation_params() -> None:
    record = _handler_with_two_tools().build_record(**_kwargs())
    assert record["model"]["model_id"] == "claude-sonnet-4-6"
    assert record["model"]["provider"] == "anthropic"


def test_caller_can_override_a_guessed_provider() -> None:
    """The class-name mapping is best effort and must never win over a caller."""
    record = _handler_with_two_tools().build_record(
        **_kwargs(), model_provider="bedrock", model_id="claude-3-5-sonnet"
    )
    assert record["model"] == {"provider": "bedrock", "model_id": "claude-3-5-sonnet"}


def test_end_without_start_is_recorded_not_dropped() -> None:
    """A transcript that silently omits a call is worse than one that says so."""
    h = TraceCallbackHandler()
    rid = uuid4()
    h.on_tool_end("out", run_id=rid)
    assert h.tool_calls[0].name == "<unobserved-start>"


# --- payloads stay out -----------------------------------------------------


def test_tool_arguments_never_reach_the_transcript() -> None:
    h = TraceCallbackHandler()
    rid = uuid4()
    h.on_tool_start({"name": "pay"}, "iban=GB33BUKB20201555555555", run_id=rid)
    h.on_tool_end("sent to GB33BUKB20201555555555", run_id=rid)
    body = h.transcript_bytes().decode()
    assert "GB33BUKB" not in body
    assert "pay" in body


def test_error_messages_never_reach_the_transcript() -> None:
    h = TraceCallbackHandler()
    rid = uuid4()
    h.on_tool_start({"name": "pay"}, "x", run_id=rid)
    h.on_tool_error(RuntimeError("failed for account GB33BUKB20201555555555"), run_id=rid)
    assert "GB33BUKB" not in h.transcript_bytes().decode()


def test_transcript_is_order_sensitive() -> None:
    a = _handler_with_two_tools().transcript_bytes()
    h = TraceCallbackHandler()
    r1, r2 = uuid4(), uuid4()
    h.on_tool_start({"name": "send_email"}, "", run_id=r1)
    h.on_tool_end("", run_id=r1)
    h.on_tool_start({"name": "search"}, "", run_id=r2)
    h.on_tool_end("", run_id=r2)
    assert h.transcript_bytes() != a


# --- refusals --------------------------------------------------------------


def test_enforcement_mode_defaults_to_declared() -> None:
    """TRACE 0.9.0 added the value that is actually true of a framework run.

    Before it, the three modes all asserted that something evaluated the policy,
    so this adapter refused to default the field and made the caller pick a value
    that overstated their run.
    """
    kwargs = _kwargs()
    del kwargs["enforcement_mode"]
    record = _handler_with_two_tools().build_record(**kwargs)
    assert record["policy"]["enforcement_mode"] == "declared"


def test_unknown_enforcement_mode_is_still_refused() -> None:
    with pytest.raises(MissingEvidence, match="enforcement_mode must be one of"):
        _handler_with_two_tools().build_record(**_kwargs(enforcement_mode="monitor"))


def test_enforce_can_still_be_stated_explicitly() -> None:
    """For a deployment that did put a real enforcement layer in front."""
    record = _handler_with_two_tools().build_record(**_kwargs(enforcement_mode="enforce"))
    assert record["policy"]["enforcement_mode"] == "enforce"


def test_policy_bundle_bytes_are_required() -> None:
    with pytest.raises(MissingEvidence, match="digest of a bundle"):
        _handler_with_two_tools().build_record(**_kwargs(policy_bundle=b""))


def test_subject_must_be_spiffe_or_did() -> None:
    with pytest.raises(MissingEvidence, match="may invent"):
        _handler_with_two_tools().build_record(**_kwargs(subject="research-bot"))


def test_workload_digest_is_required_and_checked() -> None:
    with pytest.raises(MissingEvidence, match="nothing truthful to default"):
        _handler_with_two_tools().build_record(**_kwargs(workload_digest="sha256:placeholder"))


def test_unidentified_model_is_refused() -> None:
    h = TraceCallbackHandler()
    with pytest.raises(MissingEvidence, match="names no model"):
        h.build_record(**_kwargs())


def test_attestation_may_not_claim_software_only() -> None:
    """An attestation that attests nothing is a contradiction."""
    with pytest.raises(MissingEvidence, match="attests nothing"):
        _handler_with_two_tools().build_record(
            **_kwargs(), attestation={"platform": "software-only", "measurement": DIGEST}
        )


def test_attestation_measurement_must_be_a_digest() -> None:
    with pytest.raises(MissingEvidence, match="measurement"):
        _handler_with_two_tools().build_record(
            **_kwargs(), attestation={"platform": "tpm2", "measurement": "unknown"}
        )


# --- the record ------------------------------------------------------------


def test_record_validates_against_the_released_model() -> None:
    """Signed first, because `cnf` is populated by signing.

    Validating the unsigned dict would be validating a record that does not exist
    yet: a Trust Record without a confirmation key binds to nothing.
    """
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    sign = pytest.importorskip("agentrust_trace.sign")
    record = sign.sign_record(_handler_with_two_tools().build_record(**_kwargs()), sign.generate_key())
    parsed = TrustRecord.model_validate(record)
    assert parsed.runtime.platform == "software-only"
    assert parsed.tool_transcript is not None
    assert parsed.tool_transcript.call_count == 2


def test_first_party_records_carry_no_origin_block() -> None:
    """Absence means self, and self is the truth: this ran in the operator's process."""
    assert "origin" not in _handler_with_two_tools().build_record(**_kwargs())


def test_appraisal_is_none_because_building_is_not_appraising() -> None:
    assert _handler_with_two_tools().build_record(**_kwargs())["appraisal"]["status"] == "none"


def test_transparency_is_omitted_not_empty() -> None:
    assert "transparency" not in _handler_with_two_tools().build_record(**_kwargs())


def test_attestation_lifts_the_same_record_to_hardware() -> None:
    TrustRecord = pytest.importorskip("agentrust_trace.models").TrustRecord
    sign = pytest.importorskip("agentrust_trace.sign")
    record = sign.sign_record(
        _handler_with_two_tools().build_record(
            **_kwargs(), attestation={"platform": "tpm2", "measurement": DIGEST}
        ),
        sign.generate_key(),
    )
    parsed = TrustRecord.model_validate(record)
    assert parsed.runtime.platform == "tpm2"
    assert parsed.runtime.measurement == DIGEST


def test_no_tools_omits_the_transcript_block() -> None:
    """Absent is not the same as zero calls observed."""
    h = TraceCallbackHandler()
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
    assert record["policy"]["enforcement_mode"] == "advisory"
