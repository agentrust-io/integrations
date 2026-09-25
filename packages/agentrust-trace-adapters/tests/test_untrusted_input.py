"""Regression tests for inputs an adapter receives from somebody else.

Each case was reproduced against the released code before its fix. The OCSF
cases share one property: the transcript the adapter commits to must be the
events a strict JSONL reader finds in the same bytes, as real JSON.
"""

from __future__ import annotations

import json

import pytest

from agentrust_trace_adapters import (
    MissingEvidence,
    PolicyEvidence,
    SourceSystem,
    build_record,
    build_transcript,
)

WORKLOAD = "sha256:" + "a" * 64
COMMON = {
    "sandbox_id": "sbx-123",
    "policy_bundle_hash": "sha256:" + "b" * 64,
    "acs_decisions": (),
    "capture_start": 0,
    "capture_end": 3,
    "capture_complete": True,
    "openshell_version": "0.0.105",
}
EVENT = (
    b'{"class_uid":4001,"time":1,"metadata":{"uid":"sbx-123","product":'
    b'{"vendor_name":"OpenShell","name":"OpenShell Sandbox Supervisor",'
    b'"version":"0.0.105"}}}'
)


def transcript(ocsf: bytes, **overrides) -> tuple[bytes, int]:
    return build_transcript(ocsf_jsonl=ocsf, **{**COMMON, **overrides})


def test_crlf_line_endings_are_still_accepted() -> None:
    body, _ = transcript(EVENT + b"\r\n" + EVENT + b"\r\n")
    assert len(json.loads(body)["ocsf_events"]) == 2


@pytest.mark.parametrize("separator", [b"\x0b", b"\x0c", b"\x1c", " ".encode()])
def test_non_newline_separator_does_not_split_one_line_into_two_events(
    separator: bytes,
) -> None:
    # str.splitlines() also splits on these, so one JSONL line that a strict
    # reader rejects was accepted as two events.
    with pytest.raises(ValueError, match="line 1"):
        transcript(EVENT + separator + EVENT + b"\n")


def test_line_separator_inside_a_json_string_is_one_event() -> None:
    event = EVENT[:-1] + '"note":"a b"}'.encode().join([b",", b""])
    body, _ = transcript(event + b"\n")
    assert json.loads(body)["ocsf_events"][0]["note"] == "a b"


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_finite_number_is_rejected_not_committed_as_invalid_json(
    constant: bytes,
) -> None:
    with pytest.raises(ValueError, match="line 1"):
        transcript(EVENT[:-1] + b',"x":' + constant + b"}\n")


def test_duplicate_key_is_rejected() -> None:
    # json.loads keeps the last duplicate; another reader may keep the first,
    # so the committed event would not be the one a consumer sees.
    with pytest.raises(ValueError, match="line 1"):
        transcript(EVENT[:-1] + b',"time":2}\n')


def test_deep_nesting_raises_value_error_not_recursion_error() -> None:
    with pytest.raises(ValueError, match="line 1"):
        transcript(b"[" * 100_000 + b"\n")


def test_non_utf8_input_raises_value_error() -> None:
    with pytest.raises(ValueError):
        transcript(EVENT[:-1] + b',"x":"\xff"}\n')


def test_non_finite_acs_decision_is_rejected() -> None:
    with pytest.raises(ValueError):
        transcript(EVENT + b"\n", acs_decisions=({"score": float("nan")},))


def _record(**overrides) -> dict:
    values = dict(
        source=SourceSystem(producer="vendor-gateway/2.1"),
        subject="spiffe://example.org/agent/imported",
        model_provider="anthropic",
        model_id="m",
        policy=PolicyEvidence(bundle=b"policy"),
        data_class="internal",
        jwk={"kty": "OKP"},
        workload_digest=WORKLOAD,
    )
    values.update(overrides)
    return build_record(**values)


@pytest.mark.parametrize(
    "field,value",
    [
        ("workload_digest", WORKLOAD + "\n"),
        ("model_weights_digest", WORKLOAD + "\n"),
        ("subject", "spiffe://example.org/agent/imported\n"),
        ("subject", "did:web:example.org\n"),
    ],
)
def test_trailing_newline_is_not_accepted_by_the_anchored_patterns(
    field: str, value: str
) -> None:
    # re.match with a "$" anchor accepts one trailing "\n", which then lands
    # in the record verbatim.
    with pytest.raises((ValueError, MissingEvidence)):
        _record(**{field: value})
