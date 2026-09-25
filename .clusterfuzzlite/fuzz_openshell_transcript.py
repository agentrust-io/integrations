#!/usr/bin/python3
"""Fuzz the OpenShell OCSF JSONL parser behind build_transcript().

The OCSF export is evidence the adapter did not produce and cannot vouch for:
every byte of it comes from the sandbox being described. build_transcript()
parses it, checks each event's provenance fields, and commits the result by
digest as the record's tool transcript.

Properties:
  * Failure is ValueError (MissingEvidence is one). Anything else escaping means
    a caller written against the documented errors does not catch it.
  * Success produces strict JSON: no NaN or Infinity, no duplicate keys, and
    canonical re-serialization reproduces the committed bytes exactly.
  * The committed events are exactly the non-blank newline-terminated lines,
    one event per line, so a strict JSONL reader of the same bytes agrees.
"""
import json
import sys

import atheris

with atheris.instrument_imports():
    from agentrust_trace_adapters import build_transcript

_EVENT = (
    b'{"class_uid":4001,"time":1,"metadata":{"uid":"sbx","product":'
    b'{"vendor_name":"OpenShell","name":"OpenShell Sandbox Supervisor",'
    b'"version":"0.0.105"}}}'
)


def _strict(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AssertionError("duplicate key in committed transcript")
        value[key] = item
    return value


def _no_constant(name):
    raise AssertionError("non-finite number in committed transcript: " + name)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Half the time, splice fuzz into a valid event so the provenance checks
    # after parsing are reached, not only the JSON decoder.
    if fdp.ConsumeBool():
        body = fdp.ConsumeBytes(fdp.remaining_bytes())
    else:
        cut = fdp.ConsumeIntInRange(0, len(_EVENT))
        body = _EVENT[:cut] + fdp.ConsumeBytes(fdp.remaining_bytes()) + _EVENT[cut:]
    try:
        out, count = build_transcript(
            sandbox_id="sbx",
            policy_bundle_hash="sha256:" + "0" * 64,
            ocsf_jsonl=body,
            acs_decisions=(),
            capture_start=0,
            capture_end=1,
            capture_complete=True,
            openshell_version="0.0.105",
        )
    except ValueError:
        return
    parsed = json.loads(out, object_pairs_hook=_strict, parse_constant=_no_constant)
    again = json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    assert again == out, "transcript is not canonical"
    lines = [line for line in body.split(b"\n") if line.strip()]
    assert len(parsed["ocsf_events"]) == len(lines), "event count differs from JSONL lines"
    assert count == 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
