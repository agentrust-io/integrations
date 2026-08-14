from __future__ import annotations

import json

import pytest

from agentrust_trace_adapters import (
    MissingEvidence,
    OpenShellEvidence,
    build_openshell_record,
    build_policy_bundle,
    build_transcript,
)

JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}
WORKLOAD = "sha256:" + "a" * 64


def event(*, action: str = "Allowed", time: int = 1_775_014_138_811) -> dict:
    return {
        "class_uid": 4001,
        "time": time,
        "action": action,
        "metadata": {
            "product": {
                "name": "OpenShell Sandbox Supervisor",
                "vendor_name": "OpenShell",
                "version": "0.0.105",
            },
            "version": "1.7.0",
            "uid": "sbx-123",
        },
    }


def jsonl(*events: dict) -> bytes:
    return b"".join(json.dumps(item).encode() + b"\n" for item in events)


def evidence(**overrides) -> OpenShellEvidence:
    values = {
        "sandbox_id": "sbx-123",
        "policy_revision": "42",
        "openshell_policy": b"version: 1\nnetwork_policies: {}\n",
        "acs_manifest": b"agent_control_specification_version: 0.3.0-alpha-agt\n",
        "ocsf_jsonl": jsonl(event(), event(action="Denied", time=1_775_014_138_812)),
        "acs_decisions": ({"decision": "allow", "tool": "shell.execute"},),
        "capture_start": 1_775_014_138_000,
        "capture_end": 1_775_014_139_000,
        "capture_complete": True,
        "openshell_version": "0.0.105",
    }
    values.update(overrides)
    return OpenShellEvidence(**values)


def build(ev: OpenShellEvidence | None = None) -> dict:
    return build_openshell_record(
        ev or evidence(),
        subject="spiffe://example.org/agent/codex",
        model_provider="openai",
        model_id="gpt-5",
        data_class="internal",
        workload_digest=WORKLOAD,
        jwk=JWK,
        iat=1_775_014_139,
    )


def test_builds_honest_software_only_record() -> None:
    record = build()
    assert record["origin"] == {
        "kind": "third-party-control-plane",
        "producer": "nvidia-openshell/0.0.105",
        "source_event_id": "sbx-123",
    }
    assert record["runtime"]["platform"] == "software-only"
    assert record["appraisal"]["status"] == "none"
    assert record["policy"]["enforcement_mode"] == "enforce"
    assert record["tool_transcript"]["call_count"] == 1
    assert "transparency" not in record


def test_output_validates_with_released_trace_model() -> None:
    models = pytest.importorskip("agentrust_trace.models")
    parsed = models.TrustRecord.model_validate(build())
    assert parsed.origin.kind == "third-party-control-plane"


def test_policy_bundle_is_deterministic_and_binds_revision_and_both_layers() -> None:
    first, mode = build_policy_bundle(
        openshell_policy=b"version: 1\n",
        policy_revision="7",
        acs_manifest=b"acs: 1\n",
    )
    second, _ = build_policy_bundle(
        openshell_policy=b"version: 1\n",
        policy_revision="8",
        acs_manifest=b"acs: 1\n",
    )
    assert mode == "enforce"
    assert first != second
    decoded = json.loads(first)
    assert decoded["format"] == "agentrust.openshell-policy-bundle.v1"
    assert decoded["openshell"]["revision"] == "7"


@pytest.mark.parametrize(
    ("openshell_mode", "acs_mode", "expected"),
    [
        ("enforce", "enforce", "enforce"),
        ("advisory", "enforce", "advisory"),
        ("enforce", "advisory", "advisory"),
        ("silent", "enforce", "silent"),
    ],
)
def test_combines_enforcement_modes(openshell_mode: str, acs_mode: str, expected: str) -> None:
    _, mode = build_policy_bundle(
        openshell_policy=b"p", policy_revision="1", acs_manifest=b"a",
        openshell_mode=openshell_mode, acs_mode=acs_mode,
    )
    assert mode == expected


@pytest.mark.parametrize("field", ["openshell_policy", "acs_manifest"])
def test_policy_bundle_rejects_missing_layer(field: str) -> None:
    kwargs = {"openshell_policy": b"p", "policy_revision": "1", "acs_manifest": b"a"}
    kwargs[field] = b""
    with pytest.raises(MissingEvidence):
        build_policy_bundle(**kwargs)


def test_incomplete_capture_is_rejected() -> None:
    with pytest.raises(MissingEvidence, match="incomplete"):
        build(evidence(capture_complete=False))


def test_accepts_released_openshell_0_0_105_event_contract() -> None:
    record = build()
    assert record["origin"]["producer"] == "nvidia-openshell/0.0.105"


@pytest.mark.parametrize(
    "product",
    [
        {
            "name": "OpenShell Sandbox Supervisor",
            "vendor_name": "NVIDIA",
            "version": "0.0.105",
        },
        {
            "name": "OpenShell Sandbox Supervisor",
            "vendor_name": "OpenShell",
            "version": "0.0.104",
        },
        {
            "name": "Not OpenShell",
            "vendor_name": "OpenShell",
            "version": "0.0.105",
        },
    ],
)
def test_rejects_wrong_product_identity_or_version(product: dict) -> None:
    bad_event = event()
    bad_event["metadata"]["product"] = product
    with pytest.raises(ValueError):
        build(evidence(ocsf_jsonl=jsonl(bad_event)))


def test_rejects_event_from_a_different_sandbox() -> None:
    bad_event = event()
    bad_event["metadata"]["uid"] = "sbx-other"
    with pytest.raises(ValueError, match="sandbox uid"):
        build(evidence(ocsf_jsonl=jsonl(bad_event)))


@pytest.mark.parametrize(
    "bad",
    [
        b"not-json\n",
        b"[]\n",
        jsonl({"class_uid": 4001}),
        jsonl({**event(), "metadata": {}}),
        jsonl({**event(), "metadata": []}),
        jsonl({**event(), "metadata": {"product": []}}),
    ],
)
def test_malformed_or_non_openshell_ocsf_is_rejected(bad: bytes) -> None:
    with pytest.raises((ValueError, MissingEvidence)):
        build(evidence(ocsf_jsonl=bad))


def test_event_order_changes_transcript_commitment() -> None:
    allowed = event(action="Allowed", time=1)
    denied = event(action="Denied", time=2)
    common = {
        "sandbox_id": "sbx-123",
        "policy_bundle_hash": "sha256:" + "b" * 64,
        "acs_decisions": (),
        "capture_start": 0,
        "capture_end": 3,
        "capture_complete": True,
        "openshell_version": "0.0.105",
    }
    forward, _ = build_transcript(ocsf_jsonl=jsonl(allowed, denied), **common)
    reverse, _ = build_transcript(ocsf_jsonl=jsonl(denied, allowed), **common)
    assert forward != reverse


def test_policy_change_changes_record_hashes() -> None:
    before = build(evidence(policy_revision="1"))
    after = build(evidence(policy_revision="2"))
    assert before["policy"]["bundle_hash"] != after["policy"]["bundle_hash"]
    assert before["tool_transcript"]["hash"] != after["tool_transcript"]["hash"]
