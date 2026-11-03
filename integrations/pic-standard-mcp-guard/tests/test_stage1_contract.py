"""Maintained 22-check successor to the C1 stage-1 verifier.

Nineteen check names are carried over verbatim from the C1 verifier; three are honestly
renamed because their original infrastructure does not exist in the maintained
integration: 1e (the signed artifact records no package versions -> installed versions
satisfy the declared pyproject requirements), 2a (no trace-spec git checkout -> the
released bridge's exact profile and required fields), and 5c (there is no resolver
resolution -> the supplied in-memory bridge matches the signed reference). Most checks are
re-derived from the coordinator's in-memory artifacts for one allow run and one blocked
run; 1a captures PIC's own audit log around both runs, and 4 runs the real
`trace-tests verify --level 0` CLI once against a temporary record.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
import os
import pathlib
import subprocess
import sys
import tomllib
from importlib.metadata import version
from types import SimpleNamespace

import pytest
import rfc8785
from agentrust_trace.intent_bridge import IntentBridgeError, digest_jcs, sign_bridge, verify_bridge
from agentrust_trace.validate import validate_json
from agentrust_trace_adapters import software_measurement
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from pic_standard.canonical import intent_digest_hex, sha256_hex
from pic_trace_verify import AdapterVerifyError, sha256_prefixed, verify_adapter_artifacts

from conftest import (
    ARTIFACT_STORE,
    BRIDGE_KEY,
    BRIDGE_KEY_ID,
    EVIDENCE_KEY,
    HARNESS,
    IMPACT,
    INTENT,
    MARKER,
    POLICY_BYTES,
    RECORD_KEY,
    TOOL,
    raw_public,
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_REQUIRED_AUTHZ_FIELDS = (
    "authorization_id", "decision", "authorizer", "authorizer_key_id", "authorized_at",
    "expires_at", "scope", "pic", "declaration_digest", "tool_call_digest", "transcript_required",
)


def _did_public_bytes(did: str) -> bytes:
    prefix = "did:key:z"
    assert did.startswith(prefix)
    n = 0
    for ch in did[len(prefix):]:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    assert body[:2] == b"\xed\x01"
    return body[2:]


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _one_json_object(raw: bytes) -> dict:
    text = raw.decode("utf-8")
    assert "\n" not in text and "\r" not in text, "raw decision contains a line break"

    def refuse_dupes(pairs):
        keys = [k for k, _ in pairs]
        assert len(keys) == len(set(keys)), "duplicate member names"
        return dict(pairs)

    value, end = json.JSONDecoder(object_pairs_hook=refuse_dupes).raw_decode(text)
    assert end == len(text), "bytes follow the first JSON value"
    assert isinstance(value, dict)
    return value


@pytest.fixture
def stage1(coordinator, runner):
    allow_outcome, allow_info = runner(coordinator, rid="stage1-allow")
    block_outcome, block_info = runner(coordinator, rid="stage1-block", tamper=True)
    assert allow_outcome.status == "record-emitted", allow_outcome.absence
    ra = allow_outcome.record_artifacts
    return SimpleNamespace(
        allow_outcome=allow_outcome, allow_info=allow_info,
        block_outcome=block_outcome, block_info=block_info,
        record=ra.record, bridge=ra.authorization.bridge, transcript=ra.transcript,
        authz=ra.authorization, raw=ra.authorization.pic_decision_raw, tool_call=ra.authorization.tool_call,
    )


# --- 1. PIC behaviour and raw decisions ------------------------------------

def test_1a_pic_raw_decisions_one_event_each(coordinator, runner, caplog):
    with caplog.at_level(logging.INFO, logger="pic_standard.mcp"):
        allow_outcome, _ = runner(coordinator, rid="1a-allow")
        block_outcome, _ = runner(coordinator, rid="1a-block", tamper=True)

    events = []
    for rec in caplog.records:
        if rec.name != "pic_standard.mcp":
            continue
        try:
            obj = json.loads(rec.getMessage())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("event") == "pic_mcp_decision":
            events.append((rec.getMessage(), obj))

    assert len(events) == 2, [o for _, o in events]
    assert sorted(obj["decision"] for _, obj in events) == ["allow", "block"]
    for msg, obj in events:
        parsed = _one_json_object(msg.encode("utf-8"))  # duplicate-free, single object, no newline
        assert parsed["event"] == "pic_mcp_decision"

    allow_msg = next(msg for msg, obj in events if obj["decision"] == "allow")
    assert allow_msg.encode("utf-8") == allow_outcome.record_artifacts.authorization.pic_decision_raw
    block_obj = next(obj for _, obj in events if obj["decision"] == "block")
    assert block_obj.get("reason_code") == "PIC_EVIDENCE_FAILED"
    assert block_outcome.absence["error_code"] == "PIC_EVIDENCE_FAILED"


def test_1b_pic_allow_behaviour(stage1):
    assert stage1.allow_outcome.envelope == {"isError": False, "result": {"deleted": True}}
    assert stage1.allow_info["count"] == 1
    assert not (stage1.allow_info["sandbox"] / MARKER).exists()


def test_1c_pic_block_behaviour(stage1):
    out = stage1.block_outcome
    assert out.status == "pic-blocked" and out.pic_decision == "blocked"
    assert isinstance(out.envelope, dict) and out.envelope.get("isError") is True
    assert out.absence["error_code"] == "PIC_EVIDENCE_FAILED"
    assert out.record_artifacts is None and out.authorization is None
    assert stage1.block_info["count"] == 0


def test_1d_raw_decision_digest_bindings(stage1):
    expected = "urn:sha256:" + hashlib.sha256(stage1.raw).hexdigest()
    assert stage1.bridge["authorization"]["authorization_id"] == expected
    assert stage1.record["origin"]["source_event_id"] == expected
    assert stage1.record["references"][0]["id"] == expected


def test_1e_installed_versions_meet_declared_floors():
    pyproject = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    specs = list(data["project"].get("dependencies", []))
    for extra in data["project"].get("optional-dependencies", {}).values():
        specs.extend(extra)
    requirements = {}
    for spec in specs:
        req = Requirement(spec)
        if req.marker is None or req.marker.evaluate():
            requirements[canonicalize_name(req.name)] = req
    expected = {
        "pic-standard",
        "agentrust-trace",
        "agentrust-trace-adapters",
        "agentrust-trace-tests",
    }
    assert expected <= requirements.keys()
    for package in expected:
        req = requirements[package]
        assert req.specifier, f"{package} has no declared version floor"
        installed = version(req.name)
        assert req.specifier.contains(installed, prereleases=True), \
            f"{req.name} {installed} does not satisfy {req.specifier}"


# --- 2. Bridge -------------------------------------------------------------

def test_2a_bridge_profile_and_required_fields(stage1):
    bridge = stage1.bridge
    assert bridge["profile"] == "tag:agentrust-io.com,2026:pic-trace-bridge-v1"
    assert "signature" in bridge
    authz = bridge["authorization"]
    for field in _REQUIRED_AUTHZ_FIELDS:
        assert field in authz, f"missing authorization field {field}"
    for field in ("profile", "intent_digest", "args_digest"):
        assert field in authz["pic"]
    assert authz["transcript_required"] is False
    assert "successor_observation_digest" not in authz


def test_2b_verify_bridge(stage1):
    a = stage1.authz
    verify_bridge(
        stage1.bridge, a.authorizer_jwk, declaration=a.declaration,
        pic_intent_digest="sha256:" + a.pic_intent_digest, pic_args_digest="sha256:" + a.pic_args_digest,
        tool_call=a.tool_call, now=stage1.bridge["authorization"]["authorized_at"],
    )


def test_2c_bridge_fields(stage1):
    a = stage1.bridge["authorization"]
    assert a["decision"] == "allow"
    assert a["authorizer"] == HARNESS
    assert a["authorizer_key_id"] == BRIDGE_KEY_ID == stage1.authz.authorizer_jwk["kid"]
    assert a["scope"] == {"tools": [TOOL], "impacts": [IMPACT]}
    assert a["transcript_required"] is False
    assert a["pic"]["profile"] == "PIC-CJSON/1.0"
    assert a["declaration_digest"] == digest_jcs(stage1.authz.declaration)
    assert a["tool_call_digest"] == digest_jcs(stage1.tool_call)
    assert a["pic"]["intent_digest"] == "sha256:" + intent_digest_hex(INTENT)
    assert a["pic"]["args_digest"] == "sha256:" + sha256_hex(stage1.tool_call["arguments"])


# --- 3-4. Trust Record: schema, fixed values, real CLI ---------------------

def test_3a_record_schema_validation(stage1):
    validate_json(stage1.record)


def test_3b_record_fixed_values(stage1):
    r = stage1.record
    assert r["origin"]["kind"] == "third-party-control-plane"
    assert r["origin"]["producer"] == HARNESS
    assert r["runtime"]["platform"] == "software-only"
    assert r["appraisal"]["status"] == "none"
    assert r["policy"]["enforcement_mode"] == "enforce"
    assert r["model"] == {"provider": "pic-standard-test", "model_id": "deterministic-tool-calling-model-v1"}
    assert r["data_class"] == "public"
    assert r["tool_transcript"]["call_count"] == 1
    assert r["build_provenance"] == {"slsa_level": 0, "digest": "sha256:" + hashlib.sha256(b"pic-trace-test").hexdigest()}


def test_4_trace_tests_level0(stage1, tmp_path):
    record_path = tmp_path / "stage1-record.json"
    record_path.write_text(json.dumps(stage1.record, ensure_ascii=False), encoding="utf-8")
    exe = pathlib.Path(sys.executable).with_name("trace-tests.exe" if os.name == "nt" else "trace-tests")
    proc = subprocess.run(
        [str(exe), "verify", "--record", str(record_path), "--level", "0"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --- 5. Harness-side recomputation -----------------------------------------

def test_5a_transcript_hash_recomputed(stage1):
    assert stage1.record["tool_transcript"]["hash"] == sha256_prefixed(rfc8785.dumps(stage1.transcript))


def test_5b_measurement_recomputed(stage1):
    bundle_hash = stage1.record["policy"]["bundle_hash"]
    assert bundle_hash == sha256_prefixed(POLICY_BYTES)
    expected = software_measurement(HARNESS, stage1.record["subject"], bundle_hash)
    assert stage1.record["runtime"]["measurement"] == expected


def test_5c_reference_matches_supplied_bridge_and_digest(stage1):
    refs = stage1.record["references"]
    assert len(refs) == 1
    ref = refs[0]
    assert ref["rel"] == "authorized-intent"
    assert ref["resolver"] == ARTIFACT_STORE
    assert ref["id"] == stage1.bridge["authorization"]["authorization_id"]
    assert ref["digest"] == digest_jcs(stage1.bridge)


def test_5d_subject_did_key_binding(stage1):
    assert _did_public_bytes(stage1.record["subject"]) == _b64url(stage1.record["cnf"]["jwk"]["x"])


def test_5e_three_keys_distinct():
    assert len({raw_public(EVIDENCE_KEY), raw_public(BRIDGE_KEY), raw_public(RECORD_KEY)}) == 3


def test_5f_model_output_consistency(stage1):
    assert stage1.allow_info["received"] == [{"path": MARKER}]
    assert stage1.tool_call == {"name": TOOL, "arguments": {"path": MARKER}}
    assert stage1.bridge["authorization"]["tool_call_digest"] == sha256_prefixed(rfc8785.dumps(stage1.tool_call))
    assert stage1.transcript["tool_call"] == stage1.tool_call


def test_5g_bridge_before_tool_lifecycle(stage1):
    assert stage1.allow_info["bridge_state_at_entry"] == "bridged"
    assert stage1.block_info["bridge_state_at_entry"] is None  # tool never dispatched on block


# --- 6. Negative checks ----------------------------------------------------

def test_6a_neg_altered_observation(stage1):
    altered = copy.deepcopy(stage1.transcript)
    altered["observation"]["observation"]["marker_exists_after"] = True
    assert sha256_prefixed(rfc8785.dumps(altered)) != stage1.record["tool_transcript"]["hash"]
    a = stage1.authz
    with pytest.raises(AdapterVerifyError):
        verify_adapter_artifacts(
            record=stage1.record, bridge=a.bridge, pic_decision_raw=a.pic_decision_raw,
            declaration=a.declaration, pic_intent_digest=a.pic_intent_digest,
            pic_args_digest=a.pic_args_digest, tool_call=a.tool_call,
            authorizer_jwk=a.authorizer_jwk, transcript=altered,
        )


def test_6b_neg_bare_hex_digest_refused(stage1):
    # Construct and SIGN a bridge carrying bare hex where TRACE requires sha256:<hex>,
    # then prove verification rejects it (the real boundary, not an API input guard).
    authz = copy.deepcopy(stage1.bridge["authorization"])
    authz["pic"]["intent_digest"] = stage1.authz.pic_intent_digest  # bare hex, no sha256: prefix
    malformed = sign_bridge(authz, BRIDGE_KEY)
    with pytest.raises(IntentBridgeError):
        verify_bridge(
            malformed, stage1.authz.authorizer_jwk, declaration=stage1.authz.declaration,
            pic_intent_digest="sha256:" + stage1.authz.pic_intent_digest,
            pic_args_digest="sha256:" + stage1.authz.pic_args_digest,
            tool_call=stage1.tool_call, now=authz["authorized_at"],
        )


def test_6c_neg_block_has_no_bridge_or_record(stage1):
    out = stage1.block_outcome
    assert out.record_artifacts is None
    assert out.authorization is None
    assert out.absence["reason"] == "pic_blocked"
    assert stage1.block_info["count"] == 0


def test_6d_neg_policy_byte_change(stage1):
    changed = POLICY_BYTES.replace(b"irreversible", b"irreversiblE", 1)
    assert changed != POLICY_BYTES
    changed_hash = sha256_prefixed(changed)
    assert changed_hash != stage1.record["policy"]["bundle_hash"]
    changed_measurement = software_measurement(HARNESS, stage1.record["subject"], changed_hash)
    assert changed_measurement != stage1.record["runtime"]["measurement"]
