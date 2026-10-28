"""Shared fixtures for the PIC Standard MCP Guard adapter tests. TEST keys only."""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import logging
import pathlib
import sys
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pic_standard.canonical import canonicalize, intent_digest_hex, sha256_hex  # noqa: E402

import pic_trace_guard as g  # noqa: E402

TOOL = "delete_demo_marker"
IMPACT = "irreversible"
MARKER = "marker.txt"
HARNESS = "urn:pic-standard:integration:pic-trace-test-harness"
ARTIFACT_STORE = "urn:pic-standard:integration:pic-trace-test-artifact-store"
OBSERVER = "pic-trace-test-observer"
EVIDENCE_KEY_ID = "pic-trace-test-evidence-key-1"
BRIDGE_KEY_ID = "pic-trace-test-bridge-key-1"
PROVENANCE_ID = "pic-trace-approval"
INTENT = "Delete the demo marker file in the test sandbox"

DECLARATION = {"profile": "pic-standard-action-declaration/v1", "tool": TOOL, "impact": IMPACT}
POLICY = {
    "impact_by_tool": {TOOL: IMPACT},
    "require_pic_for_impacts": [IMPACT],
    "require_evidence_for_impacts": [IMPACT],
}
POLICY_BYTES = (json.dumps(POLICY, indent=2) + "\n").encode("utf-8")

_sandbox_counter = itertools.count()


def _test_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"pic-trace-test/{label}".encode()).digest())


EVIDENCE_KEY = _test_key("pic-evidence-key")
BRIDGE_KEY = _test_key("bridge-key")
RECORD_KEY = _test_key("trace-record-key")


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_config(policy_bytes: bytes = POLICY_BYTES) -> g.PicTraceConfig:
    return g.PicTraceConfig(
        authorizer=HARNESS, authorizer_key_id=BRIDGE_KEY_ID,
        bridge_key=BRIDGE_KEY, record_key=RECORD_KEY,
        model_provider="pic-standard-test", model_id="deterministic-tool-calling-model-v1",
        data_class="public", policy_bundle=policy_bytes,
        workload_digest="sha256:" + hashlib.sha256(b"pic-trace-test").hexdigest(),
        declaration=DECLARATION, resolver=ARTIFACT_STORE,
    )


def build_proposal(*, tamper: bool = False) -> dict[str, Any]:
    """Proposal whose action.args is always {path: marker.txt}; `tamper` corrupts the
    evidence signature so PIC blocks."""
    args = {"path": MARKER}
    claims = [{"text": "The test approver authorized deleting marker.txt", "evidence": [PROVENANCE_ID]}]
    attestation = {
        "attestation_version": "PIC-ATT/1.0", "tool": TOOL, "impact": IMPACT,
        "provenance_ids": [PROVENANCE_ID], "args_digest": sha256_hex(args),
        "claims_digest": sha256_hex(claims), "intent_digest": intent_digest_hex(INTENT),
    }
    signature = base64.b64encode(EVIDENCE_KEY.sign(canonicalize(attestation))).decode()
    if tamper:
        c = signature[20]
        signature = signature[:20] + ("B" if c == "A" else "A") + signature[21:]
    return {
        "protocol": "PIC/1.0", "intent": INTENT, "impact": IMPACT,
        "provenance": [{"id": PROVENANCE_ID, "trust": "untrusted", "source": "pic-trace-test approver"}],
        "claims": claims, "action": {"tool": TOOL, "args": args},
        "evidence": [{
            "id": PROVENANCE_ID, "type": "sig", "ref": "inline:pic-att",
            "payload": json.dumps(attestation, sort_keys=True, separators=(",", ":")),
            "alg": "ed25519", "signature": signature, "key_id": EVIDENCE_KEY_ID,
            "signer": "pic-trace-test approver",
        }],
    }


@pytest.fixture
def fixtures_dir(tmp_path, monkeypatch):
    d = tmp_path / "fx"
    d.mkdir()
    (d / "pic_keys.json").write_text(
        json.dumps({"trusted_keys": {EVIDENCE_KEY_ID: base64.b64encode(raw_public(EVIDENCE_KEY)).decode()}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("PIC_KEYS_PATH", str(d / "pic_keys.json"))
    pic_log = logging.getLogger("pic_standard.mcp")
    prev_level = pic_log.level
    pic_log.setLevel(logging.CRITICAL)
    try:
        yield d
    finally:
        pic_log.setLevel(prev_level)


@pytest.fixture
def coordinator(fixtures_dir):
    return g.PicTraceCoordinator(make_config())  # default real-time clock (iat freshness window)


@pytest.fixture
def runner(tmp_path, fixtures_dir):
    """Run one guarded call in a unique sandbox.

    `tool_behavior(path, sb, info)` overrides what the tool does after instrumentation
    (e.g. raise, or return a non-JSON value); the default deletes the marker. The tool is
    always wrapped so `count`, `received`, and `bridge_state_at_entry` (the store state at
    tool entry, which proves bridge-before-dispatch) are recorded in every case.
    `observe_behavior(envelope, sb, info)` overrides the observation callback; the default
    establishes iff the marker was deleted exactly once. Returns (outcome, info).
    """

    def _run(coordinator, *, rid, tamper=False, live_path=MARKER, verdict="auto",
             tool_behavior=None, observe_behavior=None):
        sb = tmp_path / f"sb-{next(_sandbox_counter)}"
        sb.mkdir()
        (sb / MARKER).write_text("marker\n", encoding="utf-8")
        info: dict[str, Any] = {"count": 0, "received": [], "bridge_state_at_entry": None, "sandbox": sb}

        def instrumented_tool(path: str) -> Any:
            info["count"] += 1
            info["received"].append({"path": path})
            try:
                info["bridge_state_at_entry"] = coordinator._store.peek(rid).get("state")
            except Exception:  # noqa: BLE001 - instrumentation must never change behaviour
                pass
            if tool_behavior is not None:
                return tool_behavior(path, sb, info)
            target = (sb / path).resolve()
            if target.parent != sb.resolve():
                raise ValueError("path escapes the sandbox")
            target.unlink()
            return {"deleted": True}

        def observe(envelope: Any) -> g.Observation:
            if observe_behavior is not None:
                return observe_behavior(envelope, sb, info)
            doc = {"observation": {"tool_call_count": info["count"],
                                   "marker_exists_after": (sb / MARKER).exists()}, "observer": OBSERVER}
            if verdict == "auto":
                v = "established" if (info["count"] == 1 and not (sb / MARKER).exists()) else "contradicted"
            else:
                v = verdict
            return g.Observation(verdict=v, document=doc, response_projection=envelope)

        kwargs = {"path": live_path, "__pic": build_proposal(tamper=tamper), "__pic_request_id": rid}
        outcome = coordinator.run(
            tool_name=TOOL, tool_fn=instrumented_tool, kwargs=kwargs, observe=observe,
            verify_evidence=True, proposal_base_dir=fixtures_dir, strict_trust=True,
        )
        return outcome, info

    return _run
