"""Emit one signed TRACE Level 0 Trust Record from a PIC allow decision. TEST ONLY.

Runs one harmless tool (`delete_demo_marker`, operating only inside a fresh temporary
sandbox, declared `impact: irreversible`) through the released PIC MCP guard with
`strict_trust=True` and `verify_evidence=True`, builds and verifies the detached
authorization bridge in the `on_allow` hook, observes that the tool actually ran, signs
a Level 0 Trust Record, and self-verifies it (inside the coordinator) before writing it
as JSON. Then run `trace-tests verify --record <out> --level 0` separately as the
separate external CLI Level-0 check.

All keys are deterministic Ed25519 TEST keys derived from fixed labels; they
authenticate nothing outside this example and must never be used in production. The
record's model, data_class, and workload_digest are fixed TEST values, labeled as such.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pic_standard.canonical import canonicalize, intent_digest_hex, sha256_hex

from pic_trace_guard import Observation, PicTraceConfig, PicTraceCoordinator

TOOL = "delete_demo_marker"
IMPACT = "irreversible"
MARKER = "marker.txt"

HARNESS = "urn:pic-standard:integration:pic-trace-example-harness"
ARTIFACT_STORE = "urn:pic-standard:integration:pic-trace-example-artifact-store"
OBSERVER = "pic-trace-example-observer"

EVIDENCE_KEY_ID = "pic-trace-example-evidence-key-1"
BRIDGE_KEY_ID = "pic-trace-example-bridge-key-1"

MODEL_PROVIDER = "pic-standard-test"
MODEL_ID = "deterministic-tool-calling-model-v1"
DATA_CLASS = "public"

PROVENANCE_ID = "pic-trace-approval"
INTENT = "Delete the demo marker file in the example sandbox"
REQUEST_ID = "pic-trace-example-001"

DECLARATION = {"profile": "pic-standard-action-declaration/v1", "tool": TOOL, "impact": IMPACT}
POLICY = {
    "impact_by_tool": {TOOL: IMPACT},
    "require_pic_for_impacts": [IMPACT],
    "require_evidence_for_impacts": [IMPACT],
}


def _test_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"pic-trace-example/test-only/{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


EVIDENCE_KEY = _test_key("pic-evidence-key")
BRIDGE_KEY = _test_key("bridge-key")
RECORD_KEY = _test_key("trace-record-key")


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _scripted_model() -> dict[str, Any]:
    """A scripted test model whose sole output is the frozen tool call. No LLM inference."""
    return {"name": TOOL, "arguments": {"path": MARKER}}


def _pic_att_evidence() -> dict[str, Any]:
    """Canonical PIC-ATT/1.0 signature evidence bound to the exact call."""
    args = _scripted_model()["arguments"]
    claims = [{"text": "The example approver authorized deleting marker.txt in the sandbox",
               "evidence": [PROVENANCE_ID]}]
    attestation = {
        "attestation_version": "PIC-ATT/1.0",
        "tool": TOOL,
        "impact": IMPACT,
        "provenance_ids": [PROVENANCE_ID],
        "args_digest": sha256_hex(args),
        "claims_digest": sha256_hex(claims),
        "intent_digest": intent_digest_hex(INTENT),
    }
    signature = base64.b64encode(EVIDENCE_KEY.sign(canonicalize(attestation))).decode()
    return {
        "claims": claims,
        "evidence": {
            "id": PROVENANCE_ID, "type": "sig", "ref": "inline:pic-att",
            "payload": json.dumps(attestation, sort_keys=True, separators=(",", ":")),
            "alg": "ed25519", "signature": signature, "key_id": EVIDENCE_KEY_ID,
            "signer": "pic-trace-example test approver",
        },
    }


def _proposal() -> dict[str, Any]:
    model_call = _scripted_model()
    ev = _pic_att_evidence()
    return {
        "protocol": "PIC/1.0",
        "intent": INTENT,
        "impact": IMPACT,
        "provenance": [{"id": PROVENANCE_ID, "trust": "untrusted", "source": "pic-trace-example test approver"}],
        "claims": ev["claims"],
        "action": {"tool": model_call["name"], "args": model_call["arguments"]},
        "evidence": [ev["evidence"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a TEST TRACE Level 0 Trust Record from a PIC allow.")
    parser.add_argument("--out", type=Path, default=Path("trust-record.json"), help="output record path (JSON)")
    args = parser.parse_args()

    if len({_raw_public(EVIDENCE_KEY), _raw_public(BRIDGE_KEY), _raw_public(RECORD_KEY)}) != 3:
        raise RuntimeError("TEST signing keys must be pairwise distinct")

    logging.getLogger("pic_standard.mcp").setLevel(logging.CRITICAL)
    policy_bytes = (json.dumps(POLICY, indent=2) + "\n").encode("utf-8")

    prev_keys_path = os.environ.get("PIC_KEYS_PATH")
    fixtures = Path(tempfile.mkdtemp(prefix="pic-trace-example-fx-"))
    sandbox = Path(tempfile.mkdtemp(prefix="pic-trace-example-"))
    try:
        (fixtures / "pic_keys.json").write_text(
            json.dumps({"trusted_keys": {EVIDENCE_KEY_ID: base64.b64encode(_raw_public(EVIDENCE_KEY)).decode()}}),
            encoding="utf-8",
        )
        os.environ["PIC_KEYS_PATH"] = str(fixtures / "pic_keys.json")

        (sandbox / MARKER).write_text("pic-trace-example marker\n", encoding="utf-8")
        state = {"count": 0}

        def delete_demo_marker(path: str) -> dict[str, Any]:
            state["count"] += 1
            target = (sandbox / path).resolve()
            if target.parent != sandbox.resolve():
                raise ValueError("path escapes the example sandbox")
            target.unlink()
            return {"deleted": True}

        existed_before = (sandbox / MARKER).exists()

        def observe(envelope: Any) -> Observation:
            document = {
                "observation": {
                    "tool_call_count": state["count"],
                    "marker_existed_before": existed_before,
                    "marker_exists_after": (sandbox / MARKER).exists(),
                },
                "observer": OBSERVER,
                "observed_at": int(time.time()),
            }
            established = (
                state["count"] == 1
                and existed_before
                and not (sandbox / MARKER).exists()
                and envelope == {"isError": False, "result": {"deleted": True}}
            )
            return Observation(
                verdict="established" if established else "contradicted",
                document=document,
                response_projection=envelope,
            )

        config = PicTraceConfig(
            authorizer=HARNESS,
            authorizer_key_id=BRIDGE_KEY_ID,
            bridge_key=BRIDGE_KEY,
            record_key=RECORD_KEY,
            model_provider=MODEL_PROVIDER,
            model_id=MODEL_ID,
            data_class=DATA_CLASS,
            policy_bundle=policy_bytes,
            workload_digest="sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            declaration=DECLARATION,
            resolver=ARTIFACT_STORE,
        )
        coordinator = PicTraceCoordinator(config)  # default real-time clock (iat freshness window)

        kwargs = {**_scripted_model()["arguments"], "__pic": _proposal(), "__pic_request_id": REQUEST_ID}
        outcome = coordinator.run(
            tool_name=TOOL, tool_fn=delete_demo_marker, kwargs=kwargs, observe=observe,
            verify_evidence=True, proposal_base_dir=fixtures, strict_trust=True,
        )

        if outcome.status != "record-emitted" or outcome.record_artifacts is None:
            print(f"example did not emit a record: status={outcome.status} absence={outcome.absence}", file=sys.stderr)
            return 1

        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(outcome.record_artifacts.record, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.out} (status={outcome.status}, pic_decision={outcome.pic_decision})")
        print(f"next: trace-tests verify --record {args.out} --level 0")
        return 0
    finally:
        if prev_keys_path is None:
            os.environ.pop("PIC_KEYS_PATH", None)
        else:
            os.environ["PIC_KEYS_PATH"] = prev_keys_path
        shutil.rmtree(fixtures, ignore_errors=True)
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
