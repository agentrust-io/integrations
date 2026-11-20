"""Emit one signed TRACE Level 0 Trust Record from a CTA-gated MCP call. TEST ONLY.

In a fresh temporary sandbox this runs one harmless tool (`delete_demo_marker`,
declared `STATE_MUTATING` in the pinned policy bytes) twice in a session that has
ingested untrusted data:

1. Without a StepUpReceipt, and with a forged `TRUSTED_ONLY` taint claim. The gate
   refuses with `CTA_TAINTED_CONTROL_PLANE` before the tool is entered; the marker file
   is untouched and the tool ran zero times.
2. With a policy-engine StepUpReceipt bound to that exact call. The gate signs and
   verifies a `cta-trace-bridge-v1` bridge, the tool runs, an observer confirms the
   file is gone and the tool ran once, and a Level 0 Trust Record is signed.

The record is verified by `cta_trace_verify` (which uses only agentrust_trace,
rfc8785, and the standard library) from the artifacts and again from the JSON written
to disk, then written. Run `trace-tests verify --record <out> --level 0` separately
as the external Level 0 check.

All keys are deterministic Ed25519 TEST keys derived from fixed labels; they
authenticate nothing outside this example and must never be used in production. The
record's model, data_class, and workload_digest are fixed TEST values, labeled as such.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from agentrust_trace import key_to_jwk
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cta_trace_guard import CtaConfig, CtaGuard, Observation, sign_envelope
from cta_trace_verify import (
    BASIS_STEP_UP,
    RECEIPT_PROFILE,
    UNTRUSTED_INGESTED,
    digest_jcs,
    key_id,
    verify_adapter_artifacts,
)

TOOL = "delete_demo_marker"
MARKER = "marker.txt"

HARNESS = "urn:wimse-cta:integration:cta-trace-example-harness"
ARTIFACT_STORE = "urn:wimse-cta:integration:cta-trace-example-artifact-store"
APPROVER = "urn:wimse-cta:integration:cta-trace-example-policy-engine"
OBSERVER = "cta-trace-example-observer"

MODEL_PROVIDER = "wimse-cta-test"
MODEL_ID = "deterministic-tool-calling-model-v1"
DATA_CLASS = "public"

SESSION_ID = "cta-trace-example-session-1"
BLOCKED_REQUEST_ID = "cta-trace-example-request-001"
APPROVED_REQUEST_ID = "cta-trace-example-request-002"
RECEIPT_ID = "cta-trace-example-receipt-001"


def _test_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"cta-trace-example/test-only/{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


BRIDGE_KEY = _test_key("bridge-key")
RECORD_KEY = _test_key("trace-record-key")
POLICY_ENGINE_KEY = _test_key("policy-engine-key")


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _policy_bytes() -> bytes:
    policy = {
        "profile": "cta-gate-policy/v1",
        "step_up_key_id": key_id(_raw_public(POLICY_ENGINE_KEY)),
        "tools": {TOOL: {"effect_class": "STATE_MUTATING", "output_trust": "trusted"}},
    }
    return (json.dumps(policy, indent=2) + "\n").encode("utf-8")


def _fail(message: str) -> int:
    print(f"example failed: {message}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a TEST TRACE Level 0 Trust Record from a CTA gate.")
    parser.add_argument("--out", type=Path, default=Path("trust-record.json"), help="output record path (JSON)")
    args = parser.parse_args()

    if len({_raw_public(BRIDGE_KEY), _raw_public(RECORD_KEY), _raw_public(POLICY_ENGINE_KEY)}) != 3:
        raise RuntimeError("TEST signing keys must be pairwise distinct")

    policy_bytes = _policy_bytes()
    config = CtaConfig(
        authorizer=HARNESS,
        bridge_key=BRIDGE_KEY,
        record_key=RECORD_KEY,
        policy_engine_jwk=key_to_jwk(POLICY_ENGINE_KEY),
        policy_bundle=policy_bytes,
        model_provider=MODEL_PROVIDER,
        model_id=MODEL_ID,
        data_class=DATA_CLASS,
        workload_digest="sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        resolver=ARTIFACT_STORE,
    )
    guard = CtaGuard(config)  # default real-time clock

    sandbox = Path(tempfile.mkdtemp(prefix="cta-trace-example-"))
    try:
        (sandbox / MARKER).write_text("cta-trace-example marker\n", encoding="utf-8")
        state = {"count": 0}
        tool_args = {"path": MARKER}

        def delete_demo_marker(path: str) -> dict[str, Any]:
            state["count"] += 1
            target = (sandbox / path).resolve()
            if target.parent != sandbox.resolve():
                raise ValueError("path escapes the example sandbox")
            target.unlink()
            return {"deleted": True}

        def observe_for(request_id: str):
            existed_before = (sandbox / MARKER).exists()

            def observe(result: Any) -> Observation:
                document = {
                    "observation": {
                        "request_id": request_id,
                        "tool_name": TOOL,
                        "args_digest": digest_jcs(tool_args),
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
                    and result == {"deleted": True}
                )
                return Observation(
                    verdict="established" if established else "contradicted",
                    document=document,
                    response_projection=result,
                )

            return observe

        # The host reports that the model ingested untrusted data (for example, an email body).
        if guard.ingest_untrusted(SESSION_ID) != UNTRUSTED_INGESTED:
            return _fail("session was not marked UNTRUSTED_INGESTED")

        blocked = guard.run(
            session_id=SESSION_ID, request_id=BLOCKED_REQUEST_ID, tool_name=TOOL,
            tool_fn=delete_demo_marker, arguments=tool_args, observe=observe_for(BLOCKED_REQUEST_ID),
            claimed_taint="TRUSTED_ONLY",
        )
        marker_intact = (sandbox / MARKER).exists()
        print(
            f"blocked: status={blocked.status} code={blocked.code} reason={blocked.reason} "
            f"tool_entered={blocked.tool_entered} tool_calls={state['count']} marker_intact={marker_intact}"
        )
        if (
            blocked.status != "blocked" or blocked.code != "CTA_TAINTED_CONTROL_PLANE"
            or blocked.tool_entered or state["count"] != 0 or not marker_intact
            or not blocked.taint_claim_ignored
        ):
            return _fail("the tainted mutation was not refused before tool entry")

        now = int(time.time())
        receipt_body = {
            "receipt_id": RECEIPT_ID,
            "session_id": SESSION_ID,
            "request_id": APPROVED_REQUEST_ID,
            "tool_name": TOOL,
            "args_digest": digest_jcs(tool_args),
            "approver": APPROVER,
            "kid": key_id(_raw_public(POLICY_ENGINE_KEY)),
            "iat": now,
            "exp": now + 300,
        }
        receipt = sign_envelope(RECEIPT_PROFILE, "receipt", receipt_body, POLICY_ENGINE_KEY)

        allowed = guard.run(
            session_id=SESSION_ID, request_id=APPROVED_REQUEST_ID, tool_name=TOOL,
            tool_fn=delete_demo_marker, arguments=tool_args, observe=observe_for(APPROVED_REQUEST_ID),
            step_up_receipt=receipt,
        )
        if allowed.status != "record-emitted" or allowed.record_artifacts is None:
            return _fail(f"no record emitted: status={allowed.status} code={allowed.code} reason={allowed.reason}")
        print(f"allowed: status={allowed.status} events={' > '.join(allowed.events)}")

        artifacts = allowed.record_artifacts
        authz = artifacts.authorization
        if authz.bridge["authorization"]["decision_basis"] != BASIS_STEP_UP:
            return _fail("the allowed call did not rest on a step-up receipt")

        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(artifacts.record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written = json.loads(args.out.read_text(encoding="utf-8"))
        checked = verify_adapter_artifacts(
            record=written, bridge=authz.bridge, declaration=authz.declaration,
            tool_call=authz.tool_call, authorizer_jwk=authz.authorizer_jwk,
            record_jwk=guard.record_jwk, verification_time=int(time.time()),
            receipt=authz.step_up_receipt, policy_jwk=authz.policy_engine_jwk,
            policy_bundle=policy_bytes, transcript=artifacts.transcript,
        )
        print(f"verified from the written file: {', '.join(sorted(checked))}")
        print(
            f"wrote {args.out} (status={allowed.status}, taint={allowed.taint}, "
            f"basis={authz.bridge['authorization']['decision_basis']})"
        )
        print(f"next: trace-tests verify --record {args.out} --level 0")
        return 0
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
