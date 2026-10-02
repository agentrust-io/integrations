#!/usr/bin/env python3
"""Run the industrial material-movement scenarios through a live cMCP Runtime."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
from typing import Any

import httpx

from cmcp_verify import ApprovedHashes, verify_audit_bundle, verify_trace_claim


EXAMPLE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_GATEWAY = "http://localhost:8443"
WORKFLOW_ID = "industrial-material-movement"


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _external_evidence_keys() -> dict[str, bytes]:
    key_doc = json.loads(
        (EXAMPLE_DIR / "controller-receipt-public-key.json").read_text()
    )
    key_id = key_doc["key_id"]
    return {key_id: _b64url_decode(key_doc["public_key_base64url"])}


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token := os.environ.get("CMCP_BEARER_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def call_tool(
    client: httpx.Client,
    gateway: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    *,
    workflow_id: str = WORKFLOW_ID,
) -> dict[str, Any]:
    response = client.post(
        f"{gateway}/mcp",
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
                "_cmcp": {"workflow_id": workflow_id},
            },
        },
        timeout=30,
    )
    body = response.json()
    if "error" in body:
        return {
            "ok": False,
            "status_code": response.status_code,
            "error": body["error"],
        }

    result = body["result"]
    text = result.get("content", [{}])[0].get("text", "{}")
    return {
        "ok": True,
        "payload": json.loads(text),
        "session_id": result.get("_cmcp", {}).get("session_id"),
        "cmcp": result.get("_cmcp", {}),
    }


def _read_state(
    client: httpx.Client,
    gateway: str,
    request_id: int,
) -> dict[str, Any]:
    result = call_tool(
        client,
        gateway,
        "cell.read_safety_state",
        {},
        request_id,
    )
    if not result["ok"]:
        raise RuntimeError(f"Safety-state read failed: {result['error']}")
    return result


def _request_motion(
    client: httpx.Client,
    gateway: str,
    request_id: int,
    snapshot: dict[str, Any],
    motion_id: str,
    *,
    workflow_id: str = WORKFLOW_ID,
) -> dict[str, Any]:
    return call_tool(
        client,
        gateway,
        "robot.request_motion",
        {
            "motion_id": motion_id,
            "target": "transfer-station-b",
            "max_speed_mps": 0.3,
            "safety_state_token": snapshot["state_token"],
        },
        request_id,
        workflow_id=workflow_id,
    )


def _save_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def _verify_evidence(
    claim: dict[str, Any],
    bundle: dict[str, Any],
    *,
    require_hardware: bool,
) -> None:
    expected = json.loads((EXAMPLE_DIR / "artifact-hashes.json").read_text())
    result = verify_trace_claim(
        claim,
        ApprovedHashes(
            policy_bundle_hash=expected["cmcp_policy_bundle_hash"],
            tool_catalog_hash=expected["cmcp_catalog_hash"],
        ),
    )
    bundle_result = verify_audit_bundle(
        bundle,
        claim,
        external_evidence_keys=_external_evidence_keys(),
    )
    required = {
        "schema",
        "signature",
        "policy_bundle.hash",
        "tool_catalog.hash",
        "attestation_freshness",
        "audit_chain",
    }
    missing = sorted(required - set(result.verified_fields))

    print("TRACE VERIFICATION")
    schema_status = "verified" if not missing else "failed"
    print(f"  schema/signature/hashes/freshness: {schema_status}")
    print(f"  audit bundle: {'verified' if bundle_result.verified else 'failed'}")
    receipt_count = sum(
        1
        for entry in bundle.get("entries", [])
        if entry.get("external_execution_evidence")
    )
    if receipt_count:
        print(f"  controller receipts: verified ({receipt_count})")
    else:
        print("  controller receipts: not present in this bundle")
    platform = claim.get("trace", {}).get("runtime", {}).get("platform", "unknown")
    print(f"  runtime platform: {platform}")
    if platform == "software-only":
        print("  hardware attestation: not verified (development mode)")
        if require_hardware:
            missing.append("hardware_attestation")
    else:
        hardware_verified = "hardware_attestation" in result.verified_fields
        hardware_status = "verified" if hardware_verified else "failed"
        print(f"  hardware attestation: {hardware_status}")
        if require_hardware and not hardware_verified:
            missing.append("hardware_attestation")

    if bundle_result.failures:
        print(f"  audit failures: {'; '.join(bundle_result.failures)}")
    if missing or not bundle_result.verified:
        raise RuntimeError(
            "Evidence verification failed: "
            + ", ".join(missing or bundle_result.failures)
        )


def run(
    gateway: str,
    claim_out: Path,
    audit_out: Path,
    *,
    require_hardware: bool,
    print_claim: bool,
) -> None:
    session_id: str | None = None
    with httpx.Client(headers=_headers()) as client:
        print("SCOPE DENY")
        # The same in-envelope motion as the authorized path below (an approved
        # zone, an in-limit speed, a fresh valid safety token), requested under
        # an undeclared workflow. cMCP denies it on scope before the controller
        # is consulted, so the safety token is never even checked. The only
        # difference from the authorized path is the workflow scope, not the
        # motion or its physical safety.
        state = _read_state(client, gateway, 1)
        session_id = state["session_id"]
        denied = _request_motion(
            client,
            gateway,
            2,
            state["payload"],
            "move-0001",
            workflow_id="unapproved-diagnostics",
        )
        if denied["ok"] or denied["status_code"] != 403:
            raise RuntimeError("Out-of-scope motion was not denied by cMCP")
        print("  cMCP policy: denied (out of declared scope)")
        print("  controller: not consulted")
        print()

        print("SUCCESS")
        # The identical motion, now under the declared workflow. cMCP authorizes
        # it and the independent controller accepts and completes it.
        state = _read_state(client, gateway, 3)
        success = _request_motion(
            client,
            gateway,
            4,
            state["payload"],
            "move-0002",
        )
        if not success["ok"]:
            raise RuntimeError(f"Success path failed: {success['error']}")
        if (
            success["payload"].get("controller_decision") != "accepted"
            or success["payload"].get("execution_status") != "completed"
        ):
            raise RuntimeError("Controller did not complete the expected safe motion")
        print("  cMCP policy: authorized")
        print(f"  controller: {success['payload']['controller_decision']}")
        print(f"  execution: {success['payload']['execution_status']}")
        print()

        print("SAFETY REJECT")
        state = _read_state(client, gateway, 5)
        rejected = _request_motion(
            client,
            gateway,
            6,
            state["payload"],
            "move-0003",
        )
        if not rejected["ok"]:
            raise RuntimeError(f"Safety-reject path failed: {rejected['error']}")
        if rejected["payload"].get("controller_decision") != "rejected":
            raise RuntimeError("Controller unexpectedly accepted the unsafe request")
        print("  cMCP policy: authorized")
        print("  controller: rejected")
        print(f"  reason: {rejected['payload']['reason']}")
        print("  execution: not_started")
        print()

        close = client.post(
            f"{gateway}/sessions/{session_id}/close",
            timeout=10,
        )
        close.raise_for_status()
        claim = close.json()

        audit = client.get(
            f"{gateway}/audit/export",
            params={"session_id": session_id},
            timeout=10,
        )
        audit.raise_for_status()
        bundle = audit.json()

    _save_json(claim_out, claim)
    _save_json(audit_out, bundle)
    _verify_evidence(claim, bundle, require_hardware=require_hardware)
    print(f"  claim: {claim_out}")
    print(f"  audit: {audit_out}")
    if print_claim:
        print()
        print(json.dumps(claim, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run governed robot motion scenarios through cMCP"
    )
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY)
    parser.add_argument(
        "--claim-out",
        type=Path,
        default=EXAMPLE_DIR / "trace-output" / "latest-trust-record.json",
    )
    parser.add_argument(
        "--audit-out",
        type=Path,
        default=EXAMPLE_DIR / "trace-output" / "latest-audit-bundle.json",
    )
    parser.add_argument("--require-hardware", action="store_true")
    parser.add_argument("--print-claim", action="store_true")
    args = parser.parse_args()
    run(
        args.gateway,
        args.claim_out,
        args.audit_out,
        require_hardware=args.require_hardware,
        print_claim=args.print_claim,
    )


if __name__ == "__main__":
    main()
