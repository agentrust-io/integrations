#!/usr/bin/env python3
"""
PeopleGraph agent demo showing per-tenant Cedar policy isolation.

Runs the same four tool calls; the outcome depends on which tenant's policy
bundle and enforcement mode the runtime was started with:

    metzler-eu (EU, enforcing):
        headcount allow, employee lookup allow, cross-region export DENY
        (GDPR data residency), special-category lookup DENY (GDPR Art. 9)
    summit-us (US, advisory):
        headcount allow, employee lookup allow, export allow,
        special-category lookup advisory_deny (logged, not blocked)

Usage:
    python saas_agent.py --tenant metzler-eu|summit-us [--gateway http://localhost:8443]
"""

import argparse
import json
import sys
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_GATEWAY = "http://localhost:8443"
WORKFLOW_ID = "people-analytics"

# The same four calls run against whichever tenant policy the runtime loaded.
CALLS = [
    ("people.headcount_analytics",
     {"metric": "attrition", "period": "2026-Q2"}),
    ("people.employee_record_lookup",
     {"employee_id": "EMP-DE-4821", "legal_basis": "legitimate_interest"}),
    ("people.data_export",
     {"scope": "engineering", "destination_region": "us-east-1", "legal_basis": "legitimate_interest"}),
    ("people.employee_record_lookup",
     {"employee_id": "EMP-DE-4821", "include_special_category": True, "legal_basis": "legitimate_interest"}),
]


def call_tool(client, gateway, tool_name, arguments, req_id):
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
            "_cmcp": {"workflow_id": WORKFLOW_ID},
        },
    }
    resp = client.post(f"{gateway}/mcp", json=payload, timeout=30)
    body = resp.json()
    if "error" in body:
        return {"ok": False, "error": body["error"], "session_id": None}
    result = body["result"]
    return {"ok": True, "result": result, "session_id": result.get("_cmcp", {}).get("session_id")}


def print_outcome(outcome):
    if outcome["ok"]:
        meta = outcome["result"].get("_cmcp", {})
        if meta.get("would_have_denied"):
            print("      -> decision: advisory_deny (logged, not blocked)")
            _print_advice(meta.get("advice"))
        else:
            print("      -> decision: allow")
    else:
        data = outcome["error"].get("data", {})
        print(f"      -> decision: deny ({data.get('error_code', 'unknown')})")
        _print_advice(data.get("advice"))


def _print_advice(advice):
    if advice:
        print("         advice from policy:")
        for key, value in advice.items():
            print(f"           {key}: {value}")


def close_session(client, gateway, session_id):
    resp = client.post(f"{gateway}/sessions/{session_id}/close", timeout=10)
    resp.raise_for_status()
    return resp.json()


def run(gateway, tenant):
    print(f"Connecting to cMCP Runtime at {gateway}")
    print(f"Tenant:   {tenant}")
    print(f"Workflow: {WORKFLOW_ID}")
    print()
    print(f"Running the same {len(CALLS)} tool calls against {tenant}'s policy bundle.")
    print()

    session_id = None
    with httpx.Client(headers={"Content-Type": "application/json"}) as client:
        for i, (tool, args) in enumerate(CALLS, start=1):
            summary = ", ".join(f"{k}={v}" for k, v in args.items() if k != "legal_basis")
            print(f"[{i}/{len(CALLS)}] {tool} ({summary})")
            o = call_tool(client, gateway, tool, args, i)
            print_outcome(o)
            session_id = o.get("session_id") or session_id

        print()
        if session_id is None:
            print("No session id received - cannot fetch TRACE Trust Record.")
            sys.exit(1)

        print(f"Closing session {session_id} and fetching the signed TRACE Trust Record ...")
        claim = close_session(client, gateway, session_id)
        print()
        print("=== TRACE Trust Record (signed RuntimeClaim) ===")
        print(json.dumps(claim, indent=2))

    print()
    print("Done. Restart the runtime with the other tenant config to see the policy difference.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PeopleGraph multi-tenant policy isolation demo")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY,
                        help=f"cMCP Runtime base URL (default: {DEFAULT_GATEWAY})")
    parser.add_argument("--tenant", required=True, choices=["metzler-eu", "summit-us"],
                        help="Which tenant config the runtime was started with")
    args = parser.parse_args()
    run(args.gateway, args.tenant)
