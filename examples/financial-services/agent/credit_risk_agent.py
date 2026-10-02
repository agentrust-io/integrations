#!/usr/bin/env python3
"""
Credit risk agent demo for an EU corporate lender.

Runs a six-step credit assessment through the cMCP Runtime using JSON-RPC 2.0
over HTTP, then closes the session to obtain the signed TRACE Trust Record. The
arguments the agent passes to the final write call (CDD clearance, IFRS 9 stage,
concentration breach, rating) are derived from the earlier tool outputs, so the
Cedar guardrails act on the real result of the assessment.

Three scenarios:

    --scenario clean            Rheintal Präzisionstechnik GmbH, EUR 250k.
                                Clean CDD, within limits, performing. All allow.
    --scenario large-exposure   Nordwind Logistik AG, EUR 750k. Exceeds
                                delegated authority and breaches the
                                concentration limit. Write denied.
    --scenario sanctions-hit    Meridian Trading DMCC, EUR 200k. A beneficial
                                owner matches a sanctions list, so CDD does not
                                clear and the runtime blocks the write.

Usage:
    python credit_risk_agent.py [--gateway http://localhost:8443]
                                [--scenario clean|large-exposure|sanctions-hit]
"""

import argparse
import json
import sys
import httpx

# Company names in this demo carry German umlauts; force UTF-8 so the console
# output is correct on Windows terminals too.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_GATEWAY = "http://localhost:8443"
WORKFLOW_ID = "credit-risk-analyst"
BUREAU = "creditreform"

SCENARIOS = {
    "clean": {"client_id": "DE-CORP-2024-00847", "amount_eur": 250_000},
    "large-exposure": {"client_id": "DE-CORP-2024-01120", "amount_eur": 750_000},
    "sanctions-hit": {"client_id": "AE-CORP-2024-00311", "amount_eur": 200_000},
}


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
        return {"ok": False, "error": body["error"], "payload": None, "session_id": None}
    result = body["result"]
    payload_text = result.get("content", [{}])[0].get("text", "{}")
    return {
        "ok": True,
        "payload": json.loads(payload_text),
        "session_id": result.get("_cmcp", {}).get("session_id"),
    }


def print_outcome(step, tool, outcome, note=""):
    print(f"[{step}] {tool} ...")
    if outcome["ok"]:
        print(f"      -> decision: allow{('  ' + note) if note else ''}")
    else:
        data = outcome["error"].get("data", {})
        print(f"      -> decision: deny ({data.get('error_code', 'unknown')})")
        advice = data.get("advice")
        if advice:
            print("         advice from policy:")
            for key, value in advice.items():
                print(f"           {key}: {value}")


def close_session(client, gateway, session_id):
    resp = client.post(f"{gateway}/sessions/{session_id}/close", timeout=10)
    resp.raise_for_status()
    return resp.json()


def run(gateway, scenario):
    sc = SCENARIOS[scenario]
    client_id, amount = sc["client_id"], sc["amount_eur"]
    print(f"Connecting to cMCP Runtime at {gateway}")
    print(f"Scenario: {scenario}  |  Client: {client_id}  |  Facility: EUR {amount:,}")
    print()

    session_id = None
    with httpx.Client(headers={"Content-Type": "application/json"}) as client:
        o1 = call_tool(client, gateway, "finance.document_reader", {"client_id": client_id}, 1)
        note = ""
        if o1["ok"]:
            p = o1["payload"]
            note = f"{p.get('legal_name')} (LEI {p.get('lei')})"
        print_outcome("1/6", "finance.document_reader", o1, note)
        session_id = o1.get("session_id") or session_id

        o2 = call_tool(client, gateway, "finance.sanctions_screening", {"client_id": client_id}, 2)
        cdd_status = o2["payload"].get("cdd_status") if o2["ok"] else "unknown"
        print_outcome("2/6", "finance.sanctions_screening", o2, f"cdd_status={cdd_status}")
        session_id = o2.get("session_id") or session_id

        o3 = call_tool(client, gateway, "finance.credit_bureau_lookup",
                       {"client_id": client_id, "bureau": BUREAU}, 3)
        note = ""
        if o3["ok"]:
            p = o3["payload"]
            note = f"Creditreform index {p.get('bonitaetsindex')} ({p.get('assessment')})"
        print_outcome("3/6", "finance.credit_bureau_lookup", o3, note)
        session_id = o3.get("session_id") or session_id

        o4 = call_tool(client, gateway, "finance.exposure_aggregation",
                       {"client_id": client_id, "proposed_facility_eur": amount}, 4)
        breaches = o4["payload"].get("breaches_concentration_limit") if o4["ok"] else None
        aggregate = o4["payload"].get("aggregate_exposure_eur") if o4["ok"] else None
        print_outcome("4/6", "finance.exposure_aggregation", o4,
                      f"aggregate EUR {aggregate:,}  breach={breaches}" if aggregate is not None else "")
        session_id = o4.get("session_id") or session_id

        o5 = call_tool(client, gateway, "finance.risk_model",
                       {"client_id": client_id, "proposed_facility_eur": amount}, 5)
        rating = o5["payload"].get("internal_rating") if o5["ok"] else None
        pd_1y = o5["payload"].get("pd_1y") if o5["ok"] else None
        ifrs9_stage = o5["payload"].get("ifrs9_stage") if o5["ok"] else None
        print_outcome("5/6", "finance.risk_model", o5,
                      f"rating {rating}  IFRS9 stage {ifrs9_stage}")
        session_id = o5.get("session_id") or session_id

        cdd_cleared = cdd_status == "clear"
        recommendation = "approve" if (cdd_cleared and not breaches and ifrs9_stage == 1) else "refer"
        o6 = call_tool(client, gateway, "finance.risk_report_writer", {
            "client_id": client_id,
            "internal_rating": rating,
            "pd_1y": pd_1y,
            "ifrs9_stage": ifrs9_stage,
            "amount_eur": amount,
            "aggregate_exposure_eur": aggregate,
            "breaches_concentration_limit": breaches,
            "cdd_cleared": cdd_cleared,
            "recommendation": recommendation,
        }, 6)
        print_outcome("6/6", "finance.risk_report_writer", o6)
        session_id = o6.get("session_id") or session_id

        if not o6["ok"]:
            print()
            print("  The risk report was NOT written to the core banking system.")

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
    print("Done. Verify the audit chain with:")
    print(f"  curl {gateway}/audit/export?session_id={session_id}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EU corporate credit risk agent demo")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY,
                        help=f"cMCP Runtime base URL (default: {DEFAULT_GATEWAY})")
    parser.add_argument("--scenario", default="clean", choices=sorted(SCENARIOS),
                        help="which client scenario to run (default: clean)")
    args = parser.parse_args()
    run(args.gateway, args.scenario)
