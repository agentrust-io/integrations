#!/usr/bin/env python3
"""
Clinical decision support agent demo for hospital AI compliance.

Runs a four-step workflow through the cMCP Runtime using JSON-RPC 2.0 over HTTP,
then closes the session to obtain the signed TRACE Trust Record. The agent runs
a drug-interaction check and passes its result into the write call, so the
guardrails act on the real safety outcome.

Scenarios:

    --scenario standard          Add empagliflozin (second-line), standard risk.
                                 Interaction check clean. All four steps allow.
    --scenario high-risk         Same plan, patient_risk_category=high. The write
                                 is blocked for human oversight (EU AI Act Art. 14).
    --scenario contraindication  Propose co-trimoxazole for an incidental UTI.
                                 The patient has a documented sulfonamide allergy,
                                 so the interaction check flags a severe
                                 contraindication and the write is blocked.

Usage:
    python clinical_decision_agent.py [--gateway http://localhost:8443]
                                      [--scenario standard|high-risk|contraindication]
"""

import argparse
import json
import sys
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_GATEWAY = "http://localhost:8443"
WORKFLOW_ID = "clinical-decision-support"
PATIENT_ID = "P-2024-008471"
SYMPTOMS = ["fatigue", "polyuria", "polydipsia", "blurred vision"]

SCENARIOS = {
    "standard": {
        "risk": "standard",
        "proposed": ["empagliflozin"],
        "treatment": "Continue metformin 500mg BID; add empagliflozin 10mg once daily; HbA1c recheck in 3 months",
    },
    "high-risk": {
        "risk": "high",
        "proposed": ["empagliflozin"],
        "treatment": "Continue metformin 500mg BID; add empagliflozin 10mg once daily; HbA1c recheck in 3 months",
    },
    "contraindication": {
        "risk": "standard",
        "proposed": ["co-trimoxazole"],
        "treatment": "Add co-trimoxazole 960mg BID for 3 days (incidental urinary tract infection)",
    },
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
    return {"ok": True, "payload": json.loads(payload_text),
            "session_id": result.get("_cmcp", {}).get("session_id")}


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
    print(f"Connecting to cMCP Runtime at {gateway}")
    # This is a PHI-handling demo, so the patient identifier is deliberately not
    # written to stdout in clear text; it travels only in the tool arguments and
    # the signed TRACE record (trace.subject).
    print(f"Scenario: {scenario}  |  Patient: [redacted PHI]  |  Risk category: {sc['risk']}")
    print()

    session_id = None
    with httpx.Client(headers={"Content-Type": "application/json"}) as client:
        o1 = call_tool(client, gateway, "ehr.patient_record_lookup",
                       {"patient_id": PATIENT_ID, "record_type": "full"}, 1)
        note = ""
        if o1["ok"]:
            dx = ", ".join(d["icd10"] for d in o1["payload"].get("active_diagnoses", []))
            note = f"active dx: {dx}"
        print_outcome("1/4", "ehr.patient_record_lookup", o1, note)
        session_id = o1.get("session_id") or session_id

        o2 = call_tool(client, gateway, "ehr.clinical_decision_support",
                       {"patient_id": PATIENT_ID, "presenting_symptoms": SYMPTOMS}, 2)
        note = ""
        if o2["ok"] and o2["payload"].get("differential"):
            note = o2["payload"]["differential"][0]["condition"]
        print_outcome("2/4", "ehr.clinical_decision_support", o2, note)
        session_id = o2.get("session_id") or session_id

        o3 = call_tool(client, gateway, "ehr.drug_interaction_check",
                       {"patient_id": PATIENT_ID, "proposed_medications": sc["proposed"]}, 3)
        has_contra = bool(o3["payload"].get("has_severe_contraindication")) if o3["ok"] else False
        print_outcome("3/4", "ehr.drug_interaction_check", o3,
                      f"highest_severity={o3['payload'].get('highest_severity')}" if o3["ok"] else "")
        session_id = o3.get("session_id") or session_id

        o4 = call_tool(client, gateway, "ehr.treatment_plan_writer", {
            "patient_id": PATIENT_ID,
            "diagnosis": "Type 2 diabetes mellitus with hypertension",
            "treatment": sc["treatment"],
            "patient_risk_category": sc["risk"],
            "has_severe_contraindication": has_contra,
        }, 4)
        print_outcome("4/4", "ehr.treatment_plan_writer", o4)
        session_id = o4.get("session_id") or session_id

        if not o4["ok"]:
            print()
            print("  The treatment plan was NOT written to the EHR.")
            print("  An attending physician must review and approve before the plan takes effect.")

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
    parser = argparse.ArgumentParser(description="Clinical decision support agent demo")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY,
                        help=f"cMCP Runtime base URL (default: {DEFAULT_GATEWAY})")
    parser.add_argument("--scenario", default="standard", choices=sorted(SCENARIOS),
                        help="which clinical scenario to run (default: standard)")
    args = parser.parse_args()
    run(args.gateway, args.scenario)
