from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sentinel.models import (
    SentinelInput, Ticket, EnforcementResult, Action,
    IncidentReport, ReplayResult, Receipt
)
from sentinel.risk_engine import RiskEngine
from sentinel.replay_engine import ReplayEngine
import traceback
import uuid
import json
import hashlib
import base64
from datetime import datetime

app = FastAPI(title="Agent Sentinel")
BASE_DIR = Path(__file__).resolve().parent
templates_dir = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(templates_dir))
engine = RiskEngine()
replay_engine = ReplayEngine()

# In-memory stores
enforcement_status = {}
enforcement_action = {}
enforcement_timestamp = {}
receipt_store = {}          # claim_id -> Receipt (single receipt per claim)
ticket_store = {}
quarantine_store = {}
block_store = {}

def normalize_risk_level(risk_level: str) -> str:
    valid = ["low", "medium", "high", "critical"]
    if risk_level and risk_level.lower() in valid:
        return risk_level.lower()
    return "low"

def log_enforcement(action: str, claim_id: str, result: dict, status: str = "SUCCESS"):
    print(f"\n[ENFORCE]")
    print(f"Claim: {claim_id}")
    print(f"Action: {action.upper()}")
    print(f"Result: {result.get('message', result)}")
    print(f"Status: {status}\n")

def sign_payload(payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True).encode('utf-8')
    hash_digest = hashlib.sha256(data).digest()
    return base64.b64encode(hash_digest + b"signed").decode('utf-8')

def hash_payload(payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True).encode('utf-8')
    return hashlib.sha256(data).hexdigest()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.post("/evaluate")
async def evaluate(request: Request):
    try:
        data = await request.json()
        if "agents" in data or "agent_fleet" in data:
            agents_list = data.get("agents") or data.get("agent_fleet", [])
            if not agents_list:
                return JSONResponse(content={"error": "No agents provided"}, status_code=400)

            inputs = []
            for agent_data in agents_list:
                inp = SentinelInput(
                    trace_id=agent_data.get("trace_id", f"fleet-{agent_data.get('agent_id', 'unknown')}"),
                    agent_id=agent_data.get("agent_id", "unknown"),
                    session_id=agent_data.get("session_id", "unknown"),
                    policy_version=agent_data.get("policy_version", "v1"),
                    delegation_chain=agent_data.get("delegation_chain", []),
                    tool_calls=agent_data.get("tool_calls", []),
                    observer_identity_hash=agent_data.get("observer_identity_hash", ""),
                    reference_frame_hash=agent_data.get("reference_frame_hash", ""),
                    timestamp=agent_data.get("timestamp", ""),
                    agent_fleet=[a.get("agent_id", "unknown") for a in agents_list]
                )
                inputs.append(inp)

            result = engine.evaluate_fleet(inputs)

            trace_claims = []
            for c in result["trace_claims"]:
                claim_dict = c.model_dump(mode='json')
                claim_id = claim_dict["claim_id"]
                claim_dict["enforcement_status"] = enforcement_status.get(claim_id, "pending")
                if claim_id in enforcement_action:
                    claim_dict["enforcement_action"] = enforcement_action[claim_id]
                trace_claims.append(claim_dict)

            serializable = {
                "fleet_risk_score": result["fleet_risk_score"],
                "fleet_risk_level": result["fleet_risk_level"],
                "agent_results": [
                    {
                        "agent_id": r["agent_id"],
                        **r["result"].model_dump(mode='json')
                    }
                    for r in result["agent_results"]
                ],
                "collusion_patterns": [p.model_dump(mode='json') for p in result["collusion_patterns"]],
                "timeline": [
                    {
                        "timestamp": e.timestamp.isoformat(),
                        "agent_id": e.agent_id,
                        "event_type": e.event_type,
                        "description": e.description,
                        "severity": e.severity
                    }
                    for e in result["timeline"]
                ],
                "trace_claims": trace_claims,
                "graph_nodes": [n.model_dump(mode='json', by_alias=True) for n in result["graph_nodes"]],
                "graph_edges": [e.model_dump(mode='json', by_alias=True) for e in result["graph_edges"]]
            }
            return JSONResponse(content=serializable)
        else:
            try:
                inp = SentinelInput(**data)
                result = engine.evaluate(inp)
                return JSONResponse(content=result.model_dump(mode='json'))
            except Exception as e:
                return JSONResponse(content={"error": f"Invalid input: {str(e)}"}, status_code=400)
    except Exception as e:
        print("ERROR:", traceback.format_exc())
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.post("/enforce/{claim_id}")
async def enforce_action(claim_id: str, request: Request):
    data = await request.json()
    action_str = data.get("action")
    agent_id = data.get("agent_id", "unknown")

    if action_str not in ["escalate", "quarantine", "block"]:
        raise HTTPException(status_code=400, detail="Invalid action")

    action = Action(action_str)
    enforcement_status[claim_id] = f"{action_str}_applied"
    enforcement_action[claim_id] = action_str.upper()
    enforcement_timestamp[claim_id] = datetime.now().isoformat()

    result_details = {}
    log_message = ""

    # Create a single receipt for this enforcement action
    receipt = Receipt(
        receipt_id=f"RCPT-{uuid.uuid4().hex[:8].upper()}",
        executed_by="sentinel",
        timestamp=datetime.now(),
        result="SUCCESS"
    )
    receipt_store[claim_id] = receipt  # store once

    if action == Action.ESCALATE:
        ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
        ticket_store[claim_id] = {
            "ticket_id": ticket_id,
            "agent_id": agent_id,
            "claim_id": claim_id,
            "created_at": datetime.now().isoformat(),
            "status": "open",
            "assignee": "supervisor@company.com"
        }
        result_details = {
            "ticket_id": ticket_id,
            "assignee": "supervisor@company.com",
            "message": "Supervisor notified. TRACE claim attached."
        }
        log_message = "Supervisor notified"
    elif action == Action.QUARANTINE:
        blocked = ["grant_permission", "delete_logs", "write_config"]
        quarantine_store[agent_id] = {
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat(),
            "reason": "Delegation escalation and tool drift detected",
            "blocked_tools": blocked,
            "claim_id": claim_id,
            "status": "isolated"
        }
        result_details = {
            "agent_status": "isolated",
            "blocked_tools": blocked,
            "reason": "Delegation escalation detected",
            "message": "Agent isolated. Tools blocked."
        }
        log_message = "Agent isolated"
    elif action == Action.BLOCK:
        block_store[claim_id] = {
            "claim_id": claim_id,
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat(),
            "decision": "DENY",
            "reason": "Delegation escalation detected",
            "policy": "v3"
        }
        result_details = {
            "decision": "DENY",
            "policy": "v3",
            "reason": "Delegation escalation detected",
            "claim_status": "BLOCKED",
            "message": "Execution denied"
        }
        log_message = "Execution denied"

    enforcement_result = EnforcementResult(
        action=action,
        agent_id=agent_id,
        claim_id=claim_id,
        timestamp=datetime.now(),
        details=result_details,
        status="applied",
        receipt=receipt  # attach the same receipt
    )

    log_enforcement(action_str, claim_id, {"message": log_message, **result_details}, "SUCCESS")
    return JSONResponse(content=enforcement_result.model_dump(mode='json'))

@app.get("/export/receipt/{claim_id}")
async def export_receipt(claim_id: str):
    """Export the single receipt for this claim."""
    receipt = receipt_store.get(claim_id)
    if not receipt:
        return JSONResponse(content={"error": "No receipt found for this claim"}, status_code=404)
    return JSONResponse(content=receipt.model_dump(mode='json'))

@app.post("/export/incident/{claim_id}")
async def export_incident(claim_id: str, request: Request):
    try:
        data = await request.json()
        agent_id = data.get("agent_id", "unknown")
        detection_type = data.get("detection_type", "unknown")
        risk_score = data.get("risk_score", 0.0)
        raw_risk_level = data.get("risk_level", "low")
        risk_level_str = normalize_risk_level(raw_risk_level)

        enforcement_action_val = enforcement_action.get(claim_id, data.get("enforcement_action", "monitor")).upper()
        enforcement_status_val = enforcement_status.get(claim_id, data.get("enforcement_status", "pending"))
        if enforcement_status_val == "pending" and enforcement_action_val != "MONITOR":
            enforcement_status_val = "success"

        replay_results_data = data.get("replay_results", [])
        replay_results = []
        for r in replay_results_data:
            rl = normalize_risk_level(r.get("risk_level", "low"))
            replay_results.append(ReplayResult(
                policy_version=r.get("policy_version", "v1"),
                risk_score=r.get("risk_score", 0.0),
                risk_level=rl,
                decision=r.get("decision", "ADMIT"),
                reason=r.get("reason", ""),
                detections=[]
            ))

        final_rec = "Monitor"
        if enforcement_action_val == "BLOCK":
            final_rec = "Deny execution. Agent blocked."
        elif enforcement_action_val == "QUARANTINE":
            final_rec = "Isolate agent. Block listed tools. Notify security."
        elif enforcement_action_val == "ESCALATE":
            final_rec = "Escalate to supervisor with TRACE evidence."

        for r in replay_results:
            if r.policy_version == "v3" and r.decision == "DENY":
                final_rec += " Policy v3 would deny this action – consider governance update."

        report = IncidentReport(
            incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
            agent_id=agent_id,
            detection_type=detection_type,
            risk_score=risk_score,
            risk_level=risk_level_str,
            trace_claim_id=claim_id,
            enforcement_action=enforcement_action_val,
            enforcement_status=enforcement_status_val,
            replay_results=replay_results,
            final_recommendation=final_rec,
            evidence_export={"format": "trace.jwt", "claim_id": claim_id}
        )

        # Use the same receipt from the store – no new receipt created here
        if claim_id in receipt_store:
            report.receipt = receipt_store[claim_id]

        # Generate hashes and signature for the report (without the signature and hash fields)
        report_dict = report.model_dump(mode='json', exclude={'signature', 'claim_hash', 'incident_hash'})
        claim_data = {"claim_id": claim_id, "agent_id": agent_id, "detection_type": detection_type, "risk_score": risk_score}
        report.claim_hash = hash_payload(claim_data)
        report.incident_hash = hash_payload(report_dict)
        report.signature = sign_payload(report_dict)

        return JSONResponse(content=report.model_dump(mode='json'))
    except Exception as e:
        print("ERROR in export_incident:", traceback.format_exc())
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/replay")
async def replay_trace(request: Request):
    try:
        data = await request.json()
        trace_data = data.get("trace")
        policy_versions = data.get("policy_versions", ["v1", "v2", "v3"])
        inp = SentinelInput(**trace_data)
        results = replay_engine.replay(inp, policy_versions)
        return JSONResponse(content=[r.model_dump(mode='json') for r in results])
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.post("/verify/{claim_id}")
async def verify_incident(claim_id: str, request: Request):
    try:
        data = await request.json()
        report_data = data.get("report")
        if not report_data:
            return JSONResponse(content={"error": "Missing report data"}, status_code=400)

        # Recompute hashes and signature from the report (excluding signature and hash fields)
        report_copy = {k: v for k, v in report_data.items() if k not in ["signature", "claim_hash", "incident_hash"]}
        recomputed_claim_hash = hash_payload({
            "claim_id": claim_id,
            "agent_id": report_data.get("agent_id"),
            "detection_type": report_data.get("detection_type"),
            "risk_score": report_data.get("risk_score")
        })
        recomputed_incident_hash = hash_payload(report_copy)
        recomputed_signature = sign_payload(report_copy)

        valid_claim_hash = recomputed_claim_hash == report_data.get("claim_hash")
        valid_incident_hash = recomputed_incident_hash == report_data.get("incident_hash")
        valid_signature = recomputed_signature == report_data.get("signature")

        status = "VERIFIED" if (valid_claim_hash and valid_incident_hash and valid_signature) else "TAMPERED"
        return JSONResponse(content={
            "claim_id": claim_id,
            "status": status,
            "details": {
                "claim_hash_valid": valid_claim_hash,
                "incident_hash_valid": valid_incident_hash,
                "signature_valid": valid_signature
            }
        })
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)