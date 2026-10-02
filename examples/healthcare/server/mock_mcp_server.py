#!/usr/bin/env python3
"""
Mock Hospital EHR MCP Server for the healthcare demo.

Serves the four catalog tools on port 8080. Tool responses come from
``clinical_engine`` so the server, the tests and the agent share one coherent
patient. Stdlib only -- no dependencies.

Usage:
    python healthcare/server/mock_mcp_server.py
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import clinical_engine  # noqa: E402

PORT = 8080


def _patient_record_lookup(args: dict) -> str:
    return json.dumps(clinical_engine.patient_record(
        args.get("patient_id", ""), args.get("record_type", "full")))


def _clinical_decision_support(args: dict) -> str:
    return json.dumps(clinical_engine.clinical_decision_support(
        args.get("patient_id", ""), args.get("presenting_symptoms")))


def _drug_interaction_check(args: dict) -> str:
    return json.dumps(clinical_engine.drug_interaction_check(
        args.get("patient_id", ""), args.get("proposed_medications", [])))


def _treatment_plan_writer(args: dict) -> str:
    return json.dumps({
        "patient_id": args.get("patient_id", ""),
        "diagnosis": args.get("diagnosis"),
        "treatment": args.get("treatment"),
        "patient_risk_category": args.get("patient_risk_category"),
        "plan_id": "TP-2026-08831",
        "status": "written",
    })


TOOLS = {
    "ehr.patient_record_lookup": _patient_record_lookup,
    "ehr.clinical_decision_support": _clinical_decision_support,
    "ehr.drug_interaction_check": _drug_interaction_check,
    "ehr.treatment_plan_writer": _treatment_plan_writer,
}


# Upstream definitions are independent of the gateway catalog used for drift checks.
TOOL_DEFINITIONS = [
    {
        "name": "ehr.patient_record_lookup",
        "description": "Look up patient clinical record from the EHR system",
        "inputSchema": {
            "type": "object",
            "properties": {
                "patient_id": {"type": "string"},
                "record_type": {
                    "type": "string",
                    "enum": [
                        "demographics",
                        "diagnoses",
                        "medications",
                        "labs",
                        "vitals",
                        "full",
                    ],
                },
            },
            "required": ["patient_id"],
        },
    },
    {
        "name": "ehr.clinical_decision_support",
        "description": "Run AI-assisted differential diagnosis and clinical decision support",
        "inputSchema": {
            "type": "object",
            "properties": {
                "patient_id": {"type": "string"},
                "presenting_symptoms": {"type": "array", "items": {"type": "string"}},
                "lab_values": {"type": "object"},
            },
            "required": ["patient_id", "presenting_symptoms"],
        },
    },
    {
        "name": "ehr.drug_interaction_check",
        "description": "Check proposed medications against the patient's current medications and documented allergies",
        "inputSchema": {
            "type": "object",
            "properties": {
                "patient_id": {"type": "string"},
                "proposed_medications": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["patient_id", "proposed_medications"],
        },
    },
    {
        "name": "ehr.treatment_plan_writer",
        "description": "Write a treatment plan to the patient record",
        "inputSchema": {
            "type": "object",
            "properties": {
                "patient_id": {"type": "string"},
                "diagnosis": {"type": "string"},
                "treatment": {"type": "string"},
                "patient_risk_category": {
                    "type": "string",
                    "enum": ["standard", "high"],
                },
                "has_severe_contraindication": {"type": "boolean"},
            },
            "required": [
                "patient_id",
                "diagnosis",
                "treatment",
                "patient_risk_category",
            ],
        },
    },
]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        if self.path != "/mcp":
            self._reply(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length))
        method = request.get("method", "")
        if method == "tools/list":
            self._reply(200, {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {"tools": TOOL_DEFINITIONS},
            })
            return
        if method != "tools/call":
            self._reply(200, {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": f"unknown method: {method}"},
            })
            return
        params = request.get("params", {})
        tool = params.get("name", "")
        handler = TOOLS.get(tool)
        if handler is None:
            self._reply(200, {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": f"unknown tool: {tool}"},
            })
            return
        text = handler(params.get("arguments", {}))
        self._reply(200, {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"content": [{"type": "text", "text": text}]},
        })

    def _reply(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[mock-ehr] {fmt % args}")


if __name__ == "__main__":
    print(f"Mock Hospital EHR MCP Server listening on :{PORT} (tools: {', '.join(TOOLS)})")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
