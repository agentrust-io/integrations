#!/usr/bin/env python3
"""
Mock EU Credit Risk MCP Server for the financial-services demo.

Serves the six catalog tools on port 8080. Tool responses are computed by
``credit_engine`` from a small set of realistic EU corporate client fixtures,
so the server, the tests and the agent all agree on the same data.

Stdlib only -- no dependencies.

Usage:
    python financial-services/server/mock_mcp_server.py
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import credit_engine  # noqa: E402

PORT = 8080


def _document_reader(args: dict) -> str:
    return json.dumps(credit_engine.read_financials(args.get("client_id", credit_engine.DEFAULT_CLIENT)))


def _sanctions_screening(args: dict) -> str:
    return json.dumps(credit_engine.screen_sanctions(args.get("client_id", credit_engine.DEFAULT_CLIENT)))


def _credit_bureau_lookup(args: dict) -> str:
    return json.dumps(credit_engine.bureau_report(
        args.get("client_id", credit_engine.DEFAULT_CLIENT),
        args.get("bureau", "creditreform"),
    ))


def _exposure_aggregation(args: dict) -> str:
    return json.dumps(credit_engine.aggregate_exposure(
        args.get("client_id", credit_engine.DEFAULT_CLIENT),
        int(args.get("proposed_facility_eur", 0)),
    ))


def _risk_model(args: dict) -> str:
    return json.dumps(credit_engine.run_risk_model(
        args.get("client_id", credit_engine.DEFAULT_CLIENT),
        int(args.get("proposed_facility_eur", 0)),
    ))


def _risk_report_writer(args: dict) -> str:
    return json.dumps({
        "client_id": args.get("client_id", ""),
        "internal_rating": args.get("internal_rating"),
        "recommendation": args.get("recommendation"),
        "amount_eur": args.get("amount_eur"),
        "report_id": "RR-2026-04471",
        "status": "written",
    })


TOOLS = {
    "finance.document_reader": _document_reader,
    "finance.sanctions_screening": _sanctions_screening,
    "finance.credit_bureau_lookup": _credit_bureau_lookup,
    "finance.exposure_aggregation": _exposure_aggregation,
    "finance.risk_model": _risk_model,
    "finance.risk_report_writer": _risk_report_writer,
}


# Upstream definitions are independent of the gateway catalog used for drift checks.
TOOL_DEFINITIONS = [
    {
        "name": "finance.document_reader",
        "description": "Read filed annual financial statements for a corporate client from the secure "
        "document vault",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string"},
                "document_id": {"type": "string"},
            },
            "required": ["client_id"],
        },
    },
    {
        "name": "finance.sanctions_screening",
        "description": "Screen a corporate client and its beneficial owners against EU/UN sanctions and "
        "PEP lists (CDD/AML)",
        "inputSchema": {
            "type": "object",
            "properties": {"client_id": {"type": "string"}},
            "required": ["client_id"],
        },
    },
    {
        "name": "finance.credit_bureau_lookup",
        "description": "Retrieve a commercial credit-bureau report for a client",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string"},
                "bureau": {
                    "type": "string",
                    "enum": [
                        "creditreform",
                        "schufa",
                        "crif",
                        "banque-de-france-fiben",
                    ],
                },
            },
            "required": ["client_id"],
        },
    },
    {
        "name": "finance.exposure_aggregation",
        "description": "Aggregate existing group exposure with the proposed facility and test it against "
        "the single-obligor concentration limit",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string"},
                "proposed_facility_eur": {"type": "number"},
            },
            "required": ["client_id", "proposed_facility_eur"],
        },
    },
    {
        "name": "finance.risk_model",
        "description": "Compute PD/LGD/EAD, the internal rating grade and the IFRS 9 stage for a "
        "proposed facility",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string"},
                "proposed_facility_eur": {"type": "number"},
            },
            "required": ["client_id", "proposed_facility_eur"],
        },
    },
    {
        "name": "finance.risk_report_writer",
        "description": "Write the credit risk assessment to the core banking system",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_id": {"type": "string"},
                "internal_rating": {"type": "string"},
                "pd_1y": {"type": "number"},
                "ifrs9_stage": {"type": "number"},
                "amount_eur": {"type": "number"},
                "aggregate_exposure_eur": {"type": "number"},
                "breaches_concentration_limit": {"type": "boolean"},
                "cdd_cleared": {"type": "boolean"},
                "recommendation": {"type": "string"},
            },
            "required": ["client_id", "amount_eur", "recommendation", "cdd_cleared"],
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
        print(f"[mock-mcp] {fmt % args}")


if __name__ == "__main__":
    print(f"Mock EU Credit Risk MCP Server listening on :{PORT} (tools: {', '.join(TOOLS)})")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
