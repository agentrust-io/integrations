#!/usr/bin/env python3
"""
Mock PeopleGraph MCP Server for the multi-tenant-saas demo.

Serves the four catalog tools on port 8080. Tool responses come from
``people_directory`` so the server, the tests and the agent share one source
of truth. Stdlib only -- no dependencies.

Usage:
    python multi-tenant-saas/server/mock_mcp_server.py
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import people_directory  # noqa: E402

PORT = 8080


def _headcount_analytics(args: dict) -> str:
    return json.dumps(people_directory.headcount_analytics(
        args.get("metric", "attrition"), args.get("period", "2026-Q2")))


def _employee_record_lookup(args: dict) -> str:
    return json.dumps(people_directory.employee_record_lookup(
        args.get("employee_id", people_directory.DEFAULT_EMPLOYEE),
        bool(args.get("include_special_category", False))))


def _data_export(args: dict) -> str:
    return json.dumps(people_directory.data_export(
        args.get("scope", "all"), args.get("destination_region", "")))


def _config_update(args: dict) -> str:
    return json.dumps(people_directory.config_update(
        args.get("key", ""), args.get("value", "")))


TOOLS = {
    "people.headcount_analytics": _headcount_analytics,
    "people.employee_record_lookup": _employee_record_lookup,
    "people.data_export": _data_export,
    "people.config_update": _config_update,
}


# Upstream definitions are independent of the gateway catalog used for drift checks.
TOOL_DEFINITIONS = [
    {
        "name": "people.headcount_analytics",
        "description": "Run a read-only, aggregate people-analytics query (no individual records)",
        "inputSchema": {
            "type": "object",
            "properties": {"metric": {"type": "string"}, "period": {"type": "string"}},
            "required": ["metric"],
        },
    },
    {
        "name": "people.employee_record_lookup",
        "description": "Look up an individual employee record",
        "inputSchema": {
            "type": "object",
            "properties": {
                "employee_id": {"type": "string"},
                "legal_basis": {"type": "string"},
                "include_special_category": {"type": "boolean"},
            },
            "required": ["employee_id"],
        },
    },
    {
        "name": "people.data_export",
        "description": "Export employee records to a destination region",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {"type": "string"},
                "destination_region": {"type": "string"},
                "legal_basis": {"type": "string"},
            },
            "required": ["destination_region"],
        },
    },
    {
        "name": "people.config_update",
        "description": "Update tenant configuration settings",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}, "value": {"type": "string"}},
            "required": ["key", "value"],
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
        print(f"[mock-peoplegraph] {fmt % args}")


if __name__ == "__main__":
    print(f"Mock PeopleGraph MCP Server listening on :{PORT} (tools: {', '.join(TOOLS)})")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
