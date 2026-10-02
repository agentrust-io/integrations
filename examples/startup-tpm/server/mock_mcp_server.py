#!/usr/bin/env python3
"""
Mock test MCP server for the startup-tpm quickstart.

Serves test.echo on port 8080. Stdlib only -- no dependencies.

Usage:
    python startup-tpm/server/mock_mcp_server.py
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080
ECHO_TOOL = {
    "name": "test.echo",
    "description": "Echo a message back for testing",
    "inputSchema": {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
    },
}


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
                "result": {"tools": [ECHO_TOOL]},
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
        if tool != "test.echo":
            self._reply(200, {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": f"unknown tool: {tool}"},
            })
            return
        message = params.get("arguments", {}).get("message", "")
        self._reply(200, {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"content": [{"type": "text", "text": message}]},
        })

    def _reply(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[mock-echo] {fmt % args}")


if __name__ == "__main__":
    print(f"Mock test MCP server listening on :{PORT} (tools: test.echo)")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
