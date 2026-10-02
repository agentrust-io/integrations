#!/usr/bin/env python3
"""Mock robot-cell MCP server for the industrial embodied-AI example."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

from controller import IndependentSafetyController, SafetyRejected  # noqa: E402


PORT = 8080
controller = IndependentSafetyController(
    token_key=b"development-only-mock-controller-key"
)
completed_motions = 0


def _read_safety_state(arguments: dict[str, Any]) -> dict[str, Any]:
    del arguments
    snapshot = controller.read_safety_state()

    # After the first successful motion, the next read represents a person
    # entering the cell after observation but before the motion request.
    if completed_motions > 0:
        controller.set_state(human_detected=True)
        print("[mock-controller] environment changed: human_detected=true")
    return snapshot


def _request_motion(arguments: dict[str, Any]) -> dict[str, Any]:
    global completed_motions
    try:
        result = controller.request_motion(arguments)
        completed_motions += 1
        return result
    except SafetyRejected as exc:
        reason = str(exc)
        result = {
            "controller_id": "spiffe://factory.example/controller/robot-cell-7",
            "motion_id": arguments.get("motion_id"),
            "controller_decision": "rejected",
            "execution_status": "not_started",
            "reason": reason,
        }
        if reason == "human_detected":
            # Reset only the synthetic stage condition so the demo is repeatable.
            controller.set_state(human_detected=False)
            completed_motions = 0
        return result


def _with_execution_receipt(result: dict[str, Any], call_id: object) -> dict[str, Any]:
    receipt = controller.sign_execution_receipt(
        call_id=str(call_id),
        decision=result,
    )
    return {**result, "external_execution_evidence": receipt}


TOOLS = {
    "cell.read_safety_state": _read_safety_state,
    "robot.request_motion": _request_motion,
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self._reply(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._reply(400, {"error": "invalid JSON"})
            return

        params = request.get("params", {})
        tool_name = params.get("name", "")
        handler = TOOLS.get(tool_name)
        if handler is None:
            self._reply(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32601,
                        "message": f"unknown tool: {tool_name}",
                    },
                },
            )
            return

        result = handler(params.get("arguments", {}))
        if tool_name == "robot.request_motion":
            result = _with_execution_receipt(result, request.get("id"))
        self._reply(
            200,
            {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, sort_keys=True),
                        }
                    ]
                },
            },
        )

    def _reply(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[mock-controller] {fmt % args}")


if __name__ == "__main__":
    print(
        "Mock Robot Cell MCP Server listening on :8080 "
        f"(tools: {', '.join(TOOLS)})"
    )
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
