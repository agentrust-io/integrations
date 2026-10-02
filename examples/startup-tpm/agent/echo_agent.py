#!/usr/bin/env python3
"""Minimal echo agent for the cMCP startup quickstart.

Calls test.echo through the runtime, closes the session, and prints the
signed TRACE Trust Record.

Usage:
    python echo_agent.py [--gateway http://localhost:8443]
"""

import argparse
import json
import sys
import httpx

DEFAULT_GATEWAY = "http://localhost:8443"


def run(gateway: str) -> None:
    print(f"Connecting to cMCP Runtime at {gateway}")
    print()

    with httpx.Client(headers={"Content-Type": "application/json"}) as client:
        print("[1/1] Calling test.echo ...")
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "test.echo", "arguments": {"message": "hello from cMCP"}},
        }
        resp = client.post(f"{gateway}/mcp", json=payload, timeout=30)
        body = resp.json()
        if "error" in body:
            print(f"      -> error: {body['error']}")
            print("  Is the runtime running? Start it with:")
            print("    CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml")
            sys.exit(1)
        result = body["result"]
        meta = result.get("_cmcp", {})
        content = result.get("content", [])
        echoed = content[0].get("text", "") if content else ""
        print("      -> decision: allow")
        print(f"      -> echoed:   {echoed}")
        session_id = meta.get("session_id")
        print()

        if not session_id:
            print("No session id in response - cannot fetch TRACE Trust Record.")
            sys.exit(1)

        print(f"Closing session {session_id} and fetching the signed TRACE Trust Record ...")
        resp = client.post(f"{gateway}/sessions/{session_id}/close", timeout=10)
        resp.raise_for_status()
        print()
        print("=== TRACE Trust Record (signed RuntimeClaim) ===")
        print(json.dumps(resp.json(), indent=2))

    print()
    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="cMCP echo agent quickstart")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY,
                        help=f"cMCP Runtime base URL (default: {DEFAULT_GATEWAY})")
    args = parser.parse_args()
    run(args.gateway)
