#!/usr/bin/env python3
"""Demo 1: calls tools through cMCP, shows Cedar enforcement, saves TRACE claim.

Prerequisites:
  server/server.py running on :9001 (plain HTTP JSON-RPC 2.0)
  cmcp start --config cmcp-config.yaml running on :8443
  CMCP_BEARER_TOKEN env var set (run.sh exports this)

Usage:
  python call.py   (run from repo root, or via run.sh)
"""
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

GATEWAY_URL = "http://localhost:8443"
TOKEN = os.environ.get("CMCP_BEARER_TOKEN", "demo-token")
WORKSPACE = pathlib.Path(__file__).parent.parent / "workspace"


def _headers():
    return {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}


def _post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read()), exc.code


def mcp_call(name, arguments):
    return _post(f"{GATEWAY_URL}/mcp", {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_cmcp": {"workflow_id": "demo-01"},
        },
    })


def main():
    WORKSPACE.mkdir(exist_ok=True)
    session_id = None

    print("=== Demo 1: cMCP in action ===\n")

    # write_file -- Cedar: permit
    print("[1/3] write_file  [Cedar: permit]")
    body, status = mcp_call("write_file", {
        "path": "hello.txt",
        "content": "Written under Cedar enforcement at agentrust CC Summit 2026\n",
    })
    if status == 200:
        text = body["result"]["content"][0]["text"]
        cmcp = body["result"].get("_cmcp", {})
        session_id = cmcp.get("session_id")
        print(f"      ALLOWED  result={text!r}")
        print(f"      session_id={session_id}  latency={cmcp.get('latency_us')} us")
    else:
        print(f"      ERROR {status}: {body}")
        sys.exit(1)

    # read_file -- Cedar: permit
    print()
    print("[2/3] read_file   [Cedar: permit]")
    body, status = mcp_call("read_file", {"path": "hello.txt"})
    if status == 200:
        text = body["result"]["content"][0]["text"]
        session_id = body["result"].get("_cmcp", {}).get("session_id") or session_id
        print(f"      ALLOWED  content={text.strip()!r}")
    else:
        print(f"      ERROR {status}: {body}")

    # list_dir -- Cedar: forbid
    print()
    print("[3/3] list_dir    [Cedar: forbid]")
    body, status = mcp_call("list_dir", {})
    if status == 403:
        error = body.get("error", {})
        code = error.get("data", {}).get("error_code", "?")
        print(f"      HTTP 403 -- {error.get('message', '?')} [{code}]")
        print("      Cedar forbid matched: resource.tool_name == \"list_dir\"")
    else:
        print(f"      unexpected {status}: {body}")

    # close session -> signed TRACE claim
    print()
    print("Closing session -> TRACE claim...")
    if not session_id:
        print("ERROR: no session_id. Is cMCP returning _cmcp metadata?")
        sys.exit(1)

    body, status = _post(f"{GATEWAY_URL}/sessions/{session_id}/close", {})
    if status != 200:
        print(f"ERROR {status}: {body}")
        sys.exit(1)
    claim = body

    trace = claim.get("trace", {})
    gw = claim.get("gateway", {})
    chain = gw.get("audit_chain", {})

    print()
    print("=== TRACE claim ===")
    print(f"  runtime.platform:    {trace.get('runtime', {}).get('platform')}")
    print(f"  runtime.measurement: {trace.get('runtime', {}).get('measurement')}")
    print(f"  policy.bundle_hash:  {trace.get('policy', {}).get('bundle_hash')}")
    print(f"  policy.mode:         {trace.get('policy', {}).get('enforcement_mode')}")
    print(f"  catalog.hash:        {gw.get('catalog', {}).get('hash')}")
    print(f"  audit_chain.length:  {chain.get('length')}")
    sig = claim.get("signature", "")
    print(f"  signature:           {sig[:40]}...")
    print()
    print("  policy.bundle_hash is committed in the Ed25519 signature.")
    print("  On real TDX: it also flows into RTMR[2] at cMCP Runtime startup.")

    claim_path = WORKSPACE / "trace-claim.json"
    claim_path.write_text(json.dumps(claim, indent=2))
    print()
    print(f"  Claim saved to {claim_path}")
    print("  Used by demo-02 and demo-03.")


if __name__ == "__main__":
    main()
