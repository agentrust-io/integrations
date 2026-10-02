#!/usr/bin/env python3
"""Demo 4: context-aware enforcement.

The same capability (write_file) is permitted inside the approved "invoice-run"
workflow and denied under any other workflow. The agent does not get to widen
its own authority by changing its stated intent: cMCP evaluates the declared
workflow context, it does not trust the model.

Prerequisites:
  server/server.py running on :9001 (plain HTTP JSON-RPC 2.0)
  cmcp start --config cmcp-config.yaml running on :8443
  CMCP_BEARER_TOKEN env var set (run.py / run.sh export this)

Usage:
  python call.py   (run from repo root, or via run.py)
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

INVOICE_TEXT = "Invoice 4471 -- ACME Corp -- $12,400 -- net 30\n"


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


def mcp_call(name, arguments, workflow_id):
    return _post(f"{GATEWAY_URL}/mcp", {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_cmcp": {"workflow_id": workflow_id},
        },
    })


def main():
    WORKSPACE.mkdir(exist_ok=True)
    session_id = None

    print("=== Demo 4: context-aware enforcement ===")
    print("Approved tool: write_file. Approved workflow for writes: 'invoice-run'.\n")

    # 1. write_file inside the approved workflow -- Cedar: permit (workflow matches)
    print("[1/3] write_file  workflow='invoice-run'   [approved workflow]")
    body, status = mcp_call("write_file", {"path": "invoice.txt", "content": INVOICE_TEXT}, "invoice-run")
    if status == 200:
        cmcp = body["result"].get("_cmcp", {})
        session_id = cmcp.get("session_id")
        print(f"      ALLOWED  {body['result']['content'][0]['text']!r}")
        print(f"      session_id={session_id}")
    else:
        print(f"      ERROR {status}: {body}")
        sys.exit(1)

    # 2. the IDENTICAL write, under a different workflow -- Cedar: default-deny (no permit)
    print()
    print("[2/3] write_file  workflow='chat-freeform'  [same tool, same args, other workflow]")
    body, status = mcp_call("write_file", {"path": "invoice.txt", "content": INVOICE_TEXT}, "chat-freeform")
    if status == 403:
        error = body.get("error", {})
        code = error.get("data", {}).get("error_code", "?")
        print(f"      HTTP 403 -- {error.get('message', '?')} [{code}]")
        print("      No permit matches WriteFile outside 'invoice-run'. Default-deny holds.")
        print("      The model changed its stated intent; its authority did not change.")
    else:
        print(f"      unexpected {status}: {body}")
        sys.exit(1)

    # 3. read_file under the same 'chat-freeform' workflow -- Cedar: permit (reads allowed anywhere)
    print()
    print("[3/3] read_file   workflow='chat-freeform'  [reads permitted in any workflow]")
    body, status = mcp_call("read_file", {"path": "invoice.txt"}, "chat-freeform")
    if status == 200:
        session_id = body["result"].get("_cmcp", {}).get("session_id") or session_id
        print(f"      ALLOWED  content={body['result']['content'][0]['text'].strip()!r}")
        print("      The workflow is not blanket-blocked. Only the write capability is scoped.")
    else:
        print(f"      ERROR {status}: {body}")

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
    print(f"  policy.bundle_hash:  {trace.get('policy', {}).get('bundle_hash')}")
    print(f"  policy.mode:         {trace.get('policy', {}).get('enforcement_mode')}")
    print(f"  audit_chain.length:  {chain.get('length')}  (session lifecycle + every allow/deny, hash-chained)")
    sig = claim.get("signature", "")
    print(f"  signature:           {sig[:40]}...")
    print()
    print("  The allow AND the deny are both in the signed audit chain.")
    print("  You can prove which policy was in force when each call was decided.")

    claim_path = WORKSPACE / "trace-claim-demo04.json"
    claim_path.write_text(json.dumps(claim, indent=2))
    print()
    print(f"  Claim saved to {claim_path}")


if __name__ == "__main__":
    main()
