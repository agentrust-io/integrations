#!/usr/bin/env python3
"""Demo 5: attribute-based enforcement (compliance domain / BAA coverage).

demo-01 denies by tool name. demo-04 denies by workflow context. This demo
denies by the tool's compliance attributes: a tool that is not BAA-covered is
refused by a single guardrail rule, whatever the tool is named. The decision is
made on `context.baa_covered`, derived by the runtime from the catalog.

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

CHART_TEXT = "Patient 88213 -- visit note -- BP 128/82 -- follow-up 2 weeks\n"


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
            "_cmcp": {"workflow_id": "clinical-intake"},
        },
    })


def main():
    WORKSPACE.mkdir(exist_ok=True)
    session_id = None

    print("=== Demo 5: attribute-based enforcement (BAA coverage) ===")
    print("Guardrail: forbid any tool where context.baa_covered == false.\n")
    print("Catalog:")
    print("  write_file  domain=clinical            baa_covered=true")
    print("  read_file   domain=clinical            baa_covered=true")
    print("  list_dir    domain=external-analytics  baa_covered=false\n")

    # 1. write_file -- BAA-covered -> permitted
    print("[1/3] write_file  [clinical, baa_covered=true]")
    body, status = mcp_call("write_file", {"path": "chart.txt", "content": CHART_TEXT})
    if status == 200:
        session_id = body["result"].get("_cmcp", {}).get("session_id")
        print(f"      ALLOWED  {body['result']['content'][0]['text']!r}")
    else:
        print(f"      ERROR {status}: {body}")
        sys.exit(1)

    # 2. read_file -- BAA-covered -> permitted
    print()
    print("[2/3] read_file   [clinical, baa_covered=true]")
    body, status = mcp_call("read_file", {"path": "chart.txt"})
    if status == 200:
        session_id = body["result"].get("_cmcp", {}).get("session_id") or session_id
        print(f"      ALLOWED  content={body['result']['content'][0]['text'].strip()!r}")
    else:
        print(f"      ERROR {status}: {body}")

    # 3. list_dir -- NOT BAA-covered -> denied by the guardrail, not by its name
    print()
    print("[3/3] list_dir    [external-analytics, baa_covered=false]")
    body, status = mcp_call("list_dir", {})
    if status == 403:
        error = body.get("error", {})
        code = error.get("data", {}).get("error_code", "?")
        print(f"      HTTP 403 -- {error.get('message', '?')} [{code}]")
        print("      Denied by the BAA guardrail: context.baa_covered == false.")
        print("      Not blocked by naming list_dir -- blocked by its compliance attribute.")
    else:
        print(f"      unexpected {status}: {body}")
        sys.exit(1)

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
    print("  One guardrail rule covers every non-BAA-covered tool, current and future.")
    print("  Add a tool to the catalog with requires_baa=true and it is refused on arrival.")

    claim_path = WORKSPACE / "trace-claim-demo05.json"
    claim_path.write_text(json.dumps(claim, indent=2))
    print()
    print(f"  Claim saved to {claim_path}")


if __name__ == "__main__":
    main()
