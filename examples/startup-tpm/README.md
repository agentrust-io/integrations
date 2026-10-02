# startup-tpm: 15-Minute cMCP Quickstart

Get a cMCP Runtime running with TPM-backed TRACE Trust Records in under 15 minutes. Works on any cloud VM with TPM 2.0 (Azure Trusted Launch, AWS Nitro, GCP Shielded VM) or with `CMCP_DEV_MODE=1` for local development - no hardware required for testing.

---

## What you will have at the end

- A cMCP Runtime running on port 8443, proxying calls to an upstream MCP server
- A Cedar policy that permits all tool calls (replace before production)
- A one-tool catalog (`test.echo`) and a mock MCP server that serves it
- A signed TRACE Trust Record you can inspect

Estimated time: 15 minutes on a fresh VM, 5 minutes if Python is already installed.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | `python3 --version` |
| pip | any recent | `pip --version` |
| TPM 2.0 | optional | Required for hardware attestation; omit with `CMCP_DEV_MODE=1` |

---

## Step 1 - Install

```bash
pip install cmcp-runtime
```

Verify:

```bash
cmcp --version
```

---

## Step 2 - Get the quickstart files

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples/startup-tpm
```

The directory contains:

```
startup-tpm/
  cmcp-config.yaml      runtime configuration
  catalog.json          one-tool catalog (test.echo)
  policy/
    manifest.json       policy bundle metadata
    allow.cedar         permit-all policy
    schema.cedarschema  Cedar schema (minimal)
  server/
    mock_mcp_server.py  mock upstream MCP server (stdlib only)
  agent/
    echo_agent.py       minimal agent script
```

---

## Step 3 - Start the mock MCP server

The runtime proxies tool calls to the upstream MCP server listed in `catalog.json` (`http://localhost:8080/mcp`). The quickstart ships a mock:

**Terminal 1:**

```bash
python server/mock_mcp_server.py
```

To protect a real MCP server instead, point `server.url` in `catalog.json` at it and recompute nothing - the catalog hash is only pinned in production mode.

---

## Step 4 - Start the runtime

Run from inside `startup-tpm/` - the `./policy` and `./catalog.json` paths in the config resolve relative to the working directory.

**Terminal 2, with hardware TPM (Azure Trusted Launch, AWS Nitro, GCP Shielded VM):**

```bash
cmcp start --config cmcp-config.yaml
```

**Without hardware TPM (local dev, CI):**

```bash
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

On Windows PowerShell:

```powershell
$env:CMCP_DEV_MODE = "1"
cmcp start --config cmcp-config.yaml
```

`CMCP_DEV_MODE=1` marks the attestation `software-only-dev-mode` in the TRACE record. The runtime is fully functional but the attestation is not hardware-backed.

Expected startup output ends with:

```
cMCP Runtime starting: TEE: software-only, listen: 127.0.0.1:8443
INFO:     Uvicorn running on http://127.0.0.1:8443
```

---

## Step 5 - Make a test tool call

**Terminal 3, Option A - agent script (recommended):**

```bash
python agent/echo_agent.py
```

Expected output:

```
[1/1] Calling test.echo ...
      -> decision: allow
      -> echoed:   hello from cMCP

Closing session <session-id> and fetching the signed TRACE Trust Record ...

=== TRACE Trust Record (signed RuntimeClaim) ===
{
  "cmcp_version": "1.0",
  "trace": { ... },
  "gateway": { ... },
  "signature": "..."
}
```

**Option B - curl:**

```bash
curl -X POST http://localhost:8443/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test.echo","arguments":{"message":"hello"}}}'
```

The response carries the echoed text plus `_cmcp` enforcement metadata:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "hello"}],
    "_cmcp": {
      "call_id": "...",
      "audit_entry_hash": "...",
      "would_have_denied": false,
      "latency_us": 12345,
      "session_id": "..."
    }
  }
}
```

---

## Step 6 - Get the TRACE Trust Record

TRACE Trust Records are sealed when a session closes. Close the session (use the `session_id` from `_cmcp`):

```bash
curl -X POST http://localhost:8443/sessions/<session_id>/close | python3 -m json.tool
```

The response is the signed `RuntimeClaim` (see `trace-output/example-trust-record.json` for a real captured example). The runtime immediately starts a fresh session, so further tool calls keep working.

You can also export the hash-chained audit log for a closed session:

```bash
curl "http://localhost:8443/audit/export?session_id=<session_id>" > bundle.json
```

---

## Step 7 - Verify the record (and try to tamper with it)

Save the claim from Step 6 to `claim.json`, then verify it:

```bash
cmcp verify claim.json --audit-bundle bundle.json
```

```
[cmcp verify] schema                   PASS
[cmcp verify] signature                PASS
[cmcp verify] attestation_freshness    PASS
[cmcp verify] audit_chain              PASS
[cmcp verify] audit_bundle             PASS  (3 entries)
[cmcp verify] RESULT: PASS (verified)
```

Now change anything - a counter, a tool name, one character - and verify again:

```bash
python3 -c "
import json
c = json.load(open('claim.json'))
c['gateway']['call_summary']['tool_calls_total'] += 1
json.dump(c, open('claim.json', 'w'))
"
cmcp verify claim.json
```

```
[cmcp verify] signature                FAIL
[cmcp verify] RESULT: FAIL (partially_verified)
```

The signature covers the whole canonical claim, so no field can be altered after the fact. The same holds for the audit bundle: editing any entry breaks both its hash chain and the bundle signature. This is the tamper-evidence guarantee in one command.

In production, pin the approved hashes so a substituted policy or catalog also fails:

```bash
cmcp verify claim.json --policy-hash sha256:<approved> --catalog-hash sha256:<approved>
```

---

## Next steps

| Goal | Where to look |
|---|---|
| Cedar escalation rules with HITL advice | `financial-services/`, `healthcare/` |
| Per-tenant policy isolation | `multi-tenant-saas/` |
| Agent-to-agent delegation (attenuated authority) | `ca2a-delegation/` |
| Hardware attestation on Azure | [Azure Trusted Launch docs](https://learn.microsoft.com/azure/virtual-machines/trusted-launch) |
| Writing your own Cedar policies | [Cedar policy language reference](https://docs.cedarpolicy.com/) |
| Protecting a real MCP server | Edit `catalog.json` to point `server.url` at your MCP server |
| Production enforcement | Unset `CMCP_DEV_MODE`; set `CMCP_BEARER_TOKEN`, `CMCP_POLICY_HASH`, `CMCP_CATALOG_HASH` |

---

## Troubleshooting

**Port 8443 already in use**

```bash
# Change listen_addr in cmcp-config.yaml, e.g.:
listen_addr: 0.0.0.0:9443
```

**`cmcp` command not found**

```bash
pip show cmcp-runtime | grep Location
# make sure pip's bin/Scripts directory is on PATH
```

**Runtime exits immediately**

`policy_bundle_path` and `catalog_path` in `cmcp-config.yaml` are resolved relative to the **working directory** you run `cmcp start` from, not the config file location. Run from inside `startup-tpm/`.

**Tool call returns 502 `UPSTREAM_UNAVAILABLE`**

The mock MCP server is not running on port 8080. Start it (Step 3).
