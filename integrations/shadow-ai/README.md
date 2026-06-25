# Shadow AI Discovery

Detects unregistered agents making MCP tool calls not declared in a cMCP `catalog.json`, and maps findings to Agent Manifest records for remediation or quarantine.

## What it does

Shadow AI Discovery watches a cMCP audit log (JSONL) and compares every `tool_call` event against the set of tool names declared in a `catalog.json`. Any call from an agent not registered in the catalog, or using a tool not listed for that agent, is emitted as a `DiscoveryEvent`. Each event includes the agent ID, tool name, timestamp, and a suggested Agent Manifest `agent_id` field to help operators register or quarantine the offending agent.

## Integration points

| Stack component | How |
|---|---|
| **cMCP** | Reads audit log; compares tool names against `catalog.json` entries |
| **Agent Manifest** | Emits `agent_id` and tool schema fields ready for manifest registration |

## Install

```bash
pip install pyyaml
```

No other runtime dependencies. Designed to run as a sidecar or post-processor alongside the cMCP gateway.

## Usage

```python
from shadow_ai_discovery import ShadowAIScanner

scanner = ShadowAIScanner(catalog_path="catalog.json")

# Scan a cMCP audit log
events = scanner.scan_audit_log("cmcp-audit.jsonl")
for event in events:
    print(event.agent_id, event.tool_name, event.reason)
```

## DiscoveryEvent fields

| Field | Type | Description |
|---|---|---|
| `agent_id` | `str` | Agent that made the call |
| `tool_name` | `str` | Tool name called |
| `timestamp` | `str` | ISO-8601 timestamp from the audit log |
| `reason` | `str` | `"unregistered_agent"` or `"undeclared_tool"` |
| `suggested_manifest_id` | `str` | Sanitized ID suitable for an Agent Manifest `agent_id` field |

## Running tests

```bash
python -m pytest tests/ -v
```

## License

Apache 2.0
