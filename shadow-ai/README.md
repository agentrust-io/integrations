# Shadow AI Discovery

Compares enriched tool-call audit records against a separate agent-to-tools registry and reports unregistered agents and undeclared tools. It does not read cMCP output directly; see [Inputs and limitations](#inputs-and-limitations).

This is standalone tooling, outside the integration index and Marketplace. It
has no working cMCP or Agent Manifest adapter and claims neither integration.
The source moved from `integrations/shadow-ai/` to `shadow-ai/`; update local
`PYTHONPATH` settings to `shadow-ai/src`. Run its tests with `nox -s shadow_ai`.

## What it does

For every tool-call record (a record with a non-empty `tool_name`), the scanner looks up the record's `agent_id` in the registry:

- agent not in the registry: a `DiscoveryEvent` with reason `unregistered_agent`
- agent registered, but the tool is not listed for it: a `DiscoveryEvent` with reason `undeclared_tool`
- otherwise: no finding

Each event includes the agent ID, tool name, timestamp, and a `suggested_manifest_id` derived from the agent ID, as a starting point for an operator who registers or quarantines the agent.

A tool-call record without a usable `agent_id` is never classified. The scanner does not invent an agent for it; it reports the record as identity-unavailable (see [Scan reports](#scan-reports)).

## Integration points

| Stack component | How |
|---|---|
| **cMCP** | Intended source of tool-call audit records, once they are enriched with a trustworthy agent identity. Not consumed directly today; see [Inputs and limitations](#inputs-and-limitations). |
| **Agent Manifest** | `suggested_manifest_id` is a naming hint for registering a discovered agent. The scanner does not read, write or validate Agent Manifest records. |

## Inputs and limitations

### Agent registry

A JSON file mapping each agent ID to the tools it may call, in either form:

```json
{"agents": [{"id": "billing-agent", "tools": ["get_invoice", "list_invoices"]}]}
```

```json
{"billing-agent": ["get_invoice", "list_invoices"]}
```

The registry is maintained separately from cMCP. A cMCP `catalog.json` is a tool catalog, not an agent registry, and cannot supply agent identity; the cMCP v0.2.0 catalog (a top-level JSON array) is rejected with `ValueError`.

### Audit records

JSON objects, passed as a list or read from a JSONL file (one object per line):

| Field | Meaning |
|---|---|
| `tool_name` | Marks a tool-call record. Records where it is absent or empty are skipped as non-tool-call records. |
| `agent_id` | Required on tool-call records. Usable only if it is a string that is not empty or whitespace-only; used verbatim, never trimmed, lowercased or converted from another type. |
| `timestamp` | Optional. Copied as-is into results, `""` if absent. Not parsed, validated or normalized, and its type is not checked at runtime: a non-string value is copied unchanged. |

These are enriched records: whatever produces them must supply a trustworthy `agent_id`. cMCP v0.2.0 audit entries carry no `agent_id` and name their timestamp `timestamp_utc`, so they cannot be scanned directly. The scanner does not map `session_id` to an agent, does not read `timestamp_utc`, and does not infer identity from the tool catalog. Direct cMCP compatibility is not claimed until an adapter with a trustworthy session-to-agent mapping exists and is tested ([integrations#215](https://github.com/agentrust-io/integrations/issues/215)).

JSONL files are read with Python's default text encoding (`Path.read_text()`). Lines are split only on `\n`, `\r\n` and `\r`; blank lines are skipped but still counted, so reported line numbers are physical line numbers. A line that is not valid JSON raises `json.JSONDecodeError`, and a record that is not a JSON object raises `AttributeError`; both stop the scan, from every method.

## Install

No runtime dependencies beyond the Python standard library. Runs as a post-processor over enriched audit logs.

## Usage

```python
from shadow_ai_discovery import ShadowAIScanner

scanner = ShadowAIScanner(catalog_path="agents.json")

report = scanner.scan_audit_log_report("enriched-audit.jsonl")
for event in report.findings:
    print(event.agent_id, event.tool_name, event.reason)
if not report.complete:
    for item in report.unavailable:
        print(f"unclassified tool call at {item.location_kind} {item.location}: {item.reason}")
```

## Methods

| Method | Returns | Tool-call record without a usable `agent_id` |
|---|---|---|
| `scan_records(records)` | `list[DiscoveryEvent]` | raises `IdentityUnavailableError` |
| `scan_records_report(records)` | `ScanReport` | listed in `unavailable`, by 0-based list index |
| `scan_audit_log(path)` | `list[DiscoveryEvent]` | raises `IdentityUnavailableError` |
| `scan_audit_log_report(path)` | `ScanReport` | listed in `unavailable`, by 1-based physical line number |

All four share one classifier, so for the same records they produce the same findings. The list-returning methods never return a list that silently omits unclassifiable tool calls. `IdentityUnavailableError` is a `ValueError` subclass; its `report` attribute holds the complete `ScanReport`, including every valid finding, and its message lists up to five locations with reason codes, never the rejected value.

## Scan reports

`ScanReport` has two stored fields and one derived property:

| Attribute | Kind | Type | Description |
|---|---|---|---|
| `findings` | field | `tuple[DiscoveryEvent, ...]` | Findings for tool-call records with a usable `agent_id`, in input order |
| `unavailable` | field | `tuple[IdentityUnavailable, ...]` | Tool-call records that could not be classified, in input order |
| `complete` | property | `bool` | Derived from `unavailable` rather than stored, so it cannot disagree with it. `True` only if no successfully processed tool-call record was unclassifiable because of unavailable identity |

`complete` does not certify that the audit source itself is complete. It says nothing about records that were never written, truncated files, or records skipped as non-tool-call records.

`IdentityUnavailable` fields:

| Field | Type | Description |
|---|---|---|
| `location_kind` | `str` | `"index"` for in-memory records, `"line"` for JSONL files |
| `location` | `int` | 0-based list index, or 1-based physical line number |
| `tool_name` | `str` | Tool name from the record |
| `timestamp` | `str` | `timestamp` from the record, `""` if absent; copied without type validation |
| `reason` | `str` | `"missing"` (no `agent_id` key), `"null"`, `"blank"` (empty or whitespace-only string) or `"non_string"` |
| `observed_type` | `str` or `None` | JSON type of the rejected value (`"number"`, `"boolean"`, `"array"`, `"object"`) when `reason` is `"non_string"`, otherwise `None` |

It has no `agent_id` or `suggested_manifest_id`. `ScanReport.to_dict()` returns `{"complete": ..., "findings": [...], "unavailable": [...]}`, using each item's own `to_dict()`.

## DiscoveryEvent fields

| Field | Type | Description |
|---|---|---|
| `agent_id` | `str` | Agent that made the call, verbatim from the record |
| `tool_name` | `str` | Tool name called |
| `timestamp` | `str` | `timestamp` from the record, as-is, `""` if absent; copied without type validation |
| `reason` | `str` | `"unregistered_agent"` or `"undeclared_tool"` |
| `suggested_manifest_id` | `str` | `agent_id` lowercased, every character outside `[a-z0-9-]` replaced with `-`, leading and trailing `-` removed. A naming hint, not validated against the Agent Manifest schema; empty if `agent_id` has no such characters |

## Compatibility change

`scan_records` and `scan_audit_log` now raise `IdentityUnavailableError` for any tool-call record without a usable `agent_id`. Previously:

- a missing `agent_id` was replaced with the literal agent ID `"unknown"` and classified like any other agent. Usually that produced an `unregistered_agent` finding, but if the registry listed `"unknown"`, the call was reported as `undeclared_tool` or not reported at all, so the missing identity went unnoticed;
- an empty or whitespace-only `agent_id` was likewise classified as an agent ID. Usually that produced an `unregistered_agent` finding with an empty `suggested_manifest_id`, but if the registry held the same blank key, the call was reported as `undeclared_tool` or not reported at all;
- a `null` or non-string `agent_id` raised `AttributeError` or `TypeError`.

Results for records with a usable `agent_id` are unchanged.

JSONL lines are now split only on line breaks. Previously a character such as U+2028 inside a JSON string, which JSON allows unescaped, could split a valid record apart and raise `json.JSONDecodeError`.

## Running tests

```bash
python -m pytest tests/ -v
```

## License

Apache 2.0
