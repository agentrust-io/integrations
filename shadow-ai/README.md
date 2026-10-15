# Shadow AI Discovery

Finds AI agents and tool use that nobody registered. It compares tool-call audit records with a separate registry that lists each agent and the tools it may use, then reports agents that are not in the registry and undeclared tool calls. The base scanner needs enriched records with agent IDs; the [cMCP adapter](#cmcp-adapter) can attribute cMCP audit records using explicit operator-controlled session bindings.

This is standalone tooling, outside the integration index and Marketplace. It
includes a cMCP audit adapter tested against the published 0.2.0 and 0.7.0 audit
APIs. It has no Agent Manifest adapter and makes no gateway/TEE verification claim.
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
| **cMCP** | `CmcpAuditAdapter` consumes `AuditChain` / `SqliteAuditStore` JSON records using a separate trusted source/session-to-agent mapping. |
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

These are enriched records: whatever produces them must supply a trustworthy `agent_id`. cMCP audit entries carry `session_id` instead of `agent_id` and name their timestamp `timestamp_utc`. `ShadowAIScanner` still does not map session identity or read `timestamp_utc`; use the separate adapter below for identity attribution. Neither class infers identity from a tool catalog. The adapter addresses the remaining identity-mapping work in [integrations#215](https://github.com/agentrust-io/integrations/issues/215).

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

## cMCP adapter

`CmcpAuditAdapter` inherits the same four scan methods and result types. Supply
bindings from an operator-controlled configuration or an authenticated session
control plane. For example, after that control plane authenticates the agent and
records the session ID returned by the selected gateway:

```python
from cmcp_shadow_ai import CmcpAuditAdapter, SessionAgentBinding

source = "billing-gateway/boot-42"
bindings = [
    SessionAgentBinding(source, "session-id-from-that-gateway", "billing-agent"),
]
scanner = CmcpAuditAdapter(
    "agents.json",
    source_id=source,
    trusted_bindings=bindings,
)
report = scanner.scan_audit_log_report("verified-billing-gateway-audit.jsonl")
```

The caller must establish that the audit stream belongs to that source and that
the session belongs to the named agent. A successful constructor does not
authenticate those assertions. The adapter does not authenticate a caller,
verify an audit signature/chain, perform attestation or read a manifest. Do not
build bindings from a tool catalog, an unverified manifest, audit fields, or an
agent's own identity assertion. Keep the agent registry and bindings outside the
audited agent's write access.

`source_id` identifies the gateway and its session namespace/epoch. Use a new
source ID if session IDs can be reused after a restart, reset or import. Keep
each input stream within its selected source; a `source_id` inside a record
cannot choose a binding. The adapter matches `(source_id, session_id)` exactly,
without trimming, case folding or prefix matching. It snapshots the supplied
bindings at construction and rejects duplicate source/session keys, including
duplicates with the same agent, so an entry cannot overwrite another identity.

For tool-call records, the adapter reports these additional unavailable reasons:

| Reason | Meaning |
|---|---|
| `session_missing` | No `session_id` field |
| `session_null` | Session ID is `null` |
| `session_blank` | Session ID is empty or whitespace-only |
| `session_non_string` | Session ID is not a string; `observed_type` reports its JSON type |
| `session_unmapped` | No binding for the selected source and exact session ID |
| `agent_conflict` | An extra `agent_id` in the record disagrees with the trusted binding |

These diagnostics have no agent ID or suggested manifest ID. Reports retain
valid findings and mark classification incomplete; strict list methods raise
`IdentityUnavailableError`. A record-supplied agent ID is never a fallback for a
missing binding. The adapter leaves input records unchanged and rejects a
non-empty malformed tool name rather than treating it as a clean scan.

Timestamp mapping remains separate from identity attribution: `timestamp` is
copied with the existing scanner semantics, and `timestamp_utc` is not mapped or
normalized. Findings from native cMCP records therefore have `timestamp=""`.
Records with non-empty tool names include denied attempts; a finding does not
establish that a tool executed or that an effect occurred.

The tested contract is JSON serialization from the **published**
`cmcp-runtime==0.2.0` and `cmcp-runtime==0.7.0` `AuditChain` and
`SqliteAuditStore` APIs. Tests install those packages with `--no-deps` because
these audit modules use the standard library. They exercise neither the full
gateway dependency stack nor a live gateway, TEE or authenticated identity
provider. Other releases are not claimed as tested. Genuine catalog/audit
fixtures and their provenance are under [tests/fixtures](tests/fixtures/README.md).

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

From the repository root:

```bash
nox -s shadow_ai shadow_ai_cmcp
```

`shadow_ai` tests the dependency-free scanner and adapter; producer tests skip
when cMCP is not installed. `shadow_ai_cmcp` runs the suite with each pinned
published cMCP release, requiring the producer tests to run. GitHub Actions runs
both releases on Python 3.11, 3.12 and 3.13.

## License

Apache 2.0
