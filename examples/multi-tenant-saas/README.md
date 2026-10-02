# multi-tenant-saas: Per-Tenant Cedar Policy Isolation

PeopleGraph is a fictional HR / people-analytics SaaS. It serves two tenants on the same platform and the same tool catalog, but each tenant has its own data processing agreement, its own Cedar policy bundle, and its own enforcement mode in the cMCP Runtime.

| | `metzler-eu` | `summit-us` |
|---|---|---|
| Employer | Metzler Retail GmbH (EU) | Summit Brands Inc (US) |
| Contract | EU data residency, declared legal basis, no special-category processing | US regions allowed, no legal-basis requirement |
| Enforcement | `enforcing` (violations block) | `advisory` (violations logged, not blocked) |
| Policy version | `metzler-eu-v1.0` | `summit-us-v1.0` |

The **same four tool calls** produce different outcomes per tenant:

| Call | `metzler-eu` (enforcing) | `summit-us` (advisory) |
|---|---|---|
| `people.headcount_analytics` | allow | allow |
| `people.employee_record_lookup` (with legal basis) | allow | allow |
| `people.data_export` to `us-east-1` | **deny** (GDPR data residency) | allow |
| `people.employee_record_lookup` special-category | **deny** (GDPR Art. 9) | advisory_deny (logged) |

---

## What the demo shows

**1. Policy-as-isolation at the tool boundary**
Each tenant has its own Cedar bundle under `tenants/<name>/policy/` and its own runtime config pointing at it. The `trace.policy.version` field in each TRACE record identifies exactly which tenant policy was enforced.

**2. The tenants differ by real contract terms, not just a flag**
Metzler's EU processing agreement is encoded as three GDPR guardrails: a declared legal basis for personal-data processing (Art. 6), EEA data residency (Art. 44-45), and no special-category processing through the agent (Art. 9). Summit's US agreement carries none of those; it only flags special-category access for review. The bundles genuinely differ.

**3. Progressive posture via enforcement mode**
Metzler runs `enforcing`: a matched forbid blocks the call. Summit runs `advisory`: the same match is recorded in the audit chain and surfaced as `would_have_denied` + advice in the response metadata, but the call proceeds. The advisory record still counts the matched forbid in `gateway.call_summary.tool_calls_denied`, so an auditor sees what *would* have been blocked.

---

## File layout

```
multi-tenant-saas/
  cmcp-config-metzler-eu.yaml     enforcing -> tenants/metzler-eu/policy
  cmcp-config-summit-us.yaml      advisory  -> tenants/summit-us/policy
  catalog.json                    shared four-tool catalog
  people_directory.py             employee fixtures + tool logic (one source of truth)
  tenants/
    metzler-eu/policy/            metzler-eu-v1.0 (GDPR guardrails, enforced)
    summit-us/policy/             summit-us-v1.0 (permissive, advisory)
  server/mock_mcp_server.py       mock PeopleGraph MCP server (stdlib only)
  agent/saas_agent.py             demo agent (run this)
  tests/test_people_directory.py  unit tests
  trace-output/
    metzler-eu-example.json       real captured TRACE record (enforcing)
    summit-us-example.json        real captured TRACE record (advisory)
```

---

## The catalog

| Tool | compliance_domain | sensitivity_level |
|---|---|---|
| `people.headcount_analytics` | internal | public |
| `people.employee_record_lookup` | pii | confidential |
| `people.data_export` | pii | confidential |
| `people.config_update` | internal | public |

`people.data_export` and `people.employee_record_lookup` accept a `legal_basis` argument, `data_export` a `destination_region`, and the lookup an `include_special_category` flag. The Cedar guardrails act on those arguments.

---

## Run it

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples
pip install cmcp-runtime httpx
```

**Terminal 1 - mock MCP server:**

```bash
cd multi-tenant-saas
python server/mock_mcp_server.py
```

**Terminal 2 - runtime with Metzler's (EU) policy** (run from inside `multi-tenant-saas/`):

```bash
cd multi-tenant-saas
CMCP_DEV_MODE=1 cmcp start --config cmcp-config-metzler-eu.yaml
```

**Terminal 3 - agent:**

```bash
cd integrations/examples
python multi-tenant-saas/agent/saas_agent.py --tenant metzler-eu
```

```
[3/4] people.data_export (scope=engineering, destination_region=us-east-1)
      -> decision: deny (POLICY_DENY)
         advice from policy:
           id: data-residency-eea
           reason: eea-data-residency-required
           regulation: gdpr-art-44
[4/4] people.employee_record_lookup (employee_id=EMP-DE-4821, include_special_category=True)
      -> decision: deny (POLICY_DENY)
         advice from policy:
           id: special-category-block
           reason: special-category-processing-prohibited
           regulation: gdpr-art-9
```

**Switch tenants** - stop the runtime (Ctrl-C) and restart with Summit's (US) config:

```bash
CMCP_DEV_MODE=1 cmcp start --config cmcp-config-summit-us.yaml
python multi-tenant-saas/agent/saas_agent.py --tenant summit-us
```

```
[3/4] people.data_export (scope=engineering, destination_region=us-east-1)
      -> decision: allow
[4/4] people.employee_record_lookup (employee_id=EMP-DE-4821, include_special_category=True)
      -> decision: advisory_deny (logged, not blocked)
         advice from policy:
           id: special-category-review
           reason: special-category-access-flagged-for-review
           regulation: us-state-privacy
```

Each run ends by closing the session and printing the signed TRACE Trust Record. Compare `trace.policy.version`, `trace.policy.enforcement_mode` and `gateway.call_summary.tool_calls_denied` across the two captured examples in `trace-output/`.

---

## How the policies differ

**Metzler (`tenants/metzler-eu/policy/allow.cedar`, enforcing):** aggregate analytics are open; individual lookups and exports are gated on the `people-analytics` workflow; and three GDPR forbids block the call when a control fails:

```cedar
@id("data-residency-eea")
@reason("eea-data-residency-required")
@regulation("gdpr-art-44")
forbid (
  principal,
  action == Action::"People.dataExport",
  resource
) when {
  context.arguments has destination_region &&
  !(["eu-central-1", "eu-west-1", "eu-north-1", "eu-west-3"].contains(context.arguments.destination_region))
};
```

**Summit (`tenants/summit-us/policy/allow.cedar`, advisory):** a catch-all permit plus a single forbid that flags special-category access for review. Under advisory mode this logs and surfaces advice but does not block.

Action names follow the cMCP convention: `people.data_export` becomes `Action::"People.dataExport"` (the segment before the dot PascalCase, each underscore segment after it camelCase). Tool arguments are available under `context.arguments`; the `@annotation` values are returned in `error.data.advice` for hard denies and in `_cmcp.advice` for advisory ones.

---

## Running both tenants simultaneously

This is the production topology: one attested runtime instance per tenant isolation boundary, each measuring its own policy bundle hash into its TRACE records. Run two runtimes on different ports (edit `listen_addr` in one config) against the same mock server:

```bash
python multi-tenant-saas/agent/saas_agent.py --tenant metzler-eu --gateway http://localhost:8443
python multi-tenant-saas/agent/saas_agent.py --tenant summit-us --gateway http://localhost:9443
```

---

## The tests

`tests/test_people_directory.py` checks that headcount output is aggregate-only, that special-category is a request flag rather than emitted data, and that EEA region classification and per-region currency are correct.

```bash
python -m unittest discover -s tests -v
```

---

## License

Apache 2.0. See [LICENSE](../LICENSE) in the repo root.
