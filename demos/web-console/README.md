# Web console -- cMCP credit-risk assessment

A browser console for showing cMCP on a screen. It runs the **real
financial-services example** from `examples/financial-services` in this repository (an EU corporate
credit-risk agent) unmodified, behind a small web UI. Nothing here is a copy:
the tool server, Cedar policy, catalog, and agent all come from the shared example directory.

```
pip install cmcp-runtime httpx
git clone https://github.com/agentrust-io/integrations.git
cd integrations
python demos/web-console/run.py            # opens http://localhost:8000
```

`run.py` starts three local processes and opens the console:

- the example's mock EU credit-risk MCP server on `:8080`
- the cMCP gateway on `:8443` (`CMCP_DEV_MODE=1`, software-only TEE)
- this demo's web server on `:8000`

Ctrl+C stops all three. Add `--no-browser` to print the URL without opening a browser.

## What it shows

An AI agent runs a six-step credit assessment through the gateway. It reads the
client's filings, screens for sanctions, pulls a credit-bureau report,
aggregates group exposure, and runs the PD/LGD model -- then passes that outcome
into the write. Cedar enforces the bank's controls **on the result**, so the
write is only recorded if the assessment passes them. Three obligors:

| Scenario | Obligor | Write | Blocked by |
|---|---|---|---|
| Performing | Rheintal Präzisionstechnik GmbH, €250k | allowed | -- |
| Concentration breach | Nordwind Logistik AG, €750k | blocked | CRR Art. 395 / EBA/GL/2020/06 |
| Sanctions / impaired | Meridian Trading DMCC, €200k | blocked | IFRS 9 (stage 3) |

Each deny carries the regulation and reason back as structured advice. Close the
session for the signed `RuntimeClaim`, then verify it offline with `cmcp verify`
(reads `partially_verified` in software-only mode; `verified` on real TDX /
SEV-SNP).

The **Policy** tab shows the Cedar bundle the gateway loaded and maps each
guardrail to the control it enforces. **What this shows** explains the four
properties the demo proves.

## Approved vs tampered policy

The **Policy bundle** selector on the Assessment tab puts the policy-swap story
(previously the separate terminal `demo-02-policy-swap`) in the same view. Pick
**Tampered** and the console runs the agent against a second gateway holding an
edited copy of the bundle: the delegated-authority ceiling raised from €500k to
€5m, and the concentration guardrail inverted so it never fires. The tampered
copy is generated from the approved bundle at runtime, so it cannot drift from
the example.

Run **Nordwind Logistik AG (€750k)** under each:

| Bundle | Step 6, the write | Verify against the approved hash |
|---|---|---|
| Approved | `403 denied` — EBA/GL/2020/06 | `policy_bundle.hash` **PASS** |
| Tampered | `200 allow` — the write lands | `policy_bundle.hash` **FAIL** |

That is the whole argument for the record: enforcement did exactly what the
loaded policy said, so the record has to prove *which* policy was loaded.
`cmcp verify` is always pinned to the approved bundle hash — a verifier does not
get to move the goalposts after the fact.

The gateway measures the bundle at startup, so the tampered bundle needs its own
process. It starts lazily on `:8444` the first time you select **Tampered**, and
stops when the console exits. The approved gateway on `:8443` is untouched.

## How it fits together

The browser never talks to the gateway directly. `webserver.py` serves the UI
and, on **Run**, executes the example's own agent
(`examples/financial-services/agent/credit_risk_agent.py`) as a
subprocess against the gateway, then parses its output into the step timeline.
`run.py` supplies only a loopback gateway config that points at the example's
policy and catalog where they live -- it does not copy them. Changes to the shared example are exercised by the console in the same checkout.

## Files

```
web-console/
  run.py            launcher (example server + gateway + web server)
  webserver.py      static UI + /api (runs the example agent, runs cmcp verify)
  web/              index.html, app.js, styles.css
../../examples/financial-services/  the shared scenario
```
