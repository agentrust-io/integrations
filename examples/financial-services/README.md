# financial-services: EU Corporate Credit Risk Agent Demo

End-to-end demo of a corporate credit risk agent running a six-step assessment through a cMCP Runtime with Cedar policy enforcement and signed TRACE Trust Records for EU regulatory compliance (EU AI Act, CRR, EBA loan origination, EU AML, IFRS 9, DORA).

The obligor is a fictional German Mittelstand manufacturer. Identifiers are valid in format (LEI check digits per ISO 17442 / ISO 7064 MOD 97-10, German IBANs likewise), the credit bureau is Creditreform on its Bonitätsindex scale, and the guardrails act on the real output of the assessment rather than on a single hard-coded number.

---

## What the demo shows

**1. Cryptographic proof of which tools an AI agent called**
The cMCP Runtime intercepts every MCP tool call, records it in a hash-chained audit log persisted to SQLite, and seals the session into a signed `RuntimeClaim` (the TRACE Trust Record). An auditor can verify after the fact exactly which tools ran, in what order, and what was denied, without trusting the agent process.

**2. Cedar policy as machine-readable compliance**
The rules in `policy/allow.cedar` encode the bank's controls directly. Each forbid returns its `@annotation` metadata as structured advice on deny, so the calling system knows *why* the write was blocked and *who must review*.

**3. Controls that fire on the assessment result, not the request**
The agent screens the client, pulls a bureau report, aggregates group exposure and runs the PD/LGD model, then passes the outcome of those steps (CDD status, IFRS 9 stage, concentration breach, facility amount) into the write call. The Cedar guardrails act on those values, so the deny reflects the actual credit decision.

**4. Attestation-gated data access (DORA Art. 9)**
A Cedar rule forbids confidential (`mnpi`) tools when the runtime reports no attestation platform at all (`attestation_platform == "unknown"`). A software-only dev-mode runtime reports `software-only` and passes this gate, which is how the demo runs without a TEE. To require hardware attestation for `mnpi` data, forbid unless `attestation_platform` is one of the hardware platforms you accept.

---

## The workflow

```
  +------------------------------------------------------------------+
  |               Credit Risk Agent (agent/credit_risk_agent.py)     |
  +-------------------------------+----------------------------------+
                                  |  tools/call (MCP, JSON-RPC 2.0)
                                  v
  +------------------------------------------------------------------+
  |                   cMCP Runtime  :8443                            |
  |   Cedar engine (allow.cedar) | catalog checker | audit + signer  |
  +-------------------------------+----------------------------------+
                                  |  proxied tool call
                                  v
  +------------------------------------------------------------------+
  |          Mock EU Credit Risk MCP Server  :8080                  |
  |   1. finance.document_reader        annual financial statements  |
  |   2. finance.sanctions_screening    entity + UBO CDD/AML screen  |
  |   3. finance.credit_bureau_lookup   Creditreform Bonitätsindex   |
  |   4. finance.exposure_aggregation   group exposure vs limit      |
  |   5. finance.risk_model             PD/LGD/EAD, rating, IFRS 9   |
  |   6. finance.risk_report_writer     write to core banking        |
  +------------------------------------------------------------------+
```

Tool responses are computed by `credit_engine.py` from a small set of client fixtures, so the server, the tests (`tests/test_credit_engine.py`) and the agent all agree on the same data.

---

## The catalog

`catalog.json` registers the six tools with approved definitions, classifications, and definition hashes (`sha256` of the canonical JSON of `approved_definition`; the runtime rejects drifted definitions).

| Tool | compliance_domain | sensitivity_level |
|---|---|---|
| `finance.document_reader` | mnpi | confidential |
| `finance.sanctions_screening` | pii | confidential |
| `finance.credit_bureau_lookup` | pii | confidential |
| `finance.exposure_aggregation` | internal | confidential |
| `finance.risk_model` | internal | confidential |
| `finance.risk_report_writer` | internal | confidential |

---

## Run it

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples
pip install cmcp-runtime httpx
```

**Terminal 1 - mock MCP server:**

```bash
cd financial-services
python server/mock_mcp_server.py
```

**Terminal 2 - runtime** (run from inside `financial-services/` - config paths resolve relative to the working directory):

```bash
cd financial-services
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

**Terminal 3 - the three scenarios:**

```bash
# A. clean SME, EUR 250k, within limits, performing -> all six steps allow
python agent/credit_risk_agent.py --scenario clean

# B. EUR 750k, exceeds delegated authority and breaches the concentration limit
python agent/credit_risk_agent.py --scenario large-exposure

# C. a beneficial owner matches a sanctions list -> CDD does not clear
python agent/credit_risk_agent.py --scenario sanctions-hit
```

### Scenario A - clean (`clean`)

Rheintal Präzisionstechnik GmbH, EUR 250,000. CDD clears, Creditreform index 178 (very good), aggregate exposure within the limit, IFRS 9 stage 1. All six steps allow and the report is written.

### Scenario B - large exposure (`large-exposure`)

Nordwind Logistik AG, EUR 750,000. The obligor is strong, but the facility exceeds the EUR 500,000 delegated lending authority *and* pushes aggregate group exposure past the single-obligor concentration limit. The write is denied:

```
[6/6] finance.risk_report_writer ...
      -> decision: deny (POLICY_DENY)
         advice from policy:
           id: delegated-authority-hitl
           reason: human-review-required
           regulation: eba-gl-2020-06
           delegated_authority_limit_eur: 500000
```

### Scenario C - sanctions hit (`sanctions-hit`)

Meridian Trading DMCC, EUR 200,000. Sanctions screening returns a beneficial-owner match, so `cdd_cleared` stays false. Even though the agent proceeds to the write, the runtime blocks it, so the CDD gate is enforced by the runtime rather than left to the agent's good behaviour:

```
[6/6] finance.risk_report_writer ...
      -> decision: deny (POLICY_DENY)
         advice from policy:
           id: cdd-clearance-required
           reason: cdd-clearance-required
           regulation: eu-aml-regulation-2024-1624
```

---

## The Cedar policy

`policy/allow.cedar` has no catch-all permit: each tool is explicitly permitted only for the `credit-risk-analyst` workflow (declared by the agent via `_cmcp.workflow_id`). On top of the workflow-scoped permits, four guardrails forbid writing the assessment when a control fails:

| `@id` | Fires when | Regulation |
|---|---|---|
| `cdd-clearance-required` | `cdd_cleared` is not true (sanctions/PEP hit) | EU AML Regulation (EU) 2024/1624 |
| `delegated-authority-hitl` | `amount_eur > 500000` | EBA/GL/2020/06 (loan origination) |
| `large-exposure-concentration` | `breaches_concentration_limit` is true | CRR Art. 395 (large exposures) |
| `credit-impaired-manual-review` | `ifrs9_stage == 3` | IFRS 9 |
| `require-attested-runtime` | `mnpi` tool with no attestation evidence | DORA Art. 9 |

Action names follow the cMCP convention: `finance.risk_report_writer` becomes `Action::"Finance.riskReportWriter"` (the segment before the dot PascalCase, each underscore segment after it camelCase). Tool arguments are available under `context.arguments`; the `@annotation` values are returned in the deny response's `error.data.advice`.

> On the concentration limit: the CRR Art. 395 regulatory ceiling is 25% of Tier 1 capital, far larger than any single facility here. Banks implement it through a tighter internal single-obligor risk-appetite limit (EUR 2,000,000 in this demo); the runtime enforces the internal limit and cites CRR Art. 395 as the framework it implements.

---

## The TRACE Trust Records

`trace-output/` holds one signed record per scenario, captured from real runs:

| File | Result |
|---|---|
| `clean-trust-record.json` | 6 calls, 6 allowed, 0 denied |
| `large-exposure-trust-record.json` | 6 calls, 5 allowed, 1 denied |
| `sanctions-hit-trust-record.json` | 6 calls, 5 allowed, 1 denied |

Verify one (schema, signature, audit chain, and hashes pass; hardware attestation fails in software-only dev mode):

```bash
cmcp verify trace-output/large-exposure-trust-record.json
```

| TRACE field | EU AI Act | CRR / EBA | DORA | GDPR |
|---|---|---|---|---|
| `trace.policy.bundle_hash` | Art. 9 - risk mgmt system version | CRR Art. 395 controls | Art. 9 - change management | - |
| `trace.policy.version` | Art. 12 - log versioning | EBA/GL/2020/06 governance | Art. 11 - ICT change log | - |
| `trace.runtime` + `signature` | Art. 12 - tamper-evident logging | - | Art. 9 - security of ICT systems | Art. 32 - security of processing |
| `gateway.call_summary` | Art. 12 - post-hoc review data | EBA/GL/2020/06 basis of decision | Art. 17 - incident management | Art. 5(1)(c) - data minimisation |
| `trace.data_class` | Art. 10 - data governance | - | - | Art. 5(1)(b) - purpose limitation |

Export the full audit chain for a closed session:

```bash
curl "http://localhost:8443/audit/export?session_id=<id>" | python3 -m json.tool
```

---

## The tests

`tests/test_credit_engine.py` exercises the domain logic without a running server: LEI check digits, CDD clear vs hit, the Creditreform scale, exposure aggregation on both sides of the limit, and IFRS 9 staging.

```bash
python -m unittest discover -s tests -v
```

---

## Extending this example

- **Real MCP server:** point `server.url` in `catalog.json` at your endpoint; get the TLS fingerprint with `openssl s_client -connect host:443 | openssl x509 -fingerprint -sha256 -noout`.
- **Change a threshold:** edit the `when` clause and the matching `@annotation` together (e.g. the delegated-authority limit).
- **Hardware attestation:** drop `CMCP_DEV_MODE=1` on a VM with TPM 2.0 / SEV-SNP / TDX.
- **Production hardening:** set `CMCP_BEARER_TOKEN`, `CMCP_POLICY_HASH`, `CMCP_CATALOG_HASH`.

---

## Troubleshooting

**Tool call returns 502 `UPSTREAM_UNAVAILABLE`** - the mock MCP server is not running on port 8080 (Terminal 1).

**Runtime exits at startup** - config paths resolve relative to the working directory; run `cmcp start` from inside `financial-services/`.

**Cedar policy parse error** - check for stray Unicode (smart quotes) in `allow.cedar`; annotations must be `@key("value")` with double quotes.

---

## License

Apache 2.0. See [LICENSE](../LICENSE) in the repo root.
