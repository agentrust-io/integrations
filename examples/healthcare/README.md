# healthcare: Clinical Decision Support Agent Demo

End-to-end demo of a hospital AI agent running a clinical assessment through a cMCP Runtime with Cedar policy enforcement and signed TRACE Trust Records for healthcare regulatory compliance (EU AI Act Art. 14, HIPAA).

The worked patient is a fictional 54-year-old with type 2 diabetes and hypertension. Diagnoses carry ICD-10 codes, medications carry dosing, and the agent runs a drug-interaction check whose result feeds the human-oversight guardrails, so a deny reflects the real safety outcome of the plan.

---

## What the demo shows

**1. EU AI Act Article 14 - human oversight for high-risk AI**
The Cedar policy blocks any treatment plan write where `patient_risk_category == "high"`. The deny response carries the policy's `@annotation` metadata as structured advice (`regulation: eu-ai-act-art-14`, `reviewer_role: attending-physician`), and the audit chain records the deny as machine-readable Art. 14 evidence.

**2. A medication-safety guardrail that fires on the assessment result**
The agent runs `ehr.drug_interaction_check` against the patient's current medications and documented allergies, then passes `has_severe_contraindication` into the write call. A Cedar rule blocks the write when a severe contraindication is present, so the guardrail acts on the actual interaction result rather than on a static flag.

**3. HIPAA PHI protection at the tool boundary**
All four tools are classified `compliance_domain: hipaa_phi` in the attested catalog. A Cedar rule forbids PHI tools when the runtime reports no attestation platform at all (`attestation_platform == "unknown"`). A software-only dev-mode runtime reports `software-only` and passes this gate, which is how the demo runs without a TEE. To require hardware attestation for PHI, forbid unless `attestation_platform` is one of the hardware platforms you accept.

**4. Cryptographic proof of the tool call sequence**
Every call is recorded in a hash-chained audit log persisted to SQLite. Closing the session seals the chain into a signed `RuntimeClaim` (the TRACE Trust Record): which tools ran, in what order, what was denied - verifiable without trusting the agent process.

**5. Three demo scenarios**
`--scenario standard` (all four calls allowed), `--scenario high-risk` (Art. 14 block on a high-risk patient), `--scenario contraindication` (a proposed drug that the patient is allergic to blocks the write).

---

## Architecture

```
  +------------------------------------------------------------------+
  |              Clinical Decision Support Agent (LLM)               |
  |   agent/clinical_decision_agent.py -- JSON-RPC 2.0 over HTTP     |
  +-------------------------------+----------------------------------+
                                  |  tools/call (MCP)
                                  v
  +------------------------------------------------------------------+
  |                   cMCP Runtime  :8443                            |
  |                                                                  |
  |  +---------------+  +------------------+  +------------------+  |
  |  | Cedar engine  |  | Catalog checker  |  | Audit chain +    |  |
  |  | allow.cedar   |  | catalog.json     |  | TRACE signer     |  |
  |  +---------------+  +------------------+  +------------------+  |
  +-------------------------------+----------------------------------+
                                  |  proxied tool call
                                  v
  +------------------------------------------------------------------+
  |          Mock Hospital EHR MCP Server  :8080                     |
  |   server/mock_mcp_server.py                                       |
  |   ehr.patient_record_lookup                                       |
  |   ehr.clinical_decision_support                                   |
  |   ehr.drug_interaction_check                                      |
  |   ehr.treatment_plan_writer                                       |
  +------------------------------------------------------------------+
```

---

## Run it

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples
pip install cmcp-runtime httpx
```

**Terminal 1 - mock EHR server:**

```bash
cd healthcare
python server/mock_mcp_server.py
```

**Terminal 2 - runtime** (run from inside `healthcare/` - config paths resolve relative to the working directory):

```bash
cd healthcare
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

**Terminal 3 - the three scenarios:**

```bash
cd integrations/examples
# A. standard: performing plan, no interaction -> all four steps allow
python healthcare/agent/clinical_decision_agent.py --scenario standard

# B. high-risk patient -> Art. 14 human-oversight block on the write
python healthcare/agent/clinical_decision_agent.py --scenario high-risk

# C. a proposed drug the patient is allergic to -> contraindication block
python healthcare/agent/clinical_decision_agent.py --scenario contraindication
```

Standard scenario:

```
Scenario: standard  |  Patient: [redacted PHI]  |  Risk category: standard

[1/4] ehr.patient_record_lookup ...
      -> decision: allow  active dx: E11.9, I10, E78.5
[2/4] ehr.clinical_decision_support ...
      -> decision: allow  Type 2 diabetes mellitus, suboptimal glycaemic control
[3/4] ehr.drug_interaction_check ...
      -> decision: allow  highest_severity=none
[4/4] ehr.treatment_plan_writer ...
      -> decision: allow
```

Contraindication scenario (the patient has a documented sulfonamide allergy, so proposing co-trimoxazole trips a severe contraindication):

```
[3/4] ehr.drug_interaction_check ...
      -> decision: allow  highest_severity=severe
[4/4] ehr.treatment_plan_writer ...
      -> decision: deny (POLICY_DENY)
         advice from policy:
           id: medication-contraindication
           reason: severe-contraindication-detected
           regulation: eu-ai-act-art-14
           reviewer_role: attending-physician

  The treatment plan was NOT written to the EHR.
  An attending physician must review and approve before the plan takes effect.
```

---

## The Cedar policy

`policy/allow.cedar` has no catch-all permit: each EHR tool is explicitly permitted only for the `clinical-decision-support` workflow (declared by the agent via `_cmcp.workflow_id`), and anything else - wrong workflow, missing workflow, unlisted action - is denied by Cedar's default-deny:

```cedar
permit (
  principal,
  action == Action::"Ehr.patientRecordLookup",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "clinical-decision-support"
};
```

On top of the workflow-scoped permits sit three forbid rules (high-risk human oversight, severe medication contraindication, and the HIPAA attestation gate). Annotations on a `forbid` are returned to the caller as structured advice when that rule causes a deny:

```cedar
@id("hitl-high-risk")
@reason("human-review-required")
@regulation("eu-ai-act-art-14")
@reviewer_role("attending-physician")
forbid (
  principal,
  action == Action::"Ehr.treatmentPlanWriter",
  resource
) when {
  context.arguments has patient_risk_category &&
  context.arguments.patient_risk_category == "high"
};
```

The second forbid blocks the write when the drug-interaction check returned a severe contraindication:

```cedar
@id("medication-contraindication")
@reason("severe-contraindication-detected")
@regulation("eu-ai-act-art-14")
@reviewer_role("attending-physician")
forbid (
  principal,
  action == Action::"Ehr.treatmentPlanWriter",
  resource
) when {
  context.arguments has has_severe_contraindication &&
  context.arguments.has_severe_contraindication == true
};
```

Action names follow the cMCP convention: `ehr.treatment_plan_writer` becomes `Action::"Ehr.treatmentPlanWriter"` (PascalCase per underscore segment). Tool arguments are available under `context.arguments`.

---

## The TRACE Trust Record

`trace-output/` holds one signed record per scenario (`standard-trust-record.json`, `high-risk-trust-record.json`, `contraindication-trust-record.json`), captured from real runs. Verify one with `cmcp verify trace-output/high-risk-trust-record.json` (schema, signature and audit chain pass; hardware attestation fails in software-only dev mode). Key fields:

| Field | Meaning |
|---|---|
| `trace.policy.bundle_hash` / `version` | Exactly which Cedar bundle was enforced (`clinical-safety-v3.0`) |
| `trace.data_class` | Highest sensitivity touched in the session (`confidential`) |
| `trace.tool_transcript.hash` | Hash of the audit chain tip covering all calls |
| `trace.cnf.jwk` | The runtime's Ed25519 signing key (verifies `signature`) |
| `gateway.call_summary` | Allowed/denied counts, tools invoked, compliance domains touched |
| `gateway.audit_chain` | Root, tip, and length of the hash-chained audit log |
| `signature` | Ed25519 signature over the canonical claim |

Export the full audit chain for a closed session:

```bash
curl "http://localhost:8443/audit/export?session_id=<id>" | python3 -m json.tool
```

---

## Regulatory field mapping

| TRACE field | EU AI Act | HIPAA |
|---|---|---|
| `trace.policy.bundle_hash` | Art. 9 - risk management system version | 45 CFR 164.312 - access controls |
| `gateway.call_summary.tool_calls_denied` | Art. 14 - human oversight record | 45 CFR 164.308(a)(1)(ii)(D) - activity review |
| `trace.data_class` | Art. 10 - data governance | 45 CFR 164.502 - minimum necessary |
| `trace.runtime` + `signature` | Art. 12 - tamper-evident logging | 45 CFR 164.312(c) - integrity |
| `trace.subject` | Art. 12 - traceability to specific run | 45 CFR 164.308(a)(5) - access monitoring |

---

## Extending this example

- **Real EHR server:** point `server.url` in `catalog.json` at your MCP server.
- **Hardware attestation:** drop `CMCP_DEV_MODE=1` on a VM with TPM 2.0 / SEV-SNP; `trace.runtime` then carries real measurements.
- **Production hardening:** set `CMCP_BEARER_TOKEN`, `CMCP_POLICY_HASH`, and `CMCP_CATALOG_HASH` (the runtime refuses to start without them outside dev mode).

---

## The tests

`tests/test_clinical_engine.py` checks that diagnoses carry ICD-10 codes, that the differential matches the record, that an appropriate second-line agent is safe, and that a sulfonamide allergy and a drug-drug interaction are both detected.

```bash
python -m unittest discover -s tests -v
```

---

## Regulatory Variants

This demo uses EU AI Act Art. 14 and HIPAA as its primary policy example. Additional
variants in subdirectories show how the same cMCP + TRACE architecture maps to other
healthcare regulatory frameworks. The Cedar policy and TRACE record fields change;
the runtime architecture does not.

| Variant | Jurisdiction | Regulatory focus |
|---------|-------------|-----------------|
| This demo | EU + US | EU AI Act Art. 14 human oversight + HIPAA PHI |
| [`us-fda-samd/`](us-fda-samd/README.md) | United States | FDA SaMD Action Plan -- cleared-scope enforcement, 21 CFR Part 820 |
| [`uk-nhs/`](uk-nhs/README.md) | United Kingdom | UK GDPR Art. 22 -- DSPT token gate, MHRA AI as medical device |
| [`sg-moh/`](sg-moh/README.md) | Singapore | IMDA AI Governance Tier 1/2 -- PDPA consent, MOH guidelines |

Each variant includes a Cedar policy file showing jurisdiction-specific rules and a
TRACE Trust Record with the `runtime.region`, `runtime.provider`, and
`compliance_domains_touched` fields set for that jurisdiction.

---

## License

Apache 2.0. See [LICENSE](../LICENSE) in the repo root.
