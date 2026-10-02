# Singapore MOH: Clinical AI Governance with TRACE

Demonstrates TRACE Trust Records for an AI healthcare deployment in Singapore. Shows how
the governance record maps to IMDA AI Governance Framework Tier 1/2 classification,
Singapore MOH AI in Healthcare guidelines, PDPA consent requirements, and HSA medical
device registration obligations.

**Regulatory references:** IMDA AI Governance Framework v2 (2020), MOH Singapore AI in
Healthcare Guidelines (2023), PDPA 2012, HSA guidance on AI/ML-based medical devices.

---

## What the Cedar policy enforces

| Rule | Regulatory basis | What it blocks |
|------|-----------------|---------------|
| Default deny | -- | Anything not explicitly permitted |
| `imda-tier1-human-review` | IMDA AI Governance Framework v2 -- Tier 1 (consequential) | Final diagnostic outputs without `human_review_token` when `imda_tier == "tier1"` |
| `pdpa-consent-required` | PDPA 2012 -- sensitive personal data | Imaging reads when no `patient_consent_ref` is present in context |
| `sg-data-residency` | PDPA Part 9 -- cross-border transfer obligations | Calls where `data_residency != "ap-southeast-1"` |

**Key difference from EU/US demos:** IMDA's two-tier model is explicit in the policy --
`imda_tier` is a context field on every tool call. Tier 1 (consequential decisions, e.g.
diagnosis affecting treatment) requires human review unconditionally. Tier 2
(non-consequential) does not. This is a different gating model than the EU risk-category
or US acuity-level approaches. PDPA consent reference is also enforced at the call layer,
not just at data collection time.

---

## TRACE Trust Record: key fields for MOH / PDPA audit

```json
{
  "runtime": { "region": "ap-southeast-1", "provider": "aws-nitro-enclaves" },
  "policy": { "version": "radiology-sg-v1.0", "enforcement_mode": "enforce" },
  "call_graph_summary": {
    "compliance_domains_touched": ["sensitive-personal-data", "imda-ai-governance-framework-v2", "pdpa-2012"],
    "data_residency_violations": [],
    "consent_ref_present": true,
    "imda_tier": "tier1"
  }
}
```

`imda_tier: "tier1"` in the record confirms the session was treated as a consequential
decision -- meaning the human review gate was active for the duration of the session.

---

## Relationship to other healthcare variants

| Variant | Jurisdiction | Key differentiator |
|---------|-------------|-------------------|
| Base demo (`../`) | EU + US | EU AI Act Art. 14 + HIPAA |
| `../us-fda-samd/` | US FDA | Cleared-scope enforcement, SaMD Action Plan |
| `../uk-nhs/` | UK | UK GDPR Art. 22, DSPT token gate, MHRA oversight |
| This demo | Singapore | IMDA Tier 1/2 consequential-decision gate, PDPA consent |
