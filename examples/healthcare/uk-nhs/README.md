# UK NHS: Clinical AI Governance with TRACE

Demonstrates TRACE Trust Records for an NHS AI deployment in radiology. Shows how the
governance record maps to MHRA medical device guidance, UK GDPR Article 22 automated
decision-making requirements, and NHS Data Security and Protection Toolkit (DSPT) obligations.

**Regulatory references:** NHS AI Lab Principles (2023), MHRA Software and AI as a Medical
Device (2024), UK GDPR Article 22, NHS DSPT.

---

## What the Cedar policy enforces

| Rule | Regulatory basis | What it blocks |
|------|-----------------|---------------|
| Default deny | -- | Anything not explicitly permitted |
| `ukgdpr-art22-clinician-review` | UK GDPR Art. 22 -- significant automated decisions | Reports with `clinical_significance == "significant"` without clinician review token |
| `dspt-required` | NHS DSPT | Any access to NHS patient data without a DSPT access token in context |
| `uk-data-residency` | UK GDPR Chapter V | Calls where `data_residency != "uk-south"` |

**Key difference from EU AI Act demo:** UK focuses on the DSPT access token as a
runtime enforcement gate (not just configuration), and UK GDPR Art. 22 requires clinician
review for any "significant" AI output rather than EU's risk-category model. UKCA marking
(UK conformity, post-Brexit equivalent of CE) also applies to the device scope.

---

## TRACE Trust Record: key fields for MHRA / NHS audit

```json
{
  "runtime": { "region": "uk-south", "provider": "azure-confidential-compute" },
  "policy": { "version": "radiology-nhs-v1.0", "enforcement_mode": "enforce" },
  "call_graph_summary": {
    "compliance_domains_touched": ["nhs-patient-data", "uk-gdpr-art-22", "nhs-dspt"],
    "data_residency_violations": [],
    "dspt_token_present": true
  }
}
```

`dspt_token_present: true` and `data_residency_violations: []` are the two key fields
an NHS Digital or MHRA auditor checks first.

---

## Relationship to other healthcare variants

| Variant | Jurisdiction | Key differentiator |
|---------|-------------|-------------------|
| Base demo (`../`) | EU + US | EU AI Act Art. 14 + HIPAA |
| `../us-fda-samd/` | US FDA | Cleared-scope enforcement, SaMD Action Plan |
| This demo | UK | UK GDPR Art. 22, DSPT token gate, MHRA oversight |
| `../sg-moh/` | Singapore | IMDA Tier 1/2, PDPA consent, MOH guidelines |
