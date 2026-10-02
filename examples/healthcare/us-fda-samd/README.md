# US FDA SaMD: Clinical AI Governance with TRACE

Demonstrates TRACE Trust Records for an AI/ML-based Software as a Medical Device (SaMD)
running in a US regulated context. Shows how the governance record maps to FDA SaMD Action
Plan requirements, cleared-scope enforcement, and HIPAA PHI safeguards.

**Regulatory references:** FDA AI/ML SaMD Action Plan (2021), 21 CFR Part 820, HIPAA 45 CFR 164.312.

---

## What the Cedar policy enforces

| Rule | Regulatory basis | What it blocks |
|------|-----------------|---------------|
| Default deny | -- | Anything not explicitly permitted |
| `hitl-high-acuity` | FDA SaMD Action Plan -- human-AI teaming | Autonomous writes of critical-acuity reports without physician sign-off |
| `out-of-scope-modality` | 21 CFR Part 820 -- cleared device scope | Inference on imaging types outside the cleared indication of use |
| `require-attested-runtime` | HIPAA 164.312 | PHI tool access when `attestation_platform == "unknown"` |

**Key difference from EU AI Act demo:** US focuses on cleared-scope enforcement (the SaMD
may only run on imaging modalities it was FDA-cleared for) and real-world evidence
traceability, rather than EU's risk-category human oversight model.

---

## TRACE Trust Record: key fields for FDA audit

```json
{
  "runtime": { "region": "us-east-1", "provider": "aws-nitro-enclaves" },
  "policy": { "version": "radiology-fda-v1.0", "enforcement_mode": "enforce" },
  "call_graph_summary": {
    "compliance_domains_touched": ["phi", "hipaa-164-312", "fda-samd-action-plan-2021"],
    "cleared_scope_violations": [],
    "imaging_modality_used": "chest-xr"
  }
}
```

`cleared_scope_violations: []` is the machine-readable answer to "did the SaMD operate
outside its FDA-cleared scope?" for this session.

---

## Relationship to other healthcare variants

| Variant | Jurisdiction | Key differentiator |
|---------|-------------|-------------------|
| Base demo (`../`) | EU + US | EU AI Act Art. 14 + HIPAA |
| This demo | US FDA | Cleared-scope enforcement, SaMD Action Plan |
| `../uk-nhs/` | UK | UK GDPR Art. 22, DSPT token, MHRA oversight |
| `../sg-moh/` | Singapore | IMDA Tier 1/2, PDPA consent, MOH guidelines |
