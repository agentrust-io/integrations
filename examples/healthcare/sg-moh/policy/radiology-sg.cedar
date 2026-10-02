// Cedar policy bundle for AI in healthcare -- Singapore
// version: radiology-sg-v1.0
// Regulatory references:
//   MOH Singapore: Artificial Intelligence in Healthcare Guidelines (2023)
//   IMDA AI Governance Framework v2 (2020) -- Tier 1/2 risk classification
//   PDPA (Personal Data Protection Act 2012) -- health data as sensitive personal data
//   HSA (Health Sciences Authority): guidance on AI/ML-based medical devices
//
// Cedar default-deny. workflow_id required on every call.
// IMDA Tier 1 = consequential, Tier 2 = non-consequential.
// Radiology diagnosis is Tier 1 (consequential decision).

// Rule 1: imaging read permitted for the sg-radiology-ai workflow.
permit (
  principal,
  action == Action::"Radiology.imagingRead",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "sg-radiology-ai"
};

// Rule 2: inference permitted within HSA-registered device scope.
permit (
  principal,
  action == Action::"Radiology.runDiagnosticInference",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "sg-radiology-ai"
};

// Rule 3: report write permitted, subject to human oversight rules below.
permit (
  principal,
  action == Action::"Radiology.writeDiagnosticReport",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "sg-radiology-ai"
};

// Rule 4: IMDA Tier 1 (consequential decisions) -- all final diagnostic outputs
// require human review before release. MOH guidelines: AI must augment, not replace,
// clinical judgment for consequential decisions.
@id("imda-tier1-human-review")
@reason("human-review-required-for-tier1-decision")
@regulation("imda-ai-governance-framework-v2")
@reviewer_role("radiologist")
forbid (
  principal,
  action == Action::"Radiology.writeDiagnosticReport",
  resource
) when {
  context.arguments has imda_tier &&
  context.arguments.imda_tier == "tier1" &&
  !(context has human_review_token)
};

// Rule 5: PDPA -- health data is sensitive personal data requiring explicit consent
// record. Deny access if no consent reference is present in context.
@id("pdpa-consent-required")
@reason("pdpa-sensitive-data-consent-required")
@regulation("pdpa-2012")
forbid (
  principal,
  action == Action::"Radiology.imagingRead",
  resource
) when {
  context.data_class == "sensitive-personal-data" &&
  !(context has patient_consent_ref)
};

// Rule 6: health data must remain within Singapore or countries with equivalent
// PDPA protection. Singapore has not granted adequacy to all jurisdictions.
@id("sg-data-residency")
@reason("pdpa-cross-border-transfer-requires-protection")
@regulation("pdpa-2012-part-9")
forbid (
  principal,
  action,
  resource
) when {
  context has data_residency &&
  context.data_residency != "ap-southeast-1"
};
