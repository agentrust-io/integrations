// Cedar policy bundle for NHS AI deployment in radiology
// version: radiology-nhs-v1.0
// Regulatory references:
//   NHS AI Lab: Principles for the Development, Deployment and Use of AI in Health (2023)
//   MHRA guidance: Software and AI as a Medical Device (2024)
//   NHS Data Security and Protection Toolkit (DSPT) -- mandatory for NHS data access
//   UK GDPR Article 22: automated decision-making with significant effects
//
// Cedar default-deny. workflow_id required on every call.

// Rule 1: imaging read permitted for the nhs-radiology-ai workflow
// only when the DSPT access agreement token is present.
permit (
  principal,
  action == Action::"Radiology.imagingRead",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "nhs-radiology-ai" &&
  context has dspt_access_token &&
  context.dspt_access_token != ""
};

// Rule 2: inference permitted within the UKCA-marked device scope.
permit (
  principal,
  action == Action::"Radiology.runDiagnosticInference",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "nhs-radiology-ai"
};

// Rule 3: diagnostic report write permitted, subject to MHRA human oversight below.
permit (
  principal,
  action == Action::"Radiology.writeDiagnosticReport",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "nhs-radiology-ai"
};

// Rule 4: UK GDPR Article 22 -- AI decisions with significant effects on a patient
// require a qualified clinician to review before the report is issued.
// MHRA: clinically significant AI outputs must remain under qualified human oversight.
@id("ukgdpr-art22-clinician-review")
@reason("clinician-review-required")
@regulation("uk-gdpr-art-22")
@reviewer_role("reporting-radiographer-or-radiologist")
forbid (
  principal,
  action == Action::"Radiology.writeDiagnosticReport",
  resource
) when {
  context.arguments has clinical_significance &&
  context.arguments.clinical_significance == "significant"
};

// Rule 5: NHS data access requires a valid DSPT token; deny if absent.
// DSPT is a mandatory NHS England framework for data security.
@id("dspt-required")
@reason("nhs-dspt-access-agreement-required")
@regulation("nhs-dspt")
forbid (
  principal,
  action,
  resource
) when {
  context.data_class == "nhs-patient-data" &&
  !(context has dspt_access_token)
};

// Rule 6: patient data must remain within UK geographic boundary.
// UK GDPR Chapter V: international transfers require adequacy decision or SCCs.
@id("uk-data-residency")
@reason("uk-data-residency-required")
@regulation("uk-gdpr-chapter-v")
forbid (
  principal,
  action,
  resource
) when {
  context has data_residency &&
  context.data_residency != "uk-south"
};
