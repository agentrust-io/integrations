// Cedar policy bundle for AI/ML-based Software as a Medical Device (SaMD)
// version: radiology-fda-v1.0
// Regulatory references:
//   FDA Guidance: Artificial Intelligence/Machine Learning-Based SaMD Action Plan (2021)
//   FDA 21 CFR Part 820 (Quality System Regulation)
//   21st Century Cures Act - Real-World Evidence requirements
//   HIPAA 45 CFR Parts 160 and 164 (PHI safeguards)
//
// Cedar default-deny. workflow_id required on every call.

// Rule 1: imaging read permitted for the radiology-samd workflow.
permit (
  principal,
  action == Action::"Radiology.imagingRead",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "radiology-samd"
};

// Rule 2: AI inference permitted within the cleared indication of use.
// FDA SaMD: model may only run on imaging types within its 510(k)/DeNovo cleared scope.
permit (
  principal,
  action == Action::"Radiology.runDiagnosticInference",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "radiology-samd" &&
  context has imaging_modality &&
  ["chest-xr", "ct-thorax", "mammography"].contains(context.imaging_modality)
};

// Rule 3: diagnostic report write permitted, subject to human oversight rules below.
permit (
  principal,
  action == Action::"Radiology.writeDiagnosticReport",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "radiology-samd"
};

// Rule 4: FDA SaMD -- autonomous AI decisions on high-acuity findings require physician
// sign-off before the report is finalized. Maps to FDA guidance on human-AI teaming
// and the "Software Function" oversight category.
@id("hitl-high-acuity")
@reason("physician-review-required")
@regulation("fda-samd-action-plan-2021")
@reviewer_role("radiologist-md")
forbid (
  principal,
  action == Action::"Radiology.writeDiagnosticReport",
  resource
) when {
  context.arguments has acuity_level &&
  context.arguments.acuity_level == "critical"
};

// Rule 5: inference outside the cleared imaging modality scope is blocked.
// FDA: use outside cleared indications is an unauthorized device modification.
@id("out-of-scope-modality")
@reason("imaging-modality-outside-cleared-scope")
@regulation("fda-21-cfr-820")
forbid (
  principal,
  action == Action::"Radiology.runDiagnosticInference",
  resource
) when {
  context has imaging_modality &&
  !["chest-xr", "ct-thorax", "mammography"].contains(context.imaging_modality)
};

// Rule 6: PHI may only flow through an attested runtime.
// HIPAA 45 CFR 164.312(a)(2)(iv): encryption and decryption of PHI.
@id("require-attested-runtime")
@reason("attested-runtime-required")
@regulation("hipaa-164-312")
forbid (
  principal,
  action,
  resource
) when {
  context.data_class == "phi" &&
  context.attestation_platform == "unknown"
};
