// Cedar policy bundle for hospital clinical decision support agent
// version: clinical-safety-v3.0
// author: compliance@hospital.example
//
// Action names follow the cMCP convention: the segment before the dot is
// PascalCase and each underscore segment after it is camelCase, e.g.
// ehr.treatment_plan_writer becomes Action::"Ehr.treatmentPlanWriter".
//
// There is deliberately NO catch-all permit: anything not explicitly
// permitted below is denied (Cedar default-deny). The workflow_id is supplied
// by the agent via the _cmcp request metadata; calls without it are denied.

// --- Workflow-scoped permits -------------------------------------------------

permit (
  principal,
  action == Action::"Ehr.patientRecordLookup",
  resource
) when {
  context has workflow_id && context.workflow_id == "clinical-decision-support"
};

permit (
  principal,
  action == Action::"Ehr.clinicalDecisionSupport",
  resource
) when {
  context has workflow_id && context.workflow_id == "clinical-decision-support"
};

permit (
  principal,
  action == Action::"Ehr.drugInteractionCheck",
  resource
) when {
  context has workflow_id && context.workflow_id == "clinical-decision-support"
};

permit (
  principal,
  action == Action::"Ehr.treatmentPlanWriter",
  resource
) when {
  context has workflow_id && context.workflow_id == "clinical-decision-support"
};

// --- Human oversight on writing the treatment plan ---------------------------

// EU AI Act Article 14 human oversight. Treatment plan writes for high-risk
// patients are blocked until an attending physician approves.
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

// A treatment plan carrying a severe drug interaction or allergy
// contraindication cannot be written automatically; it goes to a clinician.
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

// HIPAA PHI may only flow through an attested runtime.
@id("require-attested-runtime")
@reason("attested-runtime-required")
@regulation("hipaa-164-312")
forbid (
  principal,
  action,
  resource
) when {
  context.compliance_domain == "hipaa_phi" && context.attestation_platform == "unknown"
};
