// Cedar policy bundle for EU corporate credit risk agent
// version: credit-risk-v5.0
// author: compliance@bank.eu
//
// Action names follow the cMCP convention: the segment before the dot is
// PascalCase and each underscore segment after it is camelCase, e.g.
// finance.risk_report_writer becomes Action::"Finance.riskReportWriter".
//
// There is deliberately NO catch-all permit: anything not explicitly
// permitted below is denied (Cedar default-deny). The workflow_id is supplied
// by the agent via the _cmcp request metadata; calls without it are denied.

// --- Workflow-scoped permits -------------------------------------------------
// The credit-risk-analyst workflow may run each step of the assessment.

permit (
  principal,
  action == Action::"Finance.documentReader",
  resource
) when {
  context has workflow_id && context.workflow_id == "credit-risk-analyst"
};

permit (
  principal,
  action == Action::"Finance.sanctionsScreening",
  resource
) when {
  context has workflow_id && context.workflow_id == "credit-risk-analyst"
};

permit (
  principal,
  action == Action::"Finance.creditBureauLookup",
  resource
) when {
  context has workflow_id && context.workflow_id == "credit-risk-analyst"
};

permit (
  principal,
  action == Action::"Finance.exposureAggregation",
  resource
) when {
  context has workflow_id && context.workflow_id == "credit-risk-analyst"
};

permit (
  principal,
  action == Action::"Finance.riskModel",
  resource
) when {
  context has workflow_id && context.workflow_id == "credit-risk-analyst"
};

permit (
  principal,
  action == Action::"Finance.riskReportWriter",
  resource
) when {
  context has workflow_id && context.workflow_id == "credit-risk-analyst"
};

// --- Guardrails on writing the assessment ------------------------------------
// Each forbid overrides the permits above and carries structured advice back
// to the caller in the deny response (error.data.advice).

// Customer due diligence must be cleared before any assessment is written.
// A sanctions or PEP hit leaves cdd_cleared false and blocks the write, so the
// gate is enforced by the runtime rather than left to the agent's good
// behaviour.
@id("cdd-clearance-required")
@reason("cdd-clearance-required")
@regulation("eu-aml-regulation-2024-1624")
forbid (
  principal,
  action == Action::"Finance.riskReportWriter",
  resource
) when {
  !(context.arguments has cdd_cleared) || context.arguments.cdd_cleared != true
};

// Facilities above the delegated lending authority require a human credit
// decision-maker (EBA loan-origination governance).
@id("delegated-authority-hitl")
@reason("human-review-required")
@regulation("eba-gl-2020-06")
@delegated_authority_limit_eur("500000")
forbid (
  principal,
  action == Action::"Finance.riskReportWriter",
  resource
) when {
  context.arguments has amount_eur && context.arguments.amount_eur > 500000
};

// The proposed facility must not breach the single-obligor concentration
// limit (the internal implementation of the CRR large-exposures regime).
@id("large-exposure-concentration")
@reason("concentration-limit-breached")
@regulation("crr-art-395")
forbid (
  principal,
  action == Action::"Finance.riskReportWriter",
  resource
) when {
  context.arguments has breaches_concentration_limit &&
  context.arguments.breaches_concentration_limit == true
};

// Credit-impaired obligors (IFRS 9 stage 3) cannot be auto-approved; they go
// to manual restructuring review.
@id("credit-impaired-manual-review")
@reason("ifrs9-stage-3-credit-impaired")
@regulation("ifrs-9")
forbid (
  principal,
  action == Action::"Finance.riskReportWriter",
  resource
) when {
  context.arguments has ifrs9_stage && context.arguments.ifrs9_stage == 3
};

// Confidential (mnpi) financial data may only flow through an attested
// runtime. attestation_platform is supplied by the runtime from the TEE
// attestation report; "unknown" means no attestation evidence is present.
@id("require-attested-runtime")
@reason("attested-runtime-required")
@regulation("dora-art-9")
forbid (
  principal,
  action,
  resource
) when {
  context.compliance_domain == "mnpi" && context.attestation_platform == "unknown"
};
