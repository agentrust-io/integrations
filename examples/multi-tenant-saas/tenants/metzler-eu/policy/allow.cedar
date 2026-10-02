// Cedar policy bundle for the Metzler Retail GmbH (EU) tenant of PeopleGraph.
// version: metzler-eu-v1.0
//
// Metzler is an EU employer. Its data processing agreement requires EU data
// residency, a declared legal basis for processing personal data, and no
// processing of special-category data through the analytics agent. The tenant
// runs in ENFORCING mode, so these controls block the call.
//
// Action names follow the cMCP convention: the segment before the dot is
// PascalCase and each underscore segment after it is camelCase.

// Aggregate, non-identifying analytics are open to any workflow.
permit (
  principal,
  action == Action::"People.headcountAnalytics",
  resource
);

// Individual records and exports are limited to the people-analytics workflow.
permit (
  principal,
  action == Action::"People.employeeRecordLookup",
  resource
) when {
  context has workflow_id && context.workflow_id == "people-analytics"
};

permit (
  principal,
  action == Action::"People.dataExport",
  resource
) when {
  context has workflow_id && context.workflow_id == "people-analytics"
};

// Configuration changes require the admin workflow.
permit (
  principal,
  action == Action::"People.configUpdate",
  resource
) when {
  context has workflow_id && context.workflow_id == "admin-workflow"
};

// --- GDPR guardrails (enforced) ----------------------------------------------

// Processing personal data requires a declared legal basis (GDPR Art. 6).
@id("legal-basis-required")
@reason("gdpr-legal-basis-required")
@regulation("gdpr-art-6")
forbid (
  principal,
  action in [Action::"People.employeeRecordLookup", Action::"People.dataExport"],
  resource
) when {
  !(context.arguments has legal_basis)
};

// Personal data must stay in the EEA (GDPR Chapter V, Art. 44-45).
@id("data-residency-eea")
@reason("eea-data-residency-required")
@regulation("gdpr-art-44")
forbid (
  principal,
  action == Action::"People.dataExport",
  resource
) when {
  context.arguments has destination_region &&
  !(["eu-central-1", "eu-west-1", "eu-north-1", "eu-west-3"].contains(context.arguments.destination_region))
};

// Special-category data (GDPR Art. 9) must not flow through the analytics agent.
@id("special-category-block")
@reason("special-category-processing-prohibited")
@regulation("gdpr-art-9")
forbid (
  principal,
  action == Action::"People.employeeRecordLookup",
  resource
) when {
  context.arguments has include_special_category &&
  context.arguments.include_special_category == true
};
