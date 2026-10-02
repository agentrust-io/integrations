// Demo 10 -- routing a model call by the sensitivity of the data it carries.
//
// AGT's CedarBackend maps a dotted tool name to a Cedar action:
//   model.chat_completion  becomes  Action::"Model.chatCompletion"
//
// The classes below are cMCP's own vocabulary, in ascending order:
//
//   public       may go anywhere
//   pii          may leave the region once identifiers are stripped at the boundary
//   confidential must stay in the jurisdiction
//   hipaa_phi    must stay in the jurisdiction *and* off shared infrastructure
//
// The point of the ladder is the top of it. Proof makes an out-of-region call
// provable, not permissible: a residency rule still binds at confidential, and at
// hipaa_phi the jurisdiction is necessary but not sufficient.

// --- The permit ---------------------------------------------------------------

@id("model-calls-permitted")
permit (
  principal,
  action == Action::"Model.chatCompletion",
  resource
);

// --- Guardrails ---------------------------------------------------------------
// Each forbid overrides the permit and carries advice back to the caller in
// error.data.advice, which the endpoint surfaces to the developer.

// Confidential and above stay in the jurisdiction.
@id("confidential-stays-in-region")
@reason("data-residency")
forbid (
  principal,
  action == Action::"Model.chatCompletion",
  resource
) when {
  context.arguments has model_region &&
  context.arguments.model_region != "in-region" &&
  context.arguments has data_class &&
  (context.arguments.data_class == "confidential" ||
   context.arguments.data_class == "hipaa_phi")
};

// Protected health information additionally may not run on shared infrastructure,
// even inside the region. Jurisdiction is necessary but not sufficient.
@id("phi-requires-dedicated-infrastructure")
@reason("phi-isolation")
forbid (
  principal,
  action == Action::"Model.chatCompletion",
  resource
) when {
  context.arguments has data_class &&
  context.arguments.data_class == "hipaa_phi" &&
  context.arguments has model_cloud &&
  context.arguments.model_cloud != "dedicated"
};

// Identifiers are stripped at the boundary before anything classified leaves the
// region. The endpoint performs the redaction and reports it; this rule is what
// makes the report load-bearing rather than advisory.
@id("identifiers-redacted-before-egress")
@reason("identifiers-must-be-redacted")
forbid (
  principal,
  action == Action::"Model.chatCompletion",
  resource
) when {
  context.arguments has model_region &&
  context.arguments.model_region != "in-region" &&
  context.arguments has data_class &&
  context.arguments.data_class == "pii" &&
  context.arguments has contains_identifiers &&
  context.arguments.contains_identifiers == true &&
  !(context.arguments has redacted && context.arguments.redacted == true)
};
