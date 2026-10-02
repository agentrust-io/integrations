// cMCP Cedar policy for demo-04: context-aware enforcement
//
// demo-01 gates on the tool's identity (which tool may be called at all).
// This demo gates on the *context of the call*: the same capability is
// permitted inside one workflow and denied inside another. The agent cannot
// widen its own authority by choosing a different intent -- the policy checks
// the declared workflow, it does not trust the model.
//
// AGT's CedarBackend maps tool_name to a PascalCase action:
//   read_file  -> Action::"ReadFile"
//   write_file -> Action::"WriteFile"
//
// The runtime places call context on `context` (workflow_id, compliance_domain,
// baa_covered, session_max_sensitivity). Cedar is default-deny: any call with no
// matching permit is refused.

// Reads are permitted in any approved workflow. Low-risk, read-only.
permit (
  principal,
  action == Action::"ReadFile",
  resource
);

// Writes are permitted ONLY inside the approved "invoice-run" workflow.
// The identical write attempted under any other workflow has no matching
// permit and is denied by default. Same tool, same arguments, different
// context -> different decision.
permit (
  principal,
  action == Action::"WriteFile",
  resource
)
when { context.workflow_id == "invoice-run" };
