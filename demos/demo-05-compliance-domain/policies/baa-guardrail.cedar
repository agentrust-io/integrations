// cMCP Cedar policy for demo-05: attribute-based enforcement
//
// demo-01 gates on the tool's identity (which tool by name).
// demo-04 gates on the call context (which workflow).
// This demo gates on the tool's *compliance attributes*: a tool that is not
// BAA-covered is refused, whatever it is called and whoever calls it.
//
// The runtime derives these from the catalog and places them on `context`:
//   context.compliance_domain   <- catalog entry's compliance_domain
//   context.baa_covered         <- true when the catalog entry does NOT require a BAA
//
// AGT maps tool_name -> PascalCase action:
//   write_file -> Action::"WriteFile"
//   read_file  -> Action::"ReadFile"
//   list_dir   -> Action::"ListDir"

// Baseline: the approved catalog tools may be called.
permit (
  principal,
  action in [Action::"WriteFile", Action::"ReadFile", Action::"ListDir"],
  resource
);

// Guardrail: never call a tool that is not BAA-covered.
// A Cedar forbid overrides any permit, so this holds regardless of the tool
// name or the permit above. The decision is made on the attribute, not the name.
forbid (
  principal,
  action,
  resource
)
when { context.baa_covered == false };
