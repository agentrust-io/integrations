// Cedar policy bundle for the Summit Brands Inc (US) tenant of PeopleGraph.
// version: summit-us-v1.0
//
// Summit is a US employer with a lighter contractual posture: US data regions
// are acceptable and a declared legal basis is not required. The tenant runs
// in ADVISORY mode, so a matched forbid is logged in the audit chain and
// surfaced as would_have_denied + advice, but the call still proceeds. This is
// the same platform and catalog as the EU tenant; only the policy bundle and
// the enforcement mode differ.

// Catch-all permit: the baseline posture is permissive.
permit (
  principal,
  action,
  resource
);

// Special-category access is flagged for privacy review (advisory only).
@id("special-category-review")
@reason("special-category-access-flagged-for-review")
@regulation("us-state-privacy")
forbid (
  principal,
  action == Action::"People.employeeRecordLookup",
  resource
) when {
  context.arguments has include_special_category &&
  context.arguments.include_special_category == true
};
