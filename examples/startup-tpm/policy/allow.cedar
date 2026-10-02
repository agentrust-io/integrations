// Quickstart policy: permit all tool calls.
// Replace with your own rules before going to production.

// Rule 1: Permit any principal to call any tool.
permit (
  principal,
  action == Action::"tool_call",
  resource
);

// Rule 2: Catch-all permit for any other action type.
permit (
  principal,
  action,
  resource
);
