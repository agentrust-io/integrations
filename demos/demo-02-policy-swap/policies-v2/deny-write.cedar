// v2 policy: read_file allowed; write_file DENIED
// This is the "swapped" policy. Its bundle hash differs from v1.
// Any verifier that pinned the v1 hash will reject TRACE claims produced
// by a cMCP instance loaded with this bundle.
//
// AGT CedarBackend maps write_file -> Action::"WriteFile"

permit (
  principal,
  action == Action::"ReadFile",
  resource
);

forbid (
  principal,
  action == Action::"WriteFile",
  resource
);
