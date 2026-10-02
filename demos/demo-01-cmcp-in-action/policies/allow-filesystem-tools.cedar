// cMCP Cedar policy for demo-01
//
// AGT's CedarBackend maps tool_name to a Cedar action (PascalCase):
//   write_file -> Action::"WriteFile"
//   read_file  -> Action::"ReadFile"
//   list_dir   -> Action::"ListDir"
//
// write_file and read_file: ALLOWED
// list_dir: DENIED (demonstrates Cedar enforcement)

permit (
  principal,
  action in [Action::"WriteFile", Action::"ReadFile"],
  resource
);

forbid (
  principal,
  action == Action::"ListDir",
  resource
);
