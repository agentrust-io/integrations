// Industrial material-movement policy bundle.
// cMCP maps cell.read_safety_state to Action::"Cell.readSafetyState" and
// robot.request_motion to Action::"Robot.requestMotion".
// No catch-all permit: only the declared workflow and tools are authorized.

permit (
  principal,
  action == Action::"Cell.readSafetyState",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "industrial-material-movement"
};

permit (
  principal,
  action == Action::"Robot.requestMotion",
  resource
) when {
  context has workflow_id &&
  context.workflow_id == "industrial-material-movement"
};
