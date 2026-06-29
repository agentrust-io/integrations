from sentinel.models import SentinelOutput, Action


def generate_quarantine(output: SentinelOutput, agent_id: str) -> SentinelOutput:
    """Generate a quarantine action for high-risk detections."""
    output.quarantine_recommended = True
    output.quarantine_action = {
        "agent_id": agent_id,
        "action": Action.QUARANTINE.value,
        "blocked_tools": ["grant_permission", "delete_logs", "write_config"],
        "reason": "High risk detected"
    }
    return output
