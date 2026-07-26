from sentinel.models import QuarantineAction, SentinelOutput

def generate_quarantine(output: SentinelOutput, agent_id: str) -> SentinelOutput:
    """If risk exceeds threshold, generate a quarantine action."""
    if output.risk_score > 0.7 and not output.quarantine_recommended:
        output.quarantine_recommended = True
        blocked_tools = []
        fallback = "human_review"
        reasons = []

        for d in output.detections:
            if d.risk_score > 0.6:
                reasons.append(d.reason)
                # Infer blocked tools from evidence
                if "tools_called" in d.evidence:
                    blocked_tools.extend([t for t in d.evidence["tools_called"] if "write" in t or "grant" in t or "delete" in t])
                if "delegation_chain" in d.evidence:
                    blocked_tools.append("delegation_escalation")

        output.quarantine_action = QuarantineAction(
            agent_id=agent_id,
            reason=" | ".join(reasons[:3]),
            blocked_tools=list(set(blocked_tools))[:5],
            fallback=fallback,
            risk_score=output.risk_score
        )
        # Set quarantine reason in output
        output.quarantine_reason = f"Risk score {output.risk_score:.2f} exceeds threshold. Agent quarantined."
    return output