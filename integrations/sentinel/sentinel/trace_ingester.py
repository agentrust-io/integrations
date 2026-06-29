import json
from sentinel.models import SentinelInput, SentinelOutput  # <-- added SentinelOutput
from sentinel.risk_engine import RiskEngine

def ingest_trace(trace_path: str) -> SentinelOutput:
    with open(trace_path, 'r') as f:
        data = json.load(f)

    steps = data.get("steps", [])
    if not steps:
        raise ValueError("No steps found in trace")

    first_step = steps[0]
    tool_calls = first_step.get("tool_calls", [])

    input_data = SentinelInput(
        trace_id=data.get("trace_id", "unknown"),
        agent_id=first_step.get("agent_id", "unknown"),
        session_id=first_step.get("session_id", "unknown"),
        policy_version=first_step.get("policy_version", "v1"),
        delegation_chain=first_step.get("delegation_chain", []),
        tool_calls=tool_calls,
        observer_identity_hash=first_step.get("observer_identity_hash", ""),
        reference_frame_hash=first_step.get("reference_frame_hash", ""),
        timestamp=first_step.get("timestamp", "")
    )

    engine = RiskEngine()
    return engine.evaluate(input_data)