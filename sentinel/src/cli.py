import click
import json
from src.trace_ingester import ingest_trace
from src.risk_engine import RiskEngine
from src.models import SentinelInput
from src.trace_verification import verify_trace, TraceVerificationError

@click.command()
@click.argument('trace_path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output JSON file')
@click.option('--fleet', is_flag=True, help='Treat as multi-agent fleet input')
def main(trace_path, output, fleet):
    """Run Sentinel on a trace or fleet."""
    with open(trace_path, 'r') as f:
        data = json.load(f)

    if fleet or "agents" in data:
        # Fleet mode
        # Verification gate: refuse to score/enforce on unverified trace input.
        try:
            for agent_data in data.get("agents", []):
                verify_trace(agent_data)
        except TraceVerificationError as e:
            raise click.ClickException(f"Trace verification failed: {e}")
        engine = RiskEngine()
        inputs = []
        for agent_data in data.get("agents", []):
            inp = SentinelInput(
                trace_id=agent_data.get("trace_id", "unknown"),
                agent_id=agent_data.get("agent_id", "unknown"),
                session_id=agent_data.get("session_id", "unknown"),
                policy_version=agent_data.get("policy_version", "v1"),
                delegation_chain=agent_data.get("delegation_chain", []),
                tool_calls=agent_data.get("tool_calls", []),
                observer_identity_hash=agent_data.get("observer_identity_hash", ""),
                reference_frame_hash=agent_data.get("reference_frame_hash", ""),
                timestamp=agent_data.get("timestamp", ""),
                agent_fleet=[a["agent_id"] for a in data["agents"]]
            )
            inputs.append(inp)
        result = engine.evaluate_fleet(inputs)
        output_data = result
    else:
        # Single agent
        result = ingest_trace(trace_path)
        output_data = result.model_dump()

    if output:
        with open(output, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        click.echo(f"✅ Report saved to {output}")

    # Print summary
    click.echo("\n📊 Agent Sentinel Report")
    if fleet or "agents" in data:
        click.echo(f"Fleet Risk Score: {output_data.get('fleet_risk_score', 0):.2f}")
        click.echo(f"Fleet Risk Level: {output_data.get('fleet_risk_level', 'unknown')}")
        for pattern in output_data.get("collusion_patterns", []):
            click.echo(f"  - Collusion: {pattern['description']} (risk {pattern['risk_score']:.2f})")
    else:
        click.echo(f"Risk Score: {result.risk_score:.2f}")
        click.echo(f"Risk Level: {result.risk_level}")
        click.echo(f"Quarantine Recommended: {result.quarantine_recommended}")
        if result.quarantine_recommended and result.quarantine_action:
            qa = result.quarantine_action
            click.echo(f"  Quarantine Action:")
            click.echo(f"    Agent: {qa.agent_id}")
            click.echo(f"    Reason: {qa.reason}")
            click.echo(f"    Blocked Tools: {', '.join(qa.blocked_tools)}")
            click.echo(f"    Fallback: {qa.fallback}")

    for d in (result.detections if not fleet else []):
        click.echo(f"  - {d.detection_type}: {d.risk_score:.2f} ({d.risk_level}) - {d.reason}")

if __name__ == "__main__":
    main()