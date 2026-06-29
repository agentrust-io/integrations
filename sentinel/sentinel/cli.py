import click
import json
from datetime import datetime
from sentinel.risk_engine import RiskEngine
from sentinel.models import SentinelInput


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


@click.command()
@click.argument('trace_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output JSON file for report')
def main(trace_path, output):
    with open(trace_path, 'r') as f:
        trace_data = json.load(f)

    engine = RiskEngine()

    input_data = SentinelInput(
        trace_id=trace_data.get('trace_id', 'unknown'),
        delegation_chain=trace_data.get('delegation_chain', []),
        policy_version=trace_data.get('policy_version', 'v1'),
        agent_id=trace_data.get('agent_id', 'unknown'),
        action=trace_data.get('action', 'unknown')
    )

    result = engine.evaluate(input_data)
    report = result.model_dump(mode='json')

    if output:
        with open(output, 'w') as f:
            json.dump(report, f, indent=2, cls=DateTimeEncoder)
        click.echo(f"Report written to {output}")
    else:
        click.echo(json.dumps(report, indent=2, cls=DateTimeEncoder))


if __name__ == "__main__":
    main()
