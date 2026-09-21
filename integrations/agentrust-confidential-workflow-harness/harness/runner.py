from __future__ import annotations
from .adapters.deterministic import DeterministicWorkflowAdapter
from .model import RunResult, Scenario
from .verdict import status, summarize

class HarnessRunner:
    def __init__(self, adapter=None):
        self.adapter = adapter or DeterministicWorkflowAdapter()

    def run(self, scenario: Scenario) -> RunResult:
        observations = list(self.adapter.run(scenario).observations)
        boundaries = summarize(observations)
        blocked = [scenario.waiting_on_release] if scenario.waiting_on_release else []
        return RunResult(
            scenario_id=scenario.scenario_id,
            transaction_id=scenario.transaction_id,
            claim=scenario.claim,
            status=status(boundaries, blocked),
            observations=observations,
            boundary_outcomes=boundaries,
            mutation_proof={
                "mutation": scenario.mutation,
                "gate_weakened": scenario.mutation is not None,
            },
            blocked=blocked,
            limitations=[
                "deterministic software adapter only",
                "does not establish live-peer or hardware acceptance",
                "does not claim cMCP or cA2A conformance",
            ],
            package_versions={
                "cmcp-runtime": "0.5.0",
                "ca2a": "0.2.0",
            },
        )
