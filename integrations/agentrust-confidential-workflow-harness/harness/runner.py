from __future__ import annotations
import time
from .adapters.deterministic import DeterministicWorkflowAdapter
from .model import RunResult, Scenario
from .verdict import status, summarize

SUPPORTED_MUTATIONS = frozenset({
    "disable_authorization_gate", "disable_version_gate", "disable_revocation_gate",
    "disable_replay_gate", "assume_missing_execution_success",
    "disable_response_binding_gate", "disable_release_gate",
})

class HarnessRunner:
    def __init__(self, adapter=None):
        self.adapter = adapter or DeterministicWorkflowAdapter()

    def run(self, scenario: Scenario, *, observed_at: int | None = None) -> RunResult:
        # The timestamp is fixed at run entry, never at later snapshot capture.
        if observed_at is None:
            observed_at = int(time.time())
        if type(observed_at) is not int or observed_at < 0:
            raise ValueError("observation time must be a non-negative integer UTC Unix second")
        scenario_digest = scenario.digest()
        if scenario.mutation is not None and scenario.mutation not in SUPPORTED_MUTATIONS:
            raise ValueError(f"unsupported mutation: {scenario.mutation!r}")
        observations = list(self.adapter.run(scenario).observations)
        if scenario.digest() != scenario_digest:
            raise ValueError("scenario changed during run")
        boundaries = summarize(observations)
        blocked = [scenario.waiting_on_release] if scenario.waiting_on_release else []
        return RunResult(
            scenario_digest=scenario_digest,
            observed_at=observed_at,
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
                "ca2a-runtime": "0.2.0",
            },
        )
