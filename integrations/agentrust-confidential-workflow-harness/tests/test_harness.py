import unittest

from harness import Boundary, HarnessRunner, Observation, Outcome, Scenario
from harness.adapters.base import AdapterResult

def scenario(**overrides):
    base = dict(
        scenario_id="positive-control",
        transaction_id="txn-001",
        claim="asset A may execute under workload A and release only to recipient R",
        protected_asset="asset-A",
        workload_principal="workload-A",
        delegated_peer="peer-B",
        permitted_recipients=("recipient-R",),
        forbidden_recipients=("recipient-X",),
        policy_version="p1",
        trust_input_digest="sha256:" + "a" * 64,
        inputs={
            "workload": "workload-A",
            "key_id": "key-A",
            "policy_version": "p1",
            "software_version": "1.0.0",
            "recipient": "recipient-R",
            "response_bound": True,
        },
    )
    base.update(overrides)
    return Scenario(**base)

class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.runner = HarnessRunner()

    def test_required_boundaries_cannot_be_not_applicable(self):
        from dataclasses import replace

        class StubAdapter:
            def __init__(self, observations):
                self.observations = observations

            def run(self, scenario):
                return AdapterResult(tuple(self.observations))

        good = list(self.runner.adapter.run(scenario()).observations)
        for boundary in Boundary:
            with self.subTest(boundary=boundary):
                observations = [
                    replace(o, outcome=Outcome.NOT_APPLICABLE)
                    if o.boundary == boundary else o for o in good
                ]
                result = HarnessRunner(StubAdapter(observations)).run(scenario())
                self.assertEqual(result.status, "unknown")
        observations = [replace(o, outcome=Outcome.NOT_APPLICABLE) for o in good]
        self.assertEqual(HarnessRunner(StubAdapter(observations)).run(scenario()).status,
                         "unknown")

    def test_core_rejects_invalid_adapter_history(self):
        class StubAdapter:
            def __init__(self, observations):
                self.observations = observations

            def run(self, scenario):
                return AdapterResult(tuple(self.observations))

        good = list(self.runner.adapter.run(scenario()).observations)
        from dataclasses import replace
        cases = {
            "missing parent": [replace(good[0], caused_by="absent"), *good[1:]],
            "future parent": [replace(good[0], caused_by=good[1].source), *good[1:]],
            "duplicate source": [good[0], replace(good[1], source=good[0].source), *good[2:]],
            "late upgrade": [*good[:4], replace(good[4], outcome=Outcome.UNAVAILABLE),
                             *good[5:], replace(good[4], source="late-execution")],
            "cross-lineage parent": [replace(good[0], lineage="retry"), *good[1:]],
        }
        for name, observations in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                HarnessRunner(StubAdapter(observations)).run(scenario())

    def test_unknown_mutation_rejected_before_adapter_runs(self):
        class MustNotRun:
            def run(self, scenario):
                raise AssertionError("invalid mutation reached adapter")

        with self.assertRaisesRegex(ValueError, "mutation"):
            HarnessRunner(MustNotRun()).run(scenario(mutation="typo"))

    def test_absent_main_evidence_stays_unknown(self):
        class StubAdapter:
            def __init__(self, observations):
                self.observations = observations

            def run(self, scenario):
                return AdapterResult(tuple(self.observations))

        for observations in (
            [],
            [Observation(Boundary.AUTHORIZATION, Outcome.ESTABLISHED, "partial")],
            [Observation(b, Outcome.ESTABLISHED, b.value, lineage="retry-1") for b in Boundary],
        ):
            with self.subTest(observations=observations):
                result = HarnessRunner(StubAdapter(observations)).run(scenario())
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.boundary_outcomes["release/disclosure"], "unavailable")

    def test_forbidden_recipient_overrides_permission(self):
        bad = scenario(forbidden_recipients=("recipient-R",))
        result = self.runner.run(bad)
        self.assertEqual(result.status, "refused")
        self.assertEqual(result.boundary_outcomes["release/disclosure"], "contradicted")
        weakened = scenario(forbidden_recipients=("recipient-R",), mutation="disable_release_gate")
        self.assertEqual(self.runner.run(weakened).status, "passed")

    def test_semantic_version_admission(self):
        for version in ["0.9.9", "1.0.0-rc.1", "1.0.0-alpha", "garbage", "01.0.0", "1.0", "1.0.0-01", 12, None]:
            with self.subTest(version=version):
                result = self.runner.run(scenario(inputs={**scenario().inputs, "software_version": version}))
                self.assertEqual(result.status, "refused")
                self.assertEqual(result.boundary_outcomes["installation/admission"], "contradicted")
        for version in ["1.0.0", "1.0.0+build.1", "1.0.1", "2.0.0-rc.1", "10.0.0"]:
            with self.subTest(version=version):
                self.assertEqual(self.runner.run(scenario(inputs={**scenario().inputs, "software_version": version})).status, "passed")
        weakened = scenario(inputs={**scenario().inputs, "software_version": "1.0.0-rc.1"}, mutation="disable_version_gate")
        self.assertEqual(self.runner.run(weakened).status, "passed")

    def test_positive_control(self):
        result = self.runner.run(scenario())
        self.assertEqual(result.status, "passed")
        self.assertTrue(
            all(
                value == "established"
                for value in result.boundary_outcomes.values()
            )
        )

    def test_invalid_workload_refused(self):
        s = scenario(inputs={**scenario().inputs, "workload": "workload-X"})
        self.assertEqual(self.runner.run(s).status, "refused")

    def test_gate_weakening_is_not_same_as_valid_control(self):
        bad = scenario(inputs={**scenario().inputs, "workload": "workload-X"})
        mutated = scenario(
            inputs={**scenario().inputs, "workload": "workload-X"},
            mutation="disable_authorization_gate",
        )
        valid = scenario()
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")
        self.assertEqual(self.runner.run(valid).status, "passed")
        self.assertIsNotNone(mutated.mutation)
        self.assertIsNone(valid.mutation)

    def test_downgrade_and_mutation_proof(self):
        bad = scenario(inputs={**scenario().inputs, "software_version": "0.9.0"})
        mutated = scenario(
            inputs={**scenario().inputs, "software_version": "0.9.0"},
            mutation="disable_version_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_replay_and_mutation_proof(self):
        bad = scenario(inputs={**scenario().inputs, "replay": True})
        mutated = scenario(
            inputs={**scenario().inputs, "replay": True},
            mutation="disable_replay_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_forbidden_disclosure_and_release_gate_mutation(self):
        bad = scenario(inputs={**scenario().inputs, "recipient": "recipient-X"})
        mutated = scenario(
            inputs={**scenario().inputs, "recipient": "recipient-X"},
            mutation="disable_release_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_timeout_after_dispatch_stays_unknown(self):
        s = scenario(inputs={**scenario().inputs, "timeout_after_dispatch": True})
        result = self.runner.run(s)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.boundary_outcomes["delivery"], "established")
        self.assertEqual(result.boundary_outcomes["execution"], "unavailable")

    def test_retry_does_not_overwrite_main_lineage(self):
        s = scenario(
            inputs={
                **scenario().inputs,
                "timeout_after_dispatch": True,
                "retry_lineage": True,
            }
        )
        result = self.runner.run(s)
        self.assertEqual(result.boundary_outcomes["execution"], "unavailable")
        self.assertTrue(
            any(
                observation.lineage == "retry-1"
                and observation.outcome == Outcome.ESTABLISHED
                for observation in result.observations
            )
        )

    def test_response_parent_is_actual_main_execution(self):
        for overrides, expected_source in (
            ({}, "execution-check"),
            ({"timeout_after_dispatch": True}, "execution-unavailable"),
            ({"dispatch": False}, "execution-not-applicable"),
            ({"missing_execution_evidence": True}, "execution-check"),
        ):
            for retry in (False, True):
                with self.subTest(inputs=overrides, retry=retry):
                    result = self.runner.run(scenario(inputs={
                        **scenario().inputs, **overrides, "retry_lineage": retry,
                    }))
                    response = next(o for o in result.observations
                                    if o.boundary == Boundary.RESPONSE_VERIFICATION)
                    self.assertEqual(response.lineage, "main")
                    self.assertEqual(response.caused_by, expected_source)
                    self.assertTrue(any(
                        o.boundary == Boundary.EXECUTION
                        and o.lineage == response.lineage
                        and o.source == response.caused_by
                        for o in result.observations
                    ))

    def test_causal_parents_resolve_earlier_in_same_lineage(self):
        for overrides in ({}, {"timeout_after_dispatch": True}, {"dispatch": False},
                          {"missing_execution_evidence": True}, {"workload": "wrong"}):
            for retry in (False, True):
                with self.subTest(inputs=overrides, retry=retry):
                    result = self.runner.run(scenario(inputs={
                        **scenario().inputs, **overrides, "retry_lineage": retry,
                    }))
                    seen = set()
                    for observation in result.observations:
                        if observation.caused_by is not None:
                            self.assertIn((observation.lineage, observation.caused_by), seen)
                        seen.add((observation.lineage, observation.source))

    def test_key_substitution_and_authorization_gate_mutation(self):
        bad = scenario(inputs={**scenario().inputs, "key_id": "key-X"})
        mutated = scenario(
            inputs={**scenario().inputs, "key_id": "key-X"},
            mutation="disable_authorization_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_policy_substitution_and_authorization_gate_mutation(self):
        bad = scenario(inputs={**scenario().inputs, "policy_version": "p0"})
        mutated = scenario(
            inputs={**scenario().inputs, "policy_version": "p0"},
            mutation="disable_authorization_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_revocation_before_use_and_revocation_gate_mutation(self):
        bad = scenario(inputs={**scenario().inputs, "revoked_before_use": True})
        mutated = scenario(
            inputs={**scenario().inputs, "revoked_before_use": True},
            mutation="disable_revocation_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_bypass_egress_and_release_gate_mutation(self):
        bad = scenario(inputs={**scenario().inputs, "bypass_egress": True})
        mutated = scenario(
            inputs={**scenario().inputs, "bypass_egress": True},
            mutation="disable_release_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_response_binding_and_binding_gate_mutation(self):
        bad = scenario(inputs={**scenario().inputs, "response_bound": False})
        mutated = scenario(
            inputs={**scenario().inputs, "response_bound": False},
            mutation="disable_response_binding_gate",
        )
        self.assertEqual(self.runner.run(bad).status, "refused")
        self.assertEqual(self.runner.run(mutated).status, "passed")

    def test_missing_execution_evidence_stays_unknown(self):
        bad = scenario(inputs={**scenario().inputs, "missing_execution_evidence": True})
        weakened = scenario(
            inputs={**scenario().inputs, "missing_execution_evidence": True},
            mutation="assume_missing_execution_success",
        )
        self.assertEqual(self.runner.run(bad).status, "unknown")
        self.assertEqual(self.runner.run(bad).boundary_outcomes["execution"], "unavailable")
        self.assertEqual(self.runner.run(weakened).status, "passed")

    def test_blocked_case_keeps_milestone_incomplete(self):
        s = scenario(waiting_on_release="released disclosure API required")
        result = self.runner.run(s)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.blocked, ["released disclosure API required"])

if __name__ == "__main__":
    unittest.main()
