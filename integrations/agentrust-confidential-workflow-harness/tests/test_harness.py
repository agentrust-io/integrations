import unittest

from harness import HarnessRunner, Outcome, Scenario

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

    def test_positive_control(self):
        result = self.runner.run(scenario())
        self.assertEqual(result.status, "passed")
        self.assertTrue(
            all(
                value in {"established", "not_applicable"}
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
