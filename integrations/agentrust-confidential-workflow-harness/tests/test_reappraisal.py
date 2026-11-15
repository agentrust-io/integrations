from dataclasses import asdict, replace
import json
import unittest
from unittest.mock import patch

from harness import HarnessRunner
from harness.model import EvidenceClass
from harness.reappraisal import EvaluationContext, EvidenceSnapshot, appraise
from test_harness import scenario


A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64
C = "sha256:" + "c" * 64


class ReappraisalTests(unittest.TestCase):
    def setUp(self):
        self.scenario = scenario()
        self.context = EvaluationContext(A, B, (("lockfile", C), ("checker", A)))
        self.result = HarnessRunner().run(self.scenario, observed_at=100)
        self.snapshot = EvidenceSnapshot.capture(
            self.scenario, self.result, self.context, captured_at=100)

    def evaluate(self, **kwargs):
        args = dict(snapshot=self.snapshot, scenario=self.scenario,
                    current=self.context, evaluated_at=109, max_age_seconds=10)
        args.update(kwargs)
        return appraise(**args)

    def test_unchanged_valid_control(self):
        self.assertEqual(self.evaluate().applicability, "applicable")
        reordered = replace(self.context, dependencies=tuple(reversed(self.context.dependencies)))
        self.assertEqual(self.evaluate(current=reordered).applicability, "applicable")

    def test_expiry_boundary_and_current_budget(self):
        for instant in (110, 111):
            with self.subTest(instant=instant):
                r = self.evaluate(evaluated_at=instant)
                self.assertEqual(r.reasons, ("evidence_expired",))
                self.assertEqual(r.applicability, "reassessment_required")
                self.assertEqual(r.historical_status, "passed")
        self.assertEqual(self.evaluate(max_age_seconds=9).reasons, ("evidence_expired",))
        self.assertEqual(self.evaluate(evaluated_at=99).reasons,
                         ("evaluation_precedes_capture",))

    def test_policy_trust_and_dependency_changes_with_valid_twins(self):
        cases = [
            (replace(self.context, policy_digest=C), "policy_changed"),
            (replace(self.context, trust_digest=C), "trust_changed"),
            (replace(self.context, dependencies=(("lockfile", A), ("checker", A))),
             "dependencies_changed"),
            (replace(self.context, dependencies=(("lockfile", C),)), "dependencies_changed"),
            (replace(self.context, dependencies=(*self.context.dependencies, ("runtime", B))),
             "dependencies_changed"),
        ]
        for changed, reason in cases:
            with self.subTest(reason=reason, changed=changed):
                self.assertEqual(self.evaluate().applicability, "applicable")
                r = self.evaluate(current=changed)
                self.assertEqual(r.reasons, (reason,))
                self.assertEqual(r.applicability, "reassessment_required")
                self.assertEqual(r.historical_status, "passed")

    def test_changed_scenario_cannot_reuse_old_evidence(self):
        for changed in (replace(self.scenario, transaction_id="other"),
                        replace(self.scenario, claim="different claim"),
                        replace(self.scenario, inputs={**self.scenario.inputs, "workload": "X"})):
            with self.subTest(changed=changed):
                self.assertEqual(self.evaluate(scenario=changed).reasons, ("scenario_changed",))

    def test_capture_rejects_same_identity_changed_scenario(self):
        changed = replace(self.scenario, inputs={**self.scenario.inputs, "workload": "X"})
        self.assertNotEqual(HarnessRunner().run(changed, observed_at=100).status, "passed")
        with self.assertRaisesRegex(ValueError, "full scenario"):
            EvidenceSnapshot.capture(changed, self.result, self.context, captured_at=100)
        self.scenario.inputs["workload"] = "X"
        with self.assertRaisesRegex(ValueError, "full scenario"):
            EvidenceSnapshot.capture(self.scenario, self.result, self.context, captured_at=100)

    def test_delayed_capture_does_not_refresh_old_observation(self):
        delayed = EvidenceSnapshot.capture(
            self.scenario, self.result, self.context, captured_at=1000)
        self.assertEqual(self.evaluate(snapshot=delayed, evaluated_at=1001).reasons,
                         ("evidence_expired",))
        fresh_result = HarnessRunner().run(self.scenario, observed_at=1000)
        fresh = EvidenceSnapshot.capture(
            self.scenario, fresh_result, self.context, captured_at=1000)
        self.assertEqual(self.evaluate(snapshot=fresh, evaluated_at=1001).applicability,
                         "applicable")

    def test_missing_invalid_or_future_observation_is_rejected(self):
        for value in (None, True, -1, 1.5, 101):
            with self.subTest(value=value), self.assertRaises(ValueError):
                EvidenceSnapshot.capture(self.scenario, replace(self.result, observed_at=value),
                                         self.context, captured_at=100)
        with self.assertRaisesRegex(ValueError, "full scenario"):
            EvidenceSnapshot.capture(self.scenario, replace(self.result, scenario_digest=None),
                                     self.context, captured_at=100)

    def test_compound_changes_do_not_mask_each_other(self):
        current = EvaluationContext(C, A, (("other", B),))
        self.scenario.inputs["workload"] = "changed"
        result = self.evaluate(current=current, evaluated_at=110)
        self.assertEqual(result.reasons, ("scenario_changed", "policy_changed", "trust_changed",
                                          "dependencies_changed", "evidence_expired"))
        self.assertEqual(result.applicability, "reassessment_required")
        self.assertEqual(result.historical_status, "passed")

    def test_fresh_run_after_change_preserves_old_snapshot(self):
        before = asdict(self.snapshot)
        changed = replace(self.context, dependencies=(("lockfile", A),))
        self.assertEqual(self.evaluate(current=changed).applicability, "reassessment_required")
        fresh = EvidenceSnapshot.capture(
            self.scenario, HarnessRunner().run(self.scenario, observed_at=110), changed, captured_at=110)
        self.assertEqual(self.evaluate(snapshot=fresh, current=changed,
                                       evaluated_at=110).applicability, "applicable")
        self.assertEqual(asdict(self.snapshot), before)

    def test_unavailable_refused_and_blocked_results_never_upgrade(self):
        for overrides in ({"inputs": {**self.scenario.inputs, "timeout_after_dispatch": True}},
                          {"inputs": {**self.scenario.inputs, "revoked_before_use": True}},
                          {"waiting_on_release": "missing API"}):
            s = scenario(**overrides)
            r = HarnessRunner().run(s, observed_at=100)
            snap = EvidenceSnapshot.capture(s, r, self.context, captured_at=100)
            result = self.evaluate(snapshot=snap, scenario=s)
            self.assertEqual(result.historical_status, r.status)
            self.assertIn("historical_result_not_passed", result.reasons)
            self.assertEqual(result.applicability, "reassessment_required")

    def test_result_is_detached_from_mutable_runner_output(self):
        retained = self.snapshot.result_json
        self.result.boundary_outcomes.clear()
        self.result.observations.clear()
        self.result.status = "refused"
        self.assertEqual(self.snapshot.result_json, retained)
        self.assertEqual(self.evaluate().historical_status, "passed")

    def test_capture_rejects_mismatched_or_weakened_results(self):
        self.result.transaction_id = "other"
        with self.assertRaises(ValueError):
            EvidenceSnapshot.capture(self.scenario, self.result, self.context, captured_at=100)
        mutated = replace(self.scenario, mutation="disable_authorization_gate")
        with self.assertRaisesRegex(ValueError, "weakened"):
            EvidenceSnapshot.capture(mutated, HarnessRunner().run(mutated, observed_at=100),
                                     self.context, captured_at=100)

    def test_capture_rejects_inconsistent_summary_and_non_synthetic_evidence(self):
        self.result.status = "unknown"
        with self.assertRaisesRegex(ValueError, "conflicts"):
            EvidenceSnapshot.capture(self.scenario, self.result, self.context, captured_at=100)
        self.result = HarnessRunner().run(self.scenario, observed_at=100)
        self.result.observations[0] = replace(
            self.result.observations[0], evidence_class=EvidenceClass.HOSTED_LIVE)
        with self.assertRaisesRegex(ValueError, "synthetic"):
            EvidenceSnapshot.capture(self.scenario, self.result, self.context, captured_at=100)

    def test_context_rejects_missing_duplicate_mutable_or_invalid_dependencies(self):
        for deps in ((), [("lock", A)], (("lock", A), ("lock", B)),
                     (("", A),), (("lock", "unknown"),), (["lock", A],)):
            with self.subTest(deps=deps), self.assertRaises(ValueError):
                EvaluationContext(A, B, deps)
        with self.assertRaises(ValueError):
            EvaluationContext("bad", B, (("lock", A),))

    def test_invalid_times_and_missing_current_context_rejected(self):
        for value in (True, -1, 1.5, float("nan"), float("inf"), "109", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.evaluate(evaluated_at=value)
        for value in (True, 0, -1, 1.5, None):
            with self.subTest(budget=value), self.assertRaises(ValueError):
                self.evaluate(max_age_seconds=value)
        with self.assertRaises(ValueError):
            self.evaluate(current=None)

    def test_tampered_snapshot_content_rejected(self):
        data = json.loads(self.snapshot.result_json)
        data["claim"] = "changed"
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.evaluate(snapshot=replace(self.snapshot, result_json=json.dumps(data)))

    def test_reappraisal_does_not_execute_adapter_or_use_wall_clock(self):
        with patch.object(HarnessRunner, "run", side_effect=AssertionError("dispatch")), \
                patch("time.time", side_effect=AssertionError("wall clock")):
            self.assertEqual(self.evaluate().applicability, "applicable")


if __name__ == "__main__":
    unittest.main()
