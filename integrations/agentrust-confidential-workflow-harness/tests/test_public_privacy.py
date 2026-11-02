"""Public projection and private retention regression controls."""
from dataclasses import field, fields, make_dataclass, replace
import json
import unittest

from harness import HarnessRunner
from harness.evidence import validate_no_sensitive_values
from harness.model import Observation, RunResult
from harness.reappraisal import EvidenceSnapshot, EvaluationContext, appraise
from test_harness import scenario


class PublicPrivacyTests(unittest.TestCase):
    def test_candidate_matching_has_no_public_scenario_digest(self):
        candidates = ('ALPHA', 'BRAVO', 'CHARLIE')
        scenarios = [scenario(inputs={**scenario().inputs, 'protected_code': value})
                     for value in candidates]
        result = HarnessRunner().run(scenarios[0], observed_at=100)
        validate_no_sensitive_values(result, candidates)
        packet = result.to_dict()
        self.assertNotIn('scenario_digest', packet)
        self.assertEqual([value for value, selected in zip(candidates, scenarios)
                          if selected.digest() == packet.get('scenario_digest')], [])
        self.assertEqual(result.scenario_digest, scenarios[0].digest())

    def setUp(self):
        digest = 'sha256:' + 'a' * 64
        self.context = EvaluationContext(digest, digest, (('checker', digest),))

    def test_private_metadata_absent_for_every_terminal_status(self):
        cases = [scenario(),
                 scenario(inputs={**scenario().inputs, 'revoked_before_use': True}),
                 scenario(inputs={**scenario().inputs, 'timeout_after_dispatch': True}),
                 scenario(waiting_on_release='missing API')]
        statuses = set()
        for selected in cases:
            result = HarnessRunner().run(selected, observed_at=100)
            before = (result.scenario_digest, result.observed_at)
            public = result.to_dict()
            statuses.add(public['status'])
            self.assertNotIn('scenario_digest', public)
            self.assertNotIn('observed_at', public)
            self.assertNotIn(selected.digest(), json.dumps(public))
            self.assertEqual((result.scenario_digest, result.observed_at), before)
        self.assertEqual(statuses, {'passed', 'refused', 'unknown', 'incomplete'})

    def test_unobserved_private_input_does_not_change_public_result(self):
        public = []
        for value in ('synthetic-private-A', 'synthetic-private-B'):
            selected = scenario(inputs={**scenario().inputs, 'private_fixture': value})
            result = HarnessRunner().run(selected, observed_at=100)
            public.append(result.to_dict())
            self.assertNotIn(result.scenario_digest, json.dumps(public[-1]))
        self.assertEqual(public[0], public[1])

    def test_capture_retains_private_metadata_and_expiry(self):
        selected = scenario()
        result = HarnessRunner().run(selected, observed_at=100)
        result.to_dict()
        snapshot = EvidenceSnapshot.capture(selected, result, self.context, captured_at=105)
        private = json.loads(snapshot.result_json)
        self.assertEqual(private['scenario_digest'], selected.digest())
        self.assertEqual(private['observed_at'], 100)
        self.assertEqual(appraise(snapshot, selected, self.context,
                                 evaluated_at=109, max_age_seconds=10).applicability,
                         'applicable')
        self.assertEqual(appraise(snapshot, selected, self.context,
                                 evaluated_at=110, max_age_seconds=10).reasons,
                         ('evidence_expired',))

    def test_public_serialization_does_not_weaken_pairing(self):
        selected = scenario()
        result = HarnessRunner().run(selected, observed_at=100)
        result.to_dict()
        changed = replace(selected, inputs={**selected.inputs, 'workload': 'other'})
        with self.assertRaises(ValueError):
            EvidenceSnapshot.capture(changed, result, self.context, captured_at=100)
        legacy = replace(result, scenario_digest=None, observed_at=None)
        self.assertEqual(result.to_dict(), legacy.to_dict())
        with self.assertRaises(ValueError):
            EvidenceSnapshot.capture(selected, legacy, self.context, captured_at=100)

    def test_future_result_field_is_not_public(self):
        result = HarnessRunner().run(scenario(), observed_at=100)
        extended_type = make_dataclass(
            "ExtendedResult", [("private_note", str, field(default="synthetic-private"))],
            bases=(RunResult,))
        extended = extended_type(**{f.name: getattr(result, f.name) for f in fields(RunResult)})
        self.assertEqual(extended.to_dict(), result.to_dict())
        self.assertNotIn("synthetic-private", json.dumps(extended.to_dict()))

    def test_future_observation_field_is_not_public(self):
        result = HarnessRunner().run(scenario(), observed_at=100)
        observation = result.observations[0]
        extended_type = make_dataclass(
            "ExtendedObservation", [("private_note", str, field(default="synthetic-private"))],
            bases=(Observation,), frozen=True)
        extended = extended_type(**{f.name: getattr(observation, f.name)
                                    for f in fields(Observation)})
        changed = replace(result, observations=[extended, *result.observations[1:]])
        self.assertEqual(changed.to_dict(), result.to_dict())
        self.assertNotIn("synthetic-private", json.dumps(changed.to_dict()))

    def test_public_projection_copies_mutable_fields(self):
        result = HarnessRunner().run(scenario(), observed_at=100)
        baseline = result.to_dict()
        public = result.to_dict()
        public["mutation_proof"]["gate_weakened"] = True
        public["boundary_outcomes"].clear()
        public["blocked"].append("synthetic-extra")
        public["limitations"].append("synthetic-extra")
        public["package_versions"].clear()
        public["observations"][0]["source"] = "synthetic-other"
        self.assertEqual(result.to_dict(), baseline)
