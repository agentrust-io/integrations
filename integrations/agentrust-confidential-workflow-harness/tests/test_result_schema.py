"""Check actual runner serialization against the published result contract."""
from dataclasses import replace
import json
from pathlib import Path
import unittest

import jsonschema

from harness import HarnessRunner
from harness.reappraisal import EvidenceSnapshot, EvaluationContext
from test_harness import scenario


SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "result.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


class ResultSchemaTests(unittest.TestCase):
    def test_schema_is_well_formed(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)

    def test_emitted_results_validate_for_every_terminal_status(self):
        cases = [
            (scenario(), "passed"),
            (scenario(inputs={**scenario().inputs, "revoked_before_use": True}), "refused"),
            (scenario(inputs={**scenario().inputs, "timeout_after_dispatch": True}), "unknown"),
            (scenario(waiting_on_release="missing API"), "incomplete"),
        ]
        for selected, expected in cases:
            with self.subTest(status=expected):
                emitted = HarnessRunner().run(selected, observed_at=100).to_dict()
                self.assertEqual(emitted["status"], expected)
                self.assertNotIn("scenario_digest", emitted)
                self.assertNotIn("observed_at", emitted)
                self.assertTrue(VALIDATOR.is_valid(emitted))

    def test_legacy_output_omits_metadata_but_is_not_reappraisable(self):
        selected = scenario()
        result = replace(HarnessRunner().run(selected, observed_at=100),
                         scenario_digest=None, observed_at=None)
        legacy = result.to_dict()
        self.assertNotIn("scenario_digest", legacy)
        self.assertNotIn("observed_at", legacy)
        self.assertTrue(VALIDATOR.is_valid(legacy))
        digest = "sha256:" + "a" * 64
        context = EvaluationContext(digest, digest, (("checker", digest),))
        with self.assertRaises(ValueError):
            EvidenceSnapshot.capture(selected, result, context, captured_at=100)

    def test_internal_metadata_rejected_by_public_schema(self):
        emitted = HarnessRunner().run(scenario(), observed_at=100).to_dict()
        metadata = {"scenario_digest": scenario().digest(), "observed_at": 100}
        for additions in ({"scenario_digest": metadata["scenario_digest"]},
                          {"observed_at": 100}, metadata):
            with self.subTest(fields=tuple(additions)):
                with self.assertRaises(jsonschema.ValidationError):
                    VALIDATOR.validate({**emitted, **additions})

    def test_zero_observation_time_and_unknown_field_boundary(self):
        emitted = HarnessRunner().run(scenario(), observed_at=0).to_dict()
        self.assertTrue(VALIDATOR.is_valid(emitted))
        with self.assertRaises(jsonschema.ValidationError):
            VALIDATOR.validate({**emitted, "unregistered_metadata": True})


if __name__ == "__main__":
    unittest.main()
