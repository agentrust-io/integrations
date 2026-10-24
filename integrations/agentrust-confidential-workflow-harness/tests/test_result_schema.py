"""Check actual runner serialization against the published result contract."""
from dataclasses import replace
import copy
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
                self.assertEqual(emitted["scenario_digest"], selected.digest())
                self.assertEqual(emitted["observed_at"], 100)
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

    def test_partial_metadata_rejected(self):
        emitted = HarnessRunner().run(scenario(), observed_at=100).to_dict()
        for missing in ("scenario_digest", "observed_at"):
            with self.subTest(missing=missing):
                partial = copy.deepcopy(emitted)
                del partial[missing]
                with self.assertRaises(jsonschema.ValidationError):
                    VALIDATOR.validate(partial)

    def test_metadata_type_and_value_negatives(self):
        emitted = HarnessRunner().run(scenario(), observed_at=100).to_dict()
        invalid = {
            "scenario_digest": [None, True, 1, "bad", "sha256:" + "A" * 64,
                                "sha256:" + "a" * 63, "sha256:" + "a" * 64 + "\n"],
            "observed_at": [None, True, -1, 1.5, "100"],
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    changed = {**emitted, field: value}
                    with self.assertRaises(jsonschema.ValidationError):
                        VALIDATOR.validate(changed)

    def test_zero_observation_time_and_unknown_field_boundary(self):
        emitted = HarnessRunner().run(scenario(), observed_at=0).to_dict()
        self.assertTrue(VALIDATOR.is_valid(emitted))
        with self.assertRaises(jsonschema.ValidationError):
            VALIDATOR.validate({**emitted, "unregistered_metadata": True})


if __name__ == "__main__":
    unittest.main()
