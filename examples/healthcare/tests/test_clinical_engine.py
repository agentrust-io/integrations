from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import clinical_engine as ce  # noqa: E402

PATIENT = "P-2024-008471"


class ClinicalEngineTests(unittest.TestCase):
    def test_record_diagnoses_carry_icd10(self) -> None:
        rec = ce.patient_record(PATIENT, "full")
        codes = {d["icd10"] for d in rec["active_diagnoses"]}
        self.assertIn("E11.9", codes)  # type 2 diabetes
        self.assertIn("I10", codes)    # hypertension

    def test_record_sections_are_scoped(self) -> None:
        meds = ce.patient_record(PATIENT, "medications")
        self.assertIn("current_medications", meds)
        self.assertNotIn("labs", meds)

    def test_differential_matches_the_record(self) -> None:
        cds = ce.clinical_decision_support(PATIENT, ["fatigue"])
        top = cds["differential"][0]["condition"].lower()
        self.assertIn("diabetes", top)

    def test_appropriate_second_line_is_safe(self) -> None:
        check = ce.drug_interaction_check(PATIENT, ["empagliflozin"])
        self.assertFalse(check["has_severe_contraindication"])
        self.assertEqual(check["highest_severity"], "none")

    def test_sulfonamide_allergy_is_a_severe_contraindication(self) -> None:
        check = ce.drug_interaction_check(PATIENT, ["co-trimoxazole"])
        self.assertTrue(check["has_severe_contraindication"])
        self.assertEqual(check["contraindications"][0]["type"], "allergy")

    def test_drug_drug_interaction_is_detected(self) -> None:
        check = ce.drug_interaction_check(PATIENT, ["potassium chloride"])
        self.assertTrue(any(i["type"] == "drug-drug" for i in check["interactions"]))
        self.assertEqual(check["highest_severity"], "severe")


if __name__ == "__main__":
    unittest.main()
