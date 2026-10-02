from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import people_directory as pd  # noqa: E402


class PeopleDirectoryTests(unittest.TestCase):
    def test_headcount_is_aggregate_only(self) -> None:
        h = pd.headcount_analytics()
        self.assertEqual(h["headcount_total"], len(pd.EMPLOYEES))
        # aggregate output must not leak individual names
        self.assertNotIn("name", h)
        self.assertIn("Engineering", h["headcount_by_department"])

    def test_lookup_returns_the_record(self) -> None:
        r = pd.employee_record_lookup("EMP-DE-4821")
        self.assertEqual(r["name"], "Katharina Vogel")
        self.assertEqual(r["region"], "eu-central-1")
        self.assertEqual(r["base_salary_eur"], 96_000)

    def test_special_category_is_a_request_flag_not_data(self) -> None:
        r = pd.employee_record_lookup("EMP-DE-4821", include_special_category=True)
        self.assertTrue(r["special_category_included"])
        # no actual special-category field is ever emitted
        for banned in ("health", "religion", "union", "ethnicity"):
            self.assertNotIn(banned, r)

    def test_eea_region_classification(self) -> None:
        self.assertTrue(pd.data_export("all", "eu-central-1")["destination_in_eea"])
        self.assertFalse(pd.data_export("all", "us-east-1")["destination_in_eea"])

    def test_us_employee_uses_usd(self) -> None:
        r = pd.employee_record_lookup("EMP-US-1099")
        self.assertIn("base_salary_usd", r)
        self.assertNotIn("base_salary_eur", r)


if __name__ == "__main__":
    unittest.main()
