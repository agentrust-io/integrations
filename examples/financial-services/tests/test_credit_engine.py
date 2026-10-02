from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import credit_engine  # noqa: E402


class CreditEngineTests(unittest.TestCase):
    CLEAN = "DE-CORP-2024-00847"
    LARGE = "DE-CORP-2024-01120"
    SANCTIONED = "AE-CORP-2024-00311"

    def test_lei_check_digits_are_valid(self) -> None:
        """Every fixture LEI passes the ISO 7064 MOD 97-10 check."""
        for client in credit_engine.CLIENTS.values():
            lei = client["lei"]
            self.assertEqual(len(lei), 20, lei)
            digits = "".join(str(int(c, 36)) if c.isalpha() else c for c in lei)
            self.assertEqual(int(digits) % 97, 1, f"invalid LEI check digits: {lei}")

    def test_clean_client_clears_cdd(self) -> None:
        result = credit_engine.screen_sanctions(self.CLEAN)
        self.assertEqual(result["cdd_status"], "clear")
        self.assertEqual(result["matches"], [])

    def test_sanctioned_ubo_produces_a_hit(self) -> None:
        result = credit_engine.screen_sanctions(self.SANCTIONED)
        self.assertEqual(result["cdd_status"], "hit")
        self.assertEqual(result["matches"][0]["match_type"], "beneficial_owner")

    def test_bureau_uses_creditreform_scale_not_fico(self) -> None:
        report = credit_engine.bureau_report(self.CLEAN)
        self.assertEqual(report["bonitaetsindex"], 178)
        self.assertEqual(report["assessment"], "very_good")
        self.assertIn("100-600", report["scale"])

    def test_exposure_within_limit_does_not_breach(self) -> None:
        agg = credit_engine.aggregate_exposure(self.CLEAN, 250_000)
        self.assertEqual(agg["aggregate_exposure_eur"], 1_150_000)
        self.assertFalse(agg["breaches_concentration_limit"])

    def test_exposure_over_limit_breaches(self) -> None:
        agg = credit_engine.aggregate_exposure(self.LARGE, 750_000)
        self.assertEqual(agg["aggregate_exposure_eur"], 2_200_000)
        self.assertTrue(agg["breaches_concentration_limit"])

    def test_performing_client_is_stage_1_and_rated(self) -> None:
        model = credit_engine.run_risk_model(self.CLEAN, 250_000)
        self.assertEqual(model["ifrs9_stage"], 1)
        self.assertEqual(model["internal_rating"], "2b")
        self.assertEqual(model["ead_eur"], 250_000)
        self.assertIsNotNone(model["expected_loss_eur"])

    def test_unaudited_client_is_credit_impaired(self) -> None:
        model = credit_engine.run_risk_model(self.SANCTIONED, 200_000)
        self.assertEqual(model["ifrs9_stage"], 3)

    def test_financial_ratios_are_derived(self) -> None:
        fin = credit_engine.read_financials(self.CLEAN)
        self.assertEqual(fin["equity_ratio"], 0.4)
        self.assertEqual(fin["net_debt_to_ebitda"], 1.26)


if __name__ == "__main__":
    unittest.main()
