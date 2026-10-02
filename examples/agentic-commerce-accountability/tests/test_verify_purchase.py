from __future__ import annotations
import json
import sys
import unittest
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE))
from generate_fixtures import build  # noqa: E402
from verify_purchase import digest, verify  # noqa: E402


def rebind_request(bundle: dict, **changes: object) -> dict:
    """Change the request and re-derive every digest that covers it."""
    bundle["purchase_request"].update(changes)
    decision = bundle["policy_decision"]
    decision["request_digest"] = digest(bundle["purchase_request"])
    evidence = bundle["runtime_evidence"]
    evidence["policy_decision_digest"] = digest(decision)
    receipt = bundle["purchase_receipt"]
    receipt["request_digest"] = digest(bundle["purchase_request"])
    receipt["runtime_evidence_digest"] = digest(evidence)
    return bundle


class PurchaseVerificationTests(unittest.TestCase):
    def test_valid_purchase_is_accepted(self) -> None:
        self.assertEqual(verify(build()), [])

    def test_overspend_and_stale_link_are_rejected(self) -> None:
        bundle = build()
        bundle["purchase_request"]["amount_minor"] = 50_000
        errors = verify(bundle)
        self.assertIn("amount exceeds delegated authority", errors)
        self.assertIn("policy decision is not bound to the purchase request", errors)

    def test_merchant_substitution_is_rejected(self) -> None:
        bundle = build()
        bundle["purchase_request"]["merchant_id"] = "merchant:attacker"
        self.assertIn("merchant is outside delegated authority", verify(bundle))

    def test_runtime_must_be_the_delegate(self) -> None:
        # Every digest link can hold while the evidence names a runtime the
        # grant never delegated to. Rebind the chain so only identity differs.
        bundle = build()
        evidence = bundle["runtime_evidence"]
        evidence["runtime_identity"] = "spiffe://attacker.example/agent/other"
        bundle["purchase_receipt"]["runtime_evidence_digest"] = digest(evidence)
        self.assertEqual(
            verify(bundle), ["runtime is not the delegate named in the authority grant"]
        )

    def test_amount_must_be_a_positive_integer(self) -> None:
        for amount in (-50_000, 0, 150.5, True, "100"):
            with self.subTest(amount=amount):
                bundle = rebind_request(build(), amount_minor=amount)
                self.assertEqual(
                    verify(bundle), ["amount is not a positive integer in minor units"]
                )

    def test_ceiling_must_be_an_integer(self) -> None:
        # json.loads accepts NaN, and every integer compares false against it.
        for ceiling in (float("nan"), float("inf"), 20_000.0, None):
            with self.subTest(ceiling=ceiling):
                bundle = build()
                grant = bundle["authority_grant"]
                grant["max_amount_minor"] = ceiling
                bundle["policy_decision"]["authority_digest"] = digest(grant)
                rebind_request(bundle)
                self.assertEqual(
                    verify(bundle), ["authority grant ceiling is not an integer"]
                )

    def test_allow_list_must_be_a_list(self) -> None:
        # "merchant:hotel-example" in "merchant:hotel-example-annex" is True.
        bundle = build()
        grant = bundle["authority_grant"]
        grant["allowed_merchants"] = "merchant:hotel-example-annex"
        bundle["policy_decision"]["authority_digest"] = digest(grant)
        rebind_request(bundle)
        errors = verify(bundle)
        self.assertIn("authority grant allow-lists are not lists", errors)
        self.assertIn("merchant is outside delegated authority", errors)

    def test_committed_fixture_matches_generator(self) -> None:
        committed = json.loads((EXAMPLE / "fixtures" / "valid-purchase.json").read_text())
        self.assertEqual(committed, build())


if __name__ == "__main__":
    unittest.main()
