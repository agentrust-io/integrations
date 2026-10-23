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
        for ceiling in (20_000.0, None, True, 0, -1):
            with self.subTest(ceiling=ceiling):
                bundle = build()
                grant = bundle["authority_grant"]
                grant["max_amount_minor"] = ceiling
                bundle["policy_decision"]["authority_digest"] = digest(grant)
                rebind_request(bundle)
                self.assertEqual(
                    verify(bundle), ["authority grant ceiling is not an integer"]
                )
        for ceiling in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(ceiling=ceiling):
                bundle = build()
                bundle["authority_grant"]["max_amount_minor"] = ceiling
                errors = verify(bundle)
                self.assertIn("authority grant ceiling is not an integer", errors)
                self.assertIn(
                    "policy decision is not bound to the authority grant", errors
                )

    def test_digest_rejects_nonfinite_values(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    digest({"x": bad})

    def test_malformed_sections_are_rejected(self) -> None:
        for non_obj in ([], None, "not-an-object", 42):
            with self.subTest(bundle=non_obj):
                self.assertEqual(verify(non_obj), ["bundle must be a JSON object"])  # type: ignore[arg-type]
        for section in (
            "authority_grant",
            "purchase_request",
            "policy_decision",
            "runtime_evidence",
            "purchase_receipt",
        ):
            for bad_section in (None, [], "string", 123):
                with self.subTest(section=section, value=bad_section):
                    bundle = build()
                    bundle[section] = bad_section
                    self.assertEqual(
                        verify(bundle), [f"{section} must be a JSON object"]
                    )

    def test_safe_integer_boundaries(self) -> None:
        max_safe = 9_007_199_254_740_991
        above_safe = 9_007_199_254_740_992

        # Valid boundary twins (accepted)
        bundle = build()
        bundle["authority_grant"]["max_amount_minor"] = max_safe
        bundle["policy_decision"]["authority_digest"] = digest(bundle["authority_grant"])
        rebind_request(bundle, amount_minor=max_safe)
        self.assertEqual(verify(bundle), [])

        bundle_min = build()
        rebind_request(bundle_min, amount_minor=1)
        self.assertEqual(verify(bundle_min), [])

        # Above safe-integer boundary on amount_minor (rejected)
        bundle_bad_amount = build()
        bundle_bad_amount["authority_grant"]["max_amount_minor"] = max_safe
        bundle_bad_amount["policy_decision"]["authority_digest"] = digest(
            bundle_bad_amount["authority_grant"]
        )
        rebind_request(bundle_bad_amount, amount_minor=above_safe)
        self.assertEqual(
            verify(bundle_bad_amount),
            ["amount is not a positive integer in minor units"],
        )

        # Above safe-integer boundary on max_amount_minor (rejected)
        bundle_bad_ceiling = build()
        bundle_bad_ceiling["authority_grant"]["max_amount_minor"] = above_safe
        bundle_bad_ceiling["policy_decision"]["authority_digest"] = digest(
            bundle_bad_ceiling["authority_grant"]
        )
        rebind_request(bundle_bad_ceiling, amount_minor=18_000)
        self.assertEqual(
            verify(bundle_bad_ceiling),
            ["authority grant ceiling is not an integer"],
        )

    def test_parser_rejects_duplicate_keys_and_nonfinite_json(self) -> None:
        from verify_purchase import _loads_strict

        raw = (EXAMPLE / "fixtures" / "valid-purchase.json").read_text(encoding="utf-8")
        dup = raw.rstrip()[:-1] + ', "extra": 1, "extra": 2}'
        self.assertEqual(verify(json.loads(dup)), [])
        with self.assertRaises(ValueError):
            _loads_strict(dup)

        for token in ("NaN", "Infinity", "-Infinity", "1e309"):
            with self.subTest(token=token):
                crafted = raw.rstrip()[:-1] + f', "extra": {token}}}'
                self.assertIsInstance(json.loads(crafted), dict)
                with self.assertRaises(ValueError):
                    _loads_strict(crafted)

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
