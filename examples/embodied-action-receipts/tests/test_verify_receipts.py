from __future__ import annotations

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_fixtures import sign
from verify_receipts import (
    load_trusted_keys,
    receipt_hash,
    verify_fixture,
)


class ReceiptFixtureTests(unittest.TestCase):
    def test_fixtures_match_expected_results(self) -> None:
        for path in sorted((ROOT / "fixtures").glob("*.json")):
            with self.subTest(path=path.name):
                fixture = json.loads(path.read_text())
                self.assertEqual(verify_fixture(path), fixture["expected"])

    def test_rejected_receipt_is_valid_evidence(self) -> None:
        result = verify_fixture(ROOT / "fixtures" / "controller-rejected.json")
        self.assertEqual(result, {"result": "valid", "receipt_state": "rejected"})

    def test_explicit_empty_trust_store_trusts_nobody(self) -> None:
        result = verify_fixture(ROOT / "fixtures" / "valid-chain.json", trusted_keys={})
        self.assertEqual(result, {"result": "invalid", "receipt_state": "untrusted"})

    def test_trusted_key_cannot_claim_a_different_issuer(self) -> None:
        fixture = json.loads((ROOT / "fixtures" / "valid-chain.json").read_text())
        forged = deepcopy(fixture["receipts"][0])
        forged.pop("signature")
        forged["issuer"] = "spiffe://attacker.example/controller"
        fixture["receipts"] = [sign(forged)]
        path = ROOT / "fixtures" / ".test-wrong-issuer.json"
        try:
            path.write_text(json.dumps(fixture))
            result = verify_fixture(path, trusted_keys=load_trusted_keys())
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(result, {"result": "invalid", "receipt_state": "issuer_mismatch"})

    def test_receipt_sequences_must_be_contiguous(self) -> None:
        fixture = json.loads((ROOT / "fixtures" / "valid-chain.json").read_text())
        first = fixture["receipts"][0]
        second = deepcopy(fixture["receipts"][1])
        second.pop("signature")
        second["sequence"] = 3
        second["prev_receipt_hash"] = receipt_hash(first)
        fixture["receipts"][1] = sign(second)
        path = ROOT / "fixtures" / ".test-sequence-gap.json"
        try:
            path.write_text(json.dumps(fixture))
            result = verify_fixture(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(result, {"result": "invalid", "receipt_state": "sequence_mismatch"})

    def verify_mutated(self, mutate) -> dict:
        fixture = json.loads((ROOT / "fixtures" / "valid-chain.json").read_text())
        mutate(fixture)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_text(json.dumps(fixture))
            return verify_fixture(path)

    def test_signature_encoding_is_not_malleable(self) -> None:
        # A lenient base64 decoder drops characters outside the alphabet and
        # ignores surplus padding, so one signature had many accepted spellings.
        def junk(fixture: dict) -> None:
            sig = fixture["receipts"][-1]["signature"]
            fixture["receipts"][-1]["signature"] = sig[:12] + "!!!!" + sig[12:]

        def padded(fixture: dict) -> None:
            fixture["receipts"][-1]["signature"] += "===="

        for mutate in (junk, padded):
            with self.subTest(mutation=mutate.__name__):
                self.assertEqual(
                    self.verify_mutated(mutate),
                    {"result": "invalid", "receipt_state": "signature_format"},
                )

    def test_malformed_fixture_is_invalid_not_a_crash(self) -> None:
        mutations = {
            "receipts_not_a_list": lambda f: f.__setitem__("receipts", "x"),
            "missing_sequence": lambda f: f["receipts"][0].pop("sequence"),
            "signature_not_a_string": lambda f: f["receipts"][0].__setitem__("signature", 5),
            "mixed_sequence_types": lambda f: f["receipts"][0].__setitem__("sequence", "1"),
            "action_not_an_object": lambda f: f.__setitem__("action", []),
            "receipt_not_an_object": lambda f: f["receipts"].append(7),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                self.assertEqual(
                    self.verify_mutated(mutate),
                    {"result": "invalid", "receipt_state": "malformed"},
                )

    def test_truncated_signature_is_a_format_error(self) -> None:
        def truncate(fixture: dict) -> None:
            fixture["receipts"][0]["signature"] = "ed25519:" + "A" * 5

        self.assertEqual(
            self.verify_mutated(truncate),
            {"result": "invalid", "receipt_state": "signature_format"},
        )


if __name__ == "__main__":
    unittest.main()

