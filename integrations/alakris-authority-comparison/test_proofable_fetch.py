"""Fixed-publication checks and independent test-key cryptographic controls."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from portable_envelope import message, qhash
from proofable_fetch import (
    MAX_FILE_BYTES,
    PINS,
    _create_response,
    _inventory,
    _json,
    _js_stringify,
    _load,
    _records,
    _semantic_checks,
    appraise,
    main,
    request_digest,
)
from runner import CASES, REQUIRED_FIELDS

ROOT = Path(__file__).resolve().parent
PACKET = ROOT / "fixtures/proofable-fetch"
TEST_KEY = "0x" + "01".zfill(64)
SECOND_KEY = "0x" + "02".zfill(64)


def envelope(records, filename):
    return records[filename]["data"]["proofs"][0]["portableProof"]


def sign(records, filename, key=TEST_KEY):
    """Create signatures locally using test keys, not vendor signatures."""
    item = envelope(records, filename)
    item["walletAddress"] = Account.from_key(key).address.lower()
    item["did"] = f"did:pkh:eip155:{item['chainId']}:{item['walletAddress']}"
    item["qHash"] = qhash(item)
    item["signature"] = "0x" + Account.sign_message(
        encode_defunct(text=message(item)), private_key=key
    ).signature.hex().removeprefix("0x")


def create_payload(records):
    return records["3-create-response.txt"]["result"]["structuredContent"]


def sync_create_text(records):
    records["3-create-response.txt"]["result"]["content"][0]["text"] = json.dumps(
        create_payload(records)
    )


def sync_joins(records):
    decision = envelope(records, "4-dispatch-decision.json")
    receipt = envelope(records, "6-terminal-receipt.json")
    create = create_payload(records)
    create["authorityDecisionQHash"] = create["authorityDecision"]["qHash"] = decision[
        "qHash"
    ]
    records["5-job-record.json"]["qHash"] = records["5-job-record.json"][
        "terminalQHash"
    ] = receipt["qHash"]
    sync_create_text(records)


def control_records():
    records = _records(_load(PACKET))
    records["1-invocation.json"]["serviceSigner"] = Account.from_key(
        TEST_KEY
    ).address.lower()
    for name in ("4-dispatch-decision.json", "6-terminal-receipt.json"):
        sign(records, name)
    sync_joins(records)
    return records


def checks(records):
    return {row["check"]: row["valid"] for row in _semantic_checks(records)["checks"]}


class PublishedFetchChecks(unittest.TestCase):
    def test_fixed_positive_packet_and_unmet_scenarios(self):
        self.assertTrue(
            PACKET.is_dir(),
            "run fetch_fixtures.py first; no fixture test may be skipped",
        )
        before = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in PACKET.iterdir()
            if p.is_file()
        }
        with patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
            report = appraise(PACKET)
        self.assertEqual(report["integrity"], "PASS")
        self.assertEqual(report["positive_dispatch_appraisal"], "PASS")
        self.assertTrue(report["positive_dispatch"]["valid"])
        self.assertEqual(len(report["artifact_hashes"]), 10)
        self.assertTrue(report["publisher_checksum_inventory_valid"])
        self.assertEqual(report["scenario_conformance"], "UNMET")
        self.assertEqual(report["service_key_attribution"]["state"], "not_measured")
        self.assertEqual(
            report["grant_and_agent_identity_validation"]["state"], "not_measured"
        )
        self.assertFalse(report["independent_live_reproduction"])
        self.assertFalse(report["independent_comparison_completed"])
        self.assertFalse(report["request_binding"]["full_returned_marker_precommitted"])
        self.assertEqual({case["case_id"] for case in report["cases"]}, set(CASES))
        for case in report["cases"]:
            self.assertEqual(set(case["fields"]), REQUIRED_FIELDS)
            self.assertEqual(case["scenario_conformance"], "UNMET")
            self.assertTrue(case["unmet_requirements"])
            self.assertTrue(
                all(
                    item["state"] == "not_measured" and item["reason"]
                    for item in case["fields"].values()
                )
            )
        self.assertEqual(
            report["unmeasured"]["EO01_unreachable_authority"]["state"], "not_measured"
        )
        self.assertFalse(report["trace_record_emitted"])
        self.assertEqual(
            before,
            {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in PACKET.iterdir()
                if p.is_file()
            },
        )

    def test_tampered_artifact_cannot_pass_even_if_semantics_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "packet"
            shutil.copytree(PACKET, packet)
            (packet / "README.md").write_text("changed publisher description\n")
            report = appraise(packet)
            self.assertEqual(report["integrity"], "FAIL")
            self.assertEqual(report["positive_dispatch_appraisal"], "FAIL")
            self.assertTrue(report["positive_dispatch"]["valid"])

    def test_missing_unsafe_and_oversized_files_rejected(self):
        for kind in ("missing", "symlink", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                packet = Path(tmp) / "packet"
                shutil.copytree(PACKET, packet)
                path = packet / "README.md"
                path.unlink()
                if kind == "symlink":
                    outside = Path(tmp) / "outside"
                    outside.write_text("outside")
                    path.symlink_to(outside)
                elif kind == "oversize":
                    path.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
                with self.assertRaises(ValueError):
                    appraise(packet)

    def test_cli_keeps_output_outside_packet(self):
        result = subprocess.run(
            [
                sys.executable,
                "proofable_fetch.py",
                "--input",
                str(PACKET),
                "--output",
                str(PACKET / "forbidden.json"),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output must be outside", result.stderr)
        self.assertFalse((PACKET / "forbidden.json").exists())

    def test_cli_replaces_hardlinked_output_without_modifying_any_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "packet"
            shutil.copytree(PACKET, packet)
            original = packet / "README.md"
            output = Path(tmp) / "outside-output.json"
            os.link(original, output)
            self.assertEqual(original.stat().st_ino, output.stat().st_ino)
            before = {
                name: hashlib.sha256((packet / name).read_bytes()).hexdigest()
                for name in PINS
            }
            result = subprocess.run(
                [
                    sys.executable,
                    "proofable_fetch.py",
                    "--input",
                    str(packet),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(output.read_text())["positive_dispatch_appraisal"], "PASS"
            )
            self.assertNotEqual(original.stat().st_ino, output.stat().st_ino)
            self.assertEqual(
                before,
                {
                    name: hashlib.sha256((packet / name).read_bytes()).hexdigest()
                    for name in PINS
                },
            )
            self.assertFalse(list(Path(tmp).glob(".proofable-fetch-*")))

    def test_atomic_output_failure_cleans_temporary_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output.json"
            before = {
                name: hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
                for name in PINS
            }
            with patch(
                "sys.argv",
                ["proofable_fetch.py", "--input", str(PACKET), "--output", str(output)],
            ), patch(
                "proofable_fetch.os.replace", side_effect=OSError("replace failed")
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    main()
            self.assertFalse(output.exists())
            self.assertFalse(list(Path(tmp).glob(".proofable-fetch-*")))
            self.assertEqual(
                before,
                {
                    name: hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
                    for name in PINS
                },
            )


class IndependentCryptoControls(unittest.TestCase):
    def test_fresh_test_key_control_verifies_without_vendor_signatures(self):
        records = control_records()
        report = _semantic_checks(records)
        self.assertTrue(report["valid"])
        self.assertNotEqual(
            report["declared_service_signer"],
            "0xa41494e1e5f9e5eaf786961e6ef84cd1a3071eec",
        )
        self.assertTrue(all(item["valid"] for item in report["envelopes"].values()))

    def test_changed_unsigned_request_digest_fails_with_valid_envelopes(self):
        records = control_records()
        records["2-request-arguments.json"]["prompt"] = records[
            "2-request-arguments.json"
        ]["prompt"].replace("b008feae", "a008feae")
        result = checks(records)
        self.assertFalse(result["request_args_digest"])
        self.assertTrue(result["decision_envelope"])
        self.assertTrue(result["receipt_envelope"])

    def test_different_validly_signed_receipt_request_fails_digest(self):
        records = control_records()
        item = envelope(records, "6-terminal-receipt.json")
        content = json.loads(item["data"]["content"])
        content["prompt"] = content["prompt"].replace("b008feae", "a008feae")
        item["data"]["content"] = json.dumps(content)
        sign(records, "6-terminal-receipt.json")
        sync_joins(records)
        result = checks(records)
        self.assertTrue(result["receipt_envelope"])
        self.assertFalse(result["receipt_request_digest"])
        self.assertFalse(result["receipt_request_fields"])

    def test_wrong_signature_and_qhash_fail_independently(self):
        for key, value in (("signature", "0x" + "00" * 65), ("qHash", "0x" + "0" * 64)):
            with self.subTest(key=key):
                records = control_records()
                envelope(records, "4-dispatch-decision.json")[key] = value
                self.assertFalse(checks(records)["decision_envelope"])

    def test_different_valid_signer_or_chain_fails_context(self):
        for kind in ("signer", "chain"):
            with self.subTest(kind=kind):
                records = control_records()
                if kind == "chain":
                    envelope(records, "6-terminal-receipt.json")["chainId"] = 1
                sign(
                    records,
                    "6-terminal-receipt.json",
                    SECOND_KEY if kind == "signer" else TEST_KEY,
                )
                sync_joins(records)
                result = checks(records)
                self.assertTrue(result["receipt_envelope"])
                self.assertFalse(result["same_declared_signer_context"])

    def test_did_binding_is_required(self):
        records = control_records()
        item = envelope(records, "4-dispatch-decision.json")
        item["did"] = item["did"].replace(":8453:", ":1:")
        item["qHash"] = qhash(item)
        self.assertFalse(checks(records)["decision_envelope"])

    def test_unsigned_create_join_mismatches_are_not_promoted_to_attestation(self):
        for kind in ("decision", "job"):
            with self.subTest(kind=kind):
                records = control_records()
                create = create_payload(records)
                if kind == "decision":
                    create["authorityDecisionQHash"] = create["authorityDecision"][
                        "qHash"
                    ] = "0x" + "1" * 64
                else:
                    create["jobId"] = "different-job"
                sync_create_text(records)
                result = checks(records)
                self.assertTrue(result["create_response_shape"])
                self.assertFalse(
                    result[
                        "create_decision_qhash_join"
                        if kind == "decision"
                        else "create_job_join"
                    ]
                )
                self.assertTrue(result["decision_envelope"])
                self.assertTrue(result["receipt_envelope"])

    def test_different_validly_signed_principal_fails_context(self):
        records = control_records()
        item = envelope(records, "6-terminal-receipt.json")
        item["data"]["owner"] = "0x" + "1" * 40
        sign(records, "6-terminal-receipt.json")
        sync_joins(records)
        result = checks(records)
        self.assertTrue(result["receipt_envelope"])
        self.assertFalse(result["same_principal_agent_context"])


class InputAndProjectionChecks(unittest.TestCase):
    def test_ambiguous_and_nonfinite_json_rejected_including_signed_content(self):
        for value in (
            '{"x":1,"x":2}',
            '{"x":NaN}',
            '{"x":Infinity}',
            '{"x":1e999}',
            "{",
            "[" * 66 + "0" + "]" * 66,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _json(value, "control")
        records = control_records()
        envelope(records, "6-terminal-receipt.json")["data"]["content"] = (
            '{"jobId":"a","jobId":"b"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            _semantic_checks(records)

    def test_multiple_sse_responses_and_ambiguous_nested_create_json_rejected(self):
        with self.assertRaises(ValueError):
            _create_response("event: message\ndata: {}\n\nevent: message\ndata: {}\n")
        records = control_records()
        records["3-create-response.txt"]["result"]["content"][0]["text"] = (
            '{"jobId":"a","jobId":"b"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            _semantic_checks(records)

    def test_checksum_inventory_rejects_escape_duplicate_and_omission(self):
        for content in (
            ("0" * 64 + "  ../outside\n").encode(),
            ("0" * 64 + "  README.md\n").encode() * 2,
        ):
            with self.assertRaises(ValueError):
                _inventory(content)
        self.assertNotEqual(
            _inventory(b""),
            {name: h for name, h in PINS.items() if name != "SHA256SUMS"},
        )

    def test_projection_matches_published_digest_and_ignores_only_declared_exclusions(
        self,
    ):
        request = _records(_load(PACKET))["2-request-arguments.json"]
        self.assertEqual(
            request_digest(request),
            "245cd3cefe248e532ba867b8735484485c26d3809ad909ef47348f449b0b7b07",
        )
        altered = copy.deepcopy(request)
        altered["runNowFirst"] = False
        altered["acceptance"]["criteria"] = ["different unsigned alias"]
        altered["agentWallet"] = altered["agentWallet"].upper().replace("0X", "0x")
        self.assertEqual(request_digest(altered), request_digest(request))
        altered["acceptance"]["criterion"] = "different criterion"
        self.assertNotEqual(request_digest(altered), request_digest(request))

    def test_stringify_preserves_unicode_and_js_key_order_without_rounding(self):
        self.assertEqual(
            _js_stringify({"z": "e\u0301", "2": False, "1": None}),
            '{"1":null,"2":false,"z":"e\u0301"}',
        )
        self.assertEqual(_js_stringify("\ud800"), '"\\ud800"')
        for value in (1.5, float("nan"), 2**53):
            with self.assertRaises(ValueError):
                _js_stringify(value)

    def test_multiple_envelopes_and_malformed_data_rejected(self):
        records = control_records()
        records["4-dispatch-decision.json"]["data"]["proofs"] *= 2
        with self.assertRaisesRegex(ValueError, "exactly one"):
            _semantic_checks(records)


if __name__ == "__main__":
    unittest.main()
