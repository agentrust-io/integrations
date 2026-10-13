import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from runner import (
    field,
    hash_check,
    relative_file,
    proofable,
    mintid,
    validate_report,
    refusal_observation,
)
from reference_adapter import Executor, run_cases
from runner import CASES, REQUIRED_FIELDS


def complete_report():
    return {
        "cases": [
            {
                "case_id": case,
                "fields": {key: field("not_emitted") for key in REQUIRED_FIELDS},
                "basis": "author_record",
                "independent_live_reproduction": False,
            }
            for case in CASES
        ]
    }


class RequiredFieldChecks(unittest.TestCase):
    def test_each_required_field_omission_rejected_without_mutation(self):
        for case_index, case_id in enumerate(CASES):
            for key in REQUIRED_FIELDS:
                with self.subTest(case=case_id, field=key):
                    report = complete_report()
                    del report["cases"][case_index]["fields"][key]
                    before = json.dumps(report, sort_keys=True)
                    with self.assertRaisesRegex(ValueError, key):
                        validate_report(report)
                    self.assertEqual(json.dumps(report, sort_keys=True), before)

    def test_authority_and_decision_omission_rejected(self):
        report = complete_report()
        del report["cases"][0]["fields"]["authority"]
        del report["cases"][0]["fields"]["decision"]
        with self.assertRaisesRegex(ValueError, "authority, decision"):
            validate_report(report)

    def test_empty_fields_rejected(self):
        report = complete_report()
        report["cases"][0]["fields"] = {}
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            validate_report(report)

    def test_explicit_unavailable_states_accepted_without_mutation(self):
        for state in ("not_emitted", "not_measured", "not_applicable"):
            with self.subTest(state=state):
                report = complete_report()
                for case in report["cases"]:
                    case["fields"] = {key: field(state) for key in REQUIRED_FIELDS}
                before = json.dumps(report, sort_keys=True)
                self.assertIs(validate_report(report), report)
                self.assertEqual(json.dumps(report, sort_keys=True), before)

    def test_complete_measured_fields_accepted(self):
        report = complete_report()
        for case in report["cases"]:
            case["fields"] = {key: field("measured", False) for key in REQUIRED_FIELDS}
        self.assertIs(validate_report(report), report)


class Checks(unittest.TestCase):
    def test_missing_states_not_collapsed(self):
        self.assertEqual(
            len(
                {
                    json.dumps(field(s))
                    for s in ["not_applicable", "not_emitted", "not_measured"]
                }
            ),
            3,
        )

    def test_missing_field_cannot_be_measured_value(self):
        with self.assertRaises(ValueError):
            field("not_measured", 5)

    def test_unknown_state_rejected(self):
        with self.assertRaises(ValueError):
            field("pass")

    def test_tampering_fails(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / "x").write_bytes(b"original")
            h = hashlib.sha256(b"original").hexdigest()
            self.assertTrue(hash_check(base, "x", h)["match"])
            (base / "x").write_bytes(b"changed")
            self.assertFalse(hash_check(base, "x", h)["match"])

    def test_escape_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                relative_file(Path(d), "../outside")

    def test_author_evidence_cannot_be_independent(self):
        report = complete_report()
        report["cases"][0]["independent_live_reproduction"] = True
        with self.assertRaisesRegex(ValueError, "author records"):
            validate_report(report)

    def test_veto_no_effect(self):
        row = run_cases()[0]
        self.assertFalse(row["decision"]["allowed"])
        self.assertFalse(row["effect"]["committed"])

    def test_revoked_no_effect(self):
        self.assertFalse(run_cases()[1]["effect"]["committed"])

    def test_unreachable_no_effect(self):
        self.assertFalse(run_cases()[2]["effect"]["committed"])

    def test_post_dispatch_recheck(self):
        row = run_cases()[3]
        self.assertTrue(row["decision"]["allowed"])
        self.assertIsNotNone(row["dispatch"])
        self.assertFalse(row["effect"]["committed"])

    def test_late_recovery_does_not_reopen(self):
        for row in run_cases():
            self.assertFalse(row["after_deadline"]["effect"]["committed"])

    def test_valid_control_and_duplicate(self):
        e = Executor()
        a = {"id": "control", "deadline": 20}
        _, d = e.dispatch(a, 10)
        self.assertTrue(e.commit(a, d, 11)["committed"])
        self.assertFalse(e.commit(a, d, 12)["committed"])
        self.assertEqual(len(e.effects), 1)

    def test_action_tampering_between_dispatch_commit(self):
        e = Executor()
        a = {"id": "control", "deadline": 20, "amount": 1}
        _, d = e.dispatch(a, 10)
        a["amount"] = 2
        self.assertFalse(e.commit(a, d, 11)["committed"])

    def test_published_proofable_stays_integrity_failed(self):
        p = Path("fixtures/proofable-historical")
        if not p.exists():
            self.skipTest("run fetch_fixtures.py first")
        report = proofable(p)
        self.assertEqual(report["integrity"], "FAIL")
        self.assertTrue(report["newline_diagnostic"]["crlf_hash_matches_published"])
        self.assertEqual(
            next(c for c in report["cases"] if c["case_id"] == "unreachable")["fields"][
                "decision"
            ]["state"],
            "not_applicable",
        )

    def test_mintid_outage_keeps_old_revision(self):
        p = Path("fixtures/mintid")
        if not (p / "revocation-trace-local-20261005T094532Z.manifest.json").exists():
            self.skipTest("run fetch_fixtures.py first")
        r = mintid(p, "revocation-trace-local-20261005T094532Z")
        self.assertEqual(r["integrity"], "PASS")
        c = next(c for c in r["cases"] if c["case_id"] == "unreachable")
        self.assertEqual(c["fields"]["decision"]["state"], "measured")
        self.assertFalse(c["independent_live_reproduction"])
        self.assertIn("public-v2026-10-05.5", r["record_revision"]["public_tags"])


class ReferenceChecks(unittest.TestCase):
    def test_released_trace_reference_shape(self):
        from trace_references import behavior_reference

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "trace.jsonl"
            path.write_bytes(b'{"decision":"deny"}\n')
            ref = behavior_reference(path, "https://example.org/pinned/trace.jsonl")
            self.assertEqual(ref.rel, "behavior-trace")
            self.assertEqual(
                ref.digest, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            )

    def test_reference_requires_http_uri(self):
        from trace_references import behavior_reference

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "trace.jsonl"
            path.write_bytes(b"{}\n")
            with self.assertRaises(ValueError):
                behavior_reference(path, "not a URI")

    def test_reference_rejects_empty_username_credentials(self):
        from trace_references import behavior_reference

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "trace.jsonl"
            path.write_bytes(b"{}\n")
            with self.assertRaises(ValueError):
                behavior_reference(path, "https://:secret@example.org/file")


class BoundaryChecks(unittest.TestCase):
    def test_late_veto_invalidates_prior_dispatch(self):
        e = Executor()
        a = {"id": "control", "deadline": 20}
        _, issued = e.dispatch(a, 10)
        decision, denied = e.dispatch(a, 11, veto=True)
        self.assertFalse(decision["allowed"])
        self.assertIsNone(denied)
        self.assertFalse(e.commit(a, issued, 12)["committed"])

    def test_emergency_bound_retains_blocks(self):
        r = refusal_observation(
            {
                "path": "emergency",
                "bound_seconds": 0,
                "bound_formula": "finalisation in blocks",
                "t0_definition": "submission",
                "first_refused": {"seconds_after_t0": 4.5, "chain_height_after": 95},
                "root_carrying_revocation": {"finalized_height": 94},
            }
        )
        self.assertEqual(r["bound_unit"], "blocks")
        self.assertEqual(r["seconds_bound"]["state"], "not_applicable")
        self.assertEqual(r["observed_seconds_after_t0"]["value"], 4.5)
        self.assertEqual(
            r["block_observations"]["value"][
                "root_carrying_revocation_finalized_height"
            ],
            94,
        )

    def test_forged_dispatch_rejected(self):
        e = Executor()
        a = {"id": "forged", "deadline": 20}
        h = hashlib.sha256(
            json.dumps(a, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertFalse(
            e.commit(a, {"token": "forged", "action_hash": h}, 11)["committed"]
        )

    def test_measured_null_rejected(self):
        with self.assertRaises(ValueError):
            field("measured")

    def test_manifest_cannot_omit_required_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "x.manifest.json").write_text(json.dumps({"files": {}}))
            with self.assertRaises(ValueError):
                mintid(p, "x")

    def test_root_age_is_seconds_not_root_identity(self):
        p = Path("fixtures/mintid")
        if not p.exists():
            self.skipTest("fetch fixtures")
        r = mintid(p, "revocation-trace-testnet-20261006T073712Z")
        c = next(c for c in r["cases"] if c["case_id"] == "revoked_stale")
        self.assertTrue(
            all(
                isinstance(a["seconds"], (int, float))
                for a in c["fields"]["root_age_seconds"]["value"]
            )
        )
        self.assertTrue(
            all(
                "epoch" in a and "height" in a
                for a in c["fields"]["evidence_identity"]["value"]
            )
        )


class CompletenessChecks(unittest.TestCase):
    def test_four_cases_required(self):
        with self.assertRaises(ValueError):
            validate_report({"cases": []})

    def test_duplicate_cases_rejected(self):
        with self.assertRaises(ValueError):
            validate_report({"cases": [{"case_id": "binding_veto", "fields": {}}] * 4})

    def test_missing_proofable_row_is_missing_not_na(self):
        p = Path("fixtures/proofable")
        if not p.exists():
            self.skipTest("fetch fixtures")
        import shutil

        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "proofable"
            shutil.copytree(p, target)
            lines = (target / "trace.jsonl").read_text().splitlines()
            (target / "trace.jsonl").write_text(
                "\n".join(
                    line
                    for line in lines
                    if json.loads(line)["case_id"] != "binding_veto"
                )
                + "\n"
            )
            r = proofable(target)
            self.assertEqual(r["integrity"], "FAIL")
            c = next(c for c in r["cases"] if c["case_id"] == "binding_veto")
            self.assertEqual(c["fields"]["decision"]["state"], "not_emitted")


class CorrectedProofableChecks(unittest.TestCase):
    def packet(self):
        p = Path("fixtures/proofable")
        self.assertTrue(p.exists(), "corrected pinned fixtures are required")
        return p

    def test_corrected_packet_verifies(self):
        report = proofable(self.packet())
        self.assertEqual(report["integrity"], "PASS")
        self.assertTrue(report["envelope_appraisal"]["valid"])
        self.assertEqual(len(report["envelope_appraisal"]["verdicts"]), 11)
        self.assertFalse(report["evidence_custody"]["independent_target_observer"])
        self.assertTrue(
            all(not row["independent_live_reproduction"] for row in report["cases"])
        )
        unreachable = next(
            row for row in report["cases"] if row["case_id"] == "unreachable"
        )
        self.assertEqual(
            unreachable["fields"]["receipt_signature_verification"]["state"],
            "not_measured",
        )

    def test_semantic_envelope_mutations_fail(self):
        import shutil
        from portable_envelope import qhash

        for mutation in (
            "did_address",
            "did_chain",
            "data",
            "signature",
            "duplicate",
            "missing",
            "trace_binding",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as d:
                target = Path(d) / "proofable"
                shutil.copytree(self.packet(), target)
                path = target / "portable-proofs.json"
                envelopes = json.loads(path.read_text())
                if mutation == "duplicate":
                    envelopes[-1] = envelopes[0]
                elif mutation == "missing":
                    envelopes.pop()
                elif mutation == "trace_binding":
                    trace = target / "trace.jsonl"
                    rows = [json.loads(line) for line in trace.read_text().splitlines()]
                    rows[0]["terminal_receipt"]["qHash"] = "0x" + "0" * 64
                    trace.write_text("".join(json.dumps(row) + "\n" for row in rows))
                elif mutation == "signature":
                    envelopes[0]["signature"] = "0x" + "00" * 65
                else:
                    if mutation == "did_address":
                        envelopes[0]["did"] = "did:pkh:eip155:84532:0x" + "1" * 40
                    elif mutation == "did_chain":
                        envelopes[0]["did"] = envelopes[0]["did"].replace(
                            ":84532:", ":1:"
                        )
                    else:
                        envelopes[0]["data"]["owner"] = "0x" + "1" * 40
                    envelopes[0]["qHash"] = qhash(envelopes[0])
                path.write_text(json.dumps(envelopes))
                report = proofable(target)
                self.assertFalse(report["envelope_appraisal"]["valid"])
                self.assertEqual(report["integrity"], "FAIL")


if __name__ == "__main__":
    unittest.main()
