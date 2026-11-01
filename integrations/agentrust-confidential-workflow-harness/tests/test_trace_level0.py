"""Check records actually emitted by the released API probe at TRACE Level 0."""
import copy
import json
import unittest
from importlib.metadata import version
from unittest.mock import patch

from trace_tests.loader import parse_record
from trace_tests.runner import run as trace_run

from harness.released_protocol_probe import emit_dag, probe


class TraceLevel0Tests(unittest.TestCase):
    def test_emitted_probe_records_pass_and_tampering_fails(self):
        self.assertEqual(version("agentrust-trace-tests"), "0.6.2")
        self.assertEqual(version("agentrust-trace"), "0.11.0")
        emitted = []

        def capture(*args, **kwargs):
            records = emit_dag(*args, **kwargs)
            emitted.extend(records)
            return records

        with patch("harness.released_protocol_probe.emit_dag", side_effect=capture):
            result = probe(transaction_id="level0-txn", subject="level0-subject",
                           tool_name="inspect", allowed_tools=("inspect",),
                           policy_digest="sha256:" + "a" * 64, nonce="level0-nonce")
        self.assertTrue(result.admitted, result.reason)
        self.assertEqual(result.actual_dispatches, 0)
        self.assertEqual(len(emitted), 2)
        for record in emitted:
            loaded, fmt = parse_record(json.dumps(record).encode())
            findings = trace_run(loaded, fmt, level=0)
            self.assertEqual(set(findings), {"TR-ENV", "TR-SIG", "TR-POL", "TR-APR"})
            self.assertTrue(all(findings.values()))
            self.assertFalse([f.message for group in findings.values() for f in group if f.failed()])
            self.assertTrue(all(f.status == "pass" for f in findings["TR-SIG"]))
            tampered = copy.deepcopy(record)
            tampered["subject"] = "did:example:tampered"
            loaded, fmt = parse_record(json.dumps(tampered).encode())
            failures = trace_run(loaded, fmt, level=0)
            self.assertTrue(any(f.failed() for f in failures["TR-SIG"]))
