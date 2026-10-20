"""Portable wrapper controls; downstream cryptography is deliberately stubbed."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch


BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from verify_evidence import verify  # noqa: E402


class VerifyEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.downstream = Mock()
        module = ModuleType("agent.material_movement_agent")
        module._verify_evidence = self.downstream
        self.modules = patch.dict(sys.modules, {module.__name__: module})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_missing_receipt_refuses_before_downstream_verification(self) -> None:
        for bundle in ({}, {"entries": []}, {"entries": [{"external_execution_evidence": {}}]}):
            with self.subTest(bundle=bundle):
                with self.assertRaisesRegex(RuntimeError, "No controller-signed motion receipt"):
                    verify({}, bundle)
                self.downstream.assert_not_called()

    def test_receipt_continues_to_downstream_without_publishing_early(self) -> None:
        claim = {"test": "claim"}
        bundle = {"entries": [{"external_execution_evidence": {"test": "receipt"}}]}
        self.downstream.side_effect = lambda *_args, **_kwargs: print("downstream report")
        visible = io.StringIO()
        with redirect_stdout(visible):
            report = verify(claim, bundle)
        self.downstream.assert_called_once_with(claim, bundle, require_hardware=False)
        self.assertEqual(report, "downstream report\n")
        self.assertEqual(visible.getvalue(), "")

    def test_downstream_failure_does_not_publish_partial_report(self) -> None:
        def fail(*_args, **_kwargs):
            print("partial success")
            raise RuntimeError("downstream rejected")

        self.downstream.side_effect = fail
        visible = io.StringIO()
        with redirect_stdout(visible):
            with self.assertRaisesRegex(RuntimeError, "downstream rejected"):
                verify({}, {"entries": [{"external_execution_evidence": {"test": "receipt"}}]})
        self.downstream.assert_called_once()
        self.assertEqual(visible.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
