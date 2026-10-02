from __future__ import annotations

import ast
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "validate_artifacts.py"


class ValidateArtifactsTests(unittest.TestCase):
    def test_checks_survive_python_optimize(self) -> None:
        # validate_artifacts.py needs the published stack, which this job does
        # not install, so this pins the property statically. Under python -O
        # every assert is stripped, and a tampered artifact then printed
        # "valid" for all four checks.
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        asserts = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        self.assertEqual(asserts, [], f"assert used for validation at lines {asserts}")


if __name__ == "__main__":
    unittest.main()
