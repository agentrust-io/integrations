from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest


BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from present import LocalServices, check_ports, tampered_copy  # noqa: E402


class PresenterTests(unittest.TestCase):
    def test_tampering_preserves_original(self) -> None:
        original = {
            "entries": [
                {
                    "external_execution_evidence": {
                        "evidence_hash": "sha256:" + "a" * 64,
                        "signature": "original-signature",
                    }
                }
            ]
        }
        before = json.dumps(original, sort_keys=True)
        altered = tampered_copy(original)
        self.assertEqual(json.dumps(original, sort_keys=True), before)
        self.assertNotEqual(altered, original)
        self.assertEqual(
            altered["entries"][0]["external_execution_evidence"]["signature"],
            "original-signature",
        )

    def test_missing_receipt_cannot_produce_tamper_success(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "without a controller receipt"):
            tampered_copy({"entries": []})

    def test_occupied_port_is_left_alone(self) -> None:
        with socket.socket() as occupant:
            try:
                occupant.bind(("127.0.0.1", 8080))
            except OSError:
                self.skipTest("Port 8080 already in use")
            occupant.listen()
            with self.assertRaisesRegex(RuntimeError, "Port 8080 is occupied"):
                check_ports()
            with socket.create_connection(("127.0.0.1", 8080), timeout=1):
                pass

    def test_cleanup_stops_owned_child_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            services = LocalServices(Path(directory), "test-run")
            outsider = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"]
            )
            try:
                services.start_child(
                    [sys.executable, "-c", "import time; time.sleep(60)"], "test", {}
                )
                services.stop()
                services.stop()  # Cleanup after an exception is safe to repeat.
                self.assertIsNotNone(services.children[0].poll())
                self.assertIsNone(outsider.poll())
            finally:
                outsider.terminate()
                outsider.wait(timeout=5)

    def test_exited_service_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            services = LocalServices(Path(directory), "test-run")
            services.start_child(
                [sys.executable, "-c", "raise SystemExit(2)"], "test", {}
            )
            services.children[0].wait(timeout=5)
            with self.assertRaisesRegex(RuntimeError, "service exited"):
                services.check_alive()


if __name__ == "__main__":
    unittest.main()
