"""Full-stack tests: install requirements-presenter.txt before running these."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from present import GATEWAY, LocalServices, check_ports, run  # noqa: E402


class LivePresenterTests(unittest.TestCase):
    def command(self, output: Path, *args: str) -> list[str]:
        return [
            sys.executable,
            str(BASE / "present.py"),
            "--output-dir",
            str(output),
            *args,
        ]

    def verify_offline(
        self, output: Path, *, tampered: bool = False
    ) -> subprocess.CompletedProcess:
        # Audit hooks reject socket creation, DNS and connections. Dependencies
        # may be imported, but any attempt to use the network fails this test.
        script = """
import sys
def deny_network(event, args):
    if event.startswith('socket.'):
        raise RuntimeError('network forbidden during offline verification')
sys.addaudithook(deny_network)
from verify_evidence import main
raise SystemExit(main())
"""
        bundle = "tampered-audit-bundle.json" if tampered else "audit-bundle.json"
        return subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(output / "trust-record.json"),
                str(output / bundle),
            ],
            cwd=BASE,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_two_fresh_runs_and_offline_tamper_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sessions = []
            for index in range(2):
                output = Path(directory) / str(index)
                result = subprocess.run(
                    self.command(output, "--auto"),
                    cwd=BASE,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Altered outcome digest: REJECTED", result.stdout)
                observed = json.loads((output / "observations.json").read_text())
                self.assertEqual(observed["denied_motion_requests"], 0)
                self.assertEqual(observed["allowed_motion_requests"], 1)
                sessions.append(observed["session_id"])
                check_ports()  # Both children really exited before verification.
                verified = self.verify_offline(output)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertIn("EVIDENCE VERIFIED", verified.stdout)
                rejected = self.verify_offline(output, tampered=True)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("EVIDENCE REJECTED", rejected.stderr)
                self.assertNotIn("receipts: verified", rejected.stdout)
                # Neither altered claims nor absent receipts can pass as valid.
                audit_path = output / "audit-bundle.json"
                original_bundle = audit_path.read_text()
                bundle = json.loads(original_bundle)
                for entry in bundle["entries"]:
                    entry["external_execution_evidence"] = None
                audit_path.write_text(json.dumps(bundle))
                self.assertNotEqual(self.verify_offline(output).returncode, 0)
                audit_path.write_text(original_bundle)
                claim = json.loads((output / "trust-record.json").read_text())
                claim["trace"]["session_id"] = "changed-session"
                (output / "trust-record.json").write_text(json.dumps(claim))
                self.assertNotEqual(self.verify_offline(output).returncode, 0)
            self.assertNotEqual(*sessions)

    def test_original_three_path_runner(self) -> None:
        import httpx

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            services = LocalServices(output, "original-runner-regression")
            try:
                with httpx.Client(trust_env=False) as client:
                    services.start(client)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(BASE / "agent/material_movement_agent.py"),
                        "--claim-out",
                        str(output / "trust-record.json"),
                        "--audit-out",
                        str(output / "audit-bundle.json"),
                    ],
                    cwd=BASE,
                    env={**os.environ, "CMCP_BEARER_TOKEN": services.token},
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("SAFETY REJECT", result.stdout)
                self.assertIn("controller receipts: verified (2)", result.stdout)
            finally:
                services.stop()
            check_ports()

    def interactive(self, output: Path, *, interrupt: bool) -> tuple[int, str]:
        child = subprocess.Popen(
            self.command(output),
            cwd=BASE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        chunks: queue.Queue = queue.Queue()

        def read_output() -> None:
            while char := child.stdout.read(1):
                chunks.put(char)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        transcript = ""
        prompts = 0
        deadline = time.monotonic() + 60
        try:
            while child.poll() is None and time.monotonic() < deadline:
                try:
                    char = chunks.get(timeout=0.1)
                except queue.Empty:
                    continue
                transcript += char
                if transcript.count("[Enter]") == prompts + 1 and transcript.endswith(
                    ": "
                ):
                    prompts += 1
                    if interrupt:
                        child.send_signal(signal.SIGINT)
                        break
                    if prompts <= 2:
                        # A pause longer than the 5-second token lifetime must
                        # work because observation happens AFTER Enter.
                        time.sleep(5.2)
                    child.stdin.write("\n")
                    child.stdin.flush()
            child.wait(timeout=15)
            reader.join(timeout=2)
            while not chunks.empty():
                transcript += chunks.get_nowait()
            if not interrupt:
                self.assertEqual(prompts, 5, transcript)
            return child.returncode, transcript
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                child.wait(timeout=15)
            child.stdin.close()
            child.stdout.close()

    def test_presenter_pauses_do_not_stale_the_safety_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, transcript = self.interactive(
                Path(directory) / "paused", interrupt=False
            )
            self.assertEqual(code, 0, transcript)
            self.assertIn("Altered outcome digest: REJECTED", transcript)
            check_ports()

    def test_interrupt_and_closed_input_release_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, transcript = self.interactive(
                Path(directory) / "interrupt", interrupt=True
            )
            self.assertEqual(code, 130, transcript)
            check_ports()
            result = subprocess.run(
                self.command(Path(directory) / "eof"),
                cwd=BASE,
                input="",
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("Input closed", result.stderr)
            check_ports()

    def test_partial_startup_failure_reaps_owned_children(self) -> None:
        original_wait = LocalServices.wait_ready
        children = []

        def fail_gateway(services, client, url, **kwargs):
            if url.startswith(GATEWAY):
                children.extend(services.children)
                raise RuntimeError("injected readiness failure")
            return original_wait(services, client, url, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(LocalServices, "wait_ready", fail_gateway):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(
                        RuntimeError, "injected readiness failure"
                    ):
                        run(Path(directory) / "partial", auto=True)
            self.assertEqual(len(children), 2)
            self.assertTrue(all(child.poll() is not None for child in children))
            check_ports()


if __name__ == "__main__":
    unittest.main()
