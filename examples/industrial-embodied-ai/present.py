#!/usr/bin/env python3
"""One-terminal, presenter-controlled workflow-authority demonstration."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from typing import Any


BASE = Path(__file__).resolve().parent
GATEWAY = "http://127.0.0.1:8443"
CONTROLLER = "http://127.0.0.1:8080"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def check_ports() -> None:
    for port in (8080, 8443):
        with socket.socket() as probe:
            # A prior owned run can leave TCP connections in TIME_WAIT.
            # Reuse permits a clean restart, never a second listening owner.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
                probe.listen()
            except OSError as exc:
                raise RuntimeError(
                    f"Port {port} is occupied. Stop its service or use another host. "
                    "No existing process was stopped."
                ) from exc


class LocalServices:
    """Own only the children started here; never search for or kill by port."""

    def __init__(self, output: Path, run_id: str):
        self.output = output
        self.run_id = run_id
        self.children: list[subprocess.Popen] = []
        self.token = secrets.token_urlsafe(32)

    def start_child(self, command: list[str], name: str, env: dict[str, str]) -> None:
        with (self.output / f"{name}.log").open("wb") as log:
            child = subprocess.Popen(
                command,
                cwd=self.output,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        self.children.append(child)

    def check_alive(self) -> None:
        require(
            all(child.poll() is None for child in self.children),
            f"A local service exited. See logs in {self.output}",
        )

    def wait_ready(self, client: Any, url: str, *, controller: bool = False) -> None:
        import httpx

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.check_alive()
            try:
                response = client.get(url, timeout=1)
            except httpx.TransportError:
                response = None
            if response is not None and response.status_code == 200:
                state = response.json()
                require(state.get("status") == "ready", "Invalid readiness response")
                if controller:
                    require(
                        state.get("run_id") == self.run_id,
                        "Controller belongs to another run",
                    )
                self.check_alive()
                return
            time.sleep(0.1)
        raise RuntimeError(f"Readiness timed out for {url}. See {self.output}")

    def start(self, client: Any) -> None:
        check_ports()
        env = dict(os.environ)
        # Keep all traffic local, independent of a presenter's corporate proxy.
        for key in list(env):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                del env[key]
        env.update(
            CMCP_DEV_MODE="1",
            CMCP_BEARER_TOKEN=self.token,
            CMCP_OPERATOR_TOKEN=secrets.token_urlsafe(32),
            PYTHONUNBUFFERED="1",
        )
        hashes = json.loads((BASE / "artifact-hashes.json").read_text())
        env["CMCP_POLICY_HASH"] = hashes["cmcp_policy_bundle_hash"]
        env["CMCP_CATALOG_HASH"] = hashes["cmcp_catalog_hash"]
        config = {
            "attestation": {
                "provider": "auto",
                "enforcement_mode": "enforcing",
                "validity_seconds": 86400,
                "staleness_policy": "fail_closed",
            },
            "policy_bundle_path": str(BASE / "policy"),
            "catalog_path": str(BASE / "catalog.json"),
            "listen_addr": "127.0.0.1:8443",
            "audit_db_path": str(self.output / "audit.db"),
        }
        config_path = self.output / "cmcp-config.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        with (self.output / "preflight.log").open("w") as log:
            subprocess.run(
                [sys.executable, str(BASE / "validate_artifacts.py")],
                cwd=BASE,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=True,
            )
        self.start_child(
            [
                sys.executable,
                str(BASE / "server/mock_robot_controller.py"),
                "--run-id",
                self.run_id,
            ],
            "controller",
            env,
        )
        self.wait_ready(client, f"{CONTROLLER}/health", controller=True)
        self.start_child(
            [
                sys.executable,
                "-c",
                "from cmcp_runtime.cli import main; main()",
                "start",
                "--config",
                str(config_path),
            ],
            "runtime",
            env,
        )
        self.wait_ready(client, f"{GATEWAY}/readyz")

    def motion_count(self, client: Any) -> int:
        self.check_alive()
        response = client.get(f"{CONTROLLER}/health")
        response.raise_for_status()
        state = response.json()
        require(state.get("run_id") == self.run_id, "Controller ownership changed")
        count = state["motion_requests"]
        require(type(count) is int and count >= 0, "Invalid motion counter")
        return count

    def stop(self) -> None:
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


def pause(auto: bool, next_step: str) -> None:
    if not auto:
        try:
            input(f"\n[Enter] {next_step}: ")
        except EOFError as exc:
            raise RuntimeError(
                "Input closed. Use --auto for an unattended rehearsal."
            ) from exc
    print(flush=True)


def tampered_copy(bundle: dict[str, Any]) -> dict[str, Any]:
    altered = copy.deepcopy(bundle)
    for entry in altered.get("entries", []):
        if entry.get("external_execution_evidence"):
            # This field records the signed outcome digest, not a robot video
            # or the physical outcome itself. Preserve every original file.
            entry["external_execution_evidence"]["evidence_hash"] = "sha256:" + "0" * 64
            return altered
    raise RuntimeError("Cannot demonstrate tampering without a controller receipt")


def run(output: Path, *, auto: bool) -> None:
    import httpx
    from agent.material_movement_agent import _read_state, _request_motion, _save_json
    from verify_evidence import verify_files

    output.mkdir(parents=True, exist_ok=False)
    print(f"Evidence and logs: {output}", flush=True)
    services = LocalServices(output, secrets.token_hex(16))
    claim_path = output / "trust-record.json"
    bundle_path = output / "audit-bundle.json"
    try:
        with httpx.Client(
            headers={"Authorization": f"Bearer {services.token}"},
            trust_env=False,
            timeout=10,
        ) as client:
            services.start(client)
            print("1/6  MISSION\n  Move material to transfer-station-b at 0.3 m/s.")
            print("  Declared workflow: industrial-material-movement")
            print("  Same motion, two workflow scopes. Live cMCP + Cedar enforcement.")
            print("  Simulated agent/controller; software-only development evidence.")

            pause(auto, "Try the undeclared workflow")
            before = services.motion_count(client)
            # Never pause between observation and motion: the token lasts 5 s.
            state = _read_state(client, GATEWAY, 1)
            session_id = state["session_id"]
            require(bool(session_id), "Runtime did not return a session id")
            denied = _request_motion(
                client,
                GATEWAY,
                2,
                state["payload"],
                "presenter-move",
                workflow_id="unapproved-diagnostics",
            )
            require(
                not denied["ok"] and denied["status_code"] == 403,
                "The undeclared workflow was not denied by cMCP",
            )
            after = services.motion_count(client)
            require(before == after == 0, "Denied motion reached the controller")
            print(
                "2/6  SCOPE DENIED\n  Same target and in-limit speed; fresh state token."
            )
            print("  cMCP: denied (undeclared workflow)")
            print(f"  Measured motion requests at controller: {before} -> {after}")
            print("  Motion safety alone does not grant task authority.")

            pause(auto, "Use the declared workflow")
            state = _read_state(client, GATEWAY, 3)
            require(state["session_id"] == session_id, "Runtime session changed")
            allowed = _request_motion(
                client, GATEWAY, 4, state["payload"], "presenter-move"
            )
            require(allowed["ok"], f"Declared workflow failed: {allowed}")
            require(allowed["session_id"] == session_id, "Runtime session changed")
            payload = allowed["payload"]
            require(
                payload.get("controller_decision") == "accepted"
                and payload.get("execution_status") == "completed",
                "Controller did not complete the simulated motion",
            )
            count = services.motion_count(client)
            require(count == after + 1, "Expected exactly one forwarded motion")
            print("3/6  AUTHORIZED\n  cMCP: allowed (declared workflow)")
            print("  Controller: accepted; simulated execution: completed")
            print(f"  Measured motion requests at controller: {after} -> {count}")

            pause(auto, "Close the session, save evidence, stop services")
            close = client.post(f"{GATEWAY}/sessions/{session_id}/close")
            close.raise_for_status()
            audit = client.get(
                f"{GATEWAY}/audit/export", params={"session_id": session_id}
            )
            audit.raise_for_status()
            _save_json(claim_path, close.json())
            _save_json(bundle_path, audit.json())
            _save_json(
                output / "observations.json",
                {
                    "session_id": session_id,
                    "denied_motion_requests": after - before,
                    "allowed_motion_requests": count - after,
                },
            )
    finally:
        services.stop()
    print("4/6  SERVICES STOPPED\n  Session closed; signed evidence saved.")
    print("  Demo-owned runtime and controller processes exited.")

    pause(auto, "Verify the saved evidence offline")
    print("5/6  OFFLINE VERIFICATION", flush=True)
    print(verify_files(claim_path, bundle_path), end="")
    print("  Original evidence: VERIFIED")

    pause(auto, "Alter a copy of the recorded outcome digest")
    altered_path = output / "tampered-audit-bundle.json"
    _save_json(altered_path, tampered_copy(json.loads(bundle_path.read_text())))
    try:
        verify_files(claim_path, altered_path)
    except (RuntimeError, ValueError) as exc:
        print("6/6  TAMPER CHECK\n  Original evidence: VERIFIED")
        print("  Altered outcome digest: REJECTED")
        (output / "tamper-rejection.txt").write_text(str(exc) + "\n")
    else:
        raise RuntimeError("Tampered evidence was accepted")
    print(
        "\nTask authority beyond motion safety, with independently checkable records."
    )
    print("Teaching keys only; no hardware provenance or proof of physical completion.")
    print(f"Saved run: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--auto", action="store_true", help="Run all steps without pauses"
    )
    parser.add_argument(
        "--output-dir", type=Path, help="New directory for evidence and logs"
    )
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (
        args.output_dir
        or BASE / "trace-output" / f"presenter-{stamp}-{secrets.token_hex(3)}"
    ).resolve()
    try:
        run(output, auto=args.auto)
    except KeyboardInterrupt:
        print(
            f"\nDemo interrupted; owned services stopped. Logs: {output}",
            file=sys.stderr,
        )
        return 130
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"DEMO FAILED: {exc}\nLogs: {output}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
