"""Opt-in execution receipts. Local evidence is not tier approval or attestation."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

import yaml

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(root: Path, integration: str, output: Path, command: list[str],
            evidence_class: str, timeout: int = 600) -> dict:
    """Run an explicitly selected command in this interpreter's environment."""
    if timeout <= 0:
        raise ValueError("Timeout must be positive")
    manifest = (root / integration / "integration.yaml").resolve()
    manifest.relative_to(root.resolve())
    declared = yaml.safe_load(manifest.read_text()).get("tested_against") or {}
    observed = {}
    for package in declared:
        try:
            observed[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            observed[package] = None
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
    ).strip()
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True,
    ).strip())
    if not command or command[0] != sys.executable:
        raise ValueError("Command must start with this Python interpreter (use -- python ...)")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    log = output / "output.log"
    timed_out = False
    with log.open("wb") as stream:
        try:
            result = subprocess.run(command, cwd=root, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            returncode = None
            timed_out = True
    receipt = {
        "version": 1, "integration": integration, "revision": revision,
        "dirty": dirty, "manifest_sha256": digest(manifest),
        "declared_packages": declared, "observed_packages": observed,
        "command": command, "evidence_class": evidence_class,
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "returncode": returncode, "timed_out": timed_out,
        "log_sha256": digest(log),
        "run_url": (f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
                    f"{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_ACTIONS") == "true"
                    else None),
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def validate(root: Path, directory: Path) -> list[str]:
    """Check a retained receipt against the current checkout and log bytes."""
    try:
        receipt = json.loads((directory / "receipt.json").read_text())
        manifest = (root / receipt["integration"] / "integration.yaml").resolve()
        manifest.relative_to(root.resolve())
        declared = yaml.safe_load(manifest.read_text()).get("tested_against") or {}
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        checks = {
            "unsupported receipt version": receipt["version"] == 1,
            "source revision mismatch": receipt["revision"] == revision,
            "dirty source snapshot": receipt["dirty"] is False,
            "current checkout is dirty": not subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True,
            ).strip(),
            "manifest changed": receipt["manifest_sha256"] == digest(manifest),
            "declared versions changed": receipt["declared_packages"] == declared,
            "missing tested_against declaration": bool(declared),
            "installed versions differ": receipt["observed_packages"] == declared,
            "command did not pass": receipt["returncode"] == 0 and receipt["timed_out"] is False,
            "log digest mismatch": receipt["log_sha256"] == digest(directory / "output.log"),
            "invalid evidence class": receipt["evidence_class"] in {"synthetic", "captured", "live"},
            "missing command": isinstance(receipt["command"], list) and bool(receipt["command"]),
        }
        for field in ("started_at", "finished_at"):
            if datetime.fromisoformat(receipt[field]).tzinfo is None:
                raise ValueError("Timestamp requires timezone")
        if datetime.fromisoformat(receipt["finished_at"]) < datetime.fromisoformat(receipt["started_at"]):
            raise ValueError("Finish precedes start")
        return [message for message, passed in checks.items() if not passed]
    except (KeyError, ValueError, TypeError, OSError) as exc:
        return [f"invalid or missing evidence: {exc}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    record = sub.add_parser("capture")
    record.add_argument("--integration", required=True)
    record.add_argument("--output", type=Path, required=True)
    record.add_argument("--evidence-class", choices=["synthetic", "captured", "live"], required=True)
    record.add_argument("--timeout", type=int, default=600)
    record.add_argument("command", nargs=argparse.REMAINDER)
    check = sub.add_parser("check")
    check.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.mode == "check":
        errors = validate(ROOT, args.directory)
        print(json.dumps({"status": "inconsistent" if errors else "consistent", "errors": errors}))
        return int(bool(errors))
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if command[:1] == ["python"]:
        command[0] = sys.executable
    receipt = capture(ROOT, args.integration, args.output, command, args.evidence_class, args.timeout)
    return int(receipt["returncode"] != 0 or receipt["timed_out"])


if __name__ == "__main__":
    raise SystemExit(main())
