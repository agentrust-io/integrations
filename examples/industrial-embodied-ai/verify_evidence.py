#!/usr/bin/env python3
"""Verify saved example evidence without contacting any service."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
from typing import Any


def verify(claim: dict[str, Any], bundle: dict[str, Any]) -> str:
    # Keep this import lazy so controller-only tests need no runtime packages.
    from agent.material_movement_agent import _verify_evidence

    receipts = [
        entry
        for entry in bundle.get("entries", [])
        if entry.get("external_execution_evidence")
    ]
    if not receipts:
        raise RuntimeError("No controller-signed motion receipt in the bundle")
    # The existing verifier prints intermediate results. Publish them only if
    # every check passes, including the signatures on the external receipts.
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        _verify_evidence(claim, bundle, require_hardware=False)
    return output.getvalue()


def verify_files(claim_path: Path, bundle_path: Path) -> str:
    return verify(
        json.loads(claim_path.read_text()), json.loads(bundle_path.read_text())
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("claim", type=Path)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        report = verify_files(args.claim, args.bundle)
    except (RuntimeError, ValueError, KeyError, TypeError, OSError) as exc:
        print(f"EVIDENCE REJECTED: {exc}", file=sys.stderr)
        return 1
    print(report, end="")
    print("EVIDENCE VERIFIED (software-only development evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
