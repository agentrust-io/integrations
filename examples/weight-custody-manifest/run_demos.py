#!/usr/bin/env python3
"""Run every offline WCM demo and the unit tests, and report what broke.

This exists because of a specific failure. weight-custody-manifest 0.27.0
shipped two correct security changes, and both broke demos in this directory:
key release began refusing manifests whose identity was not pinned out of band,
and the memory-fingerprint challenge began requiring a signed sweep. Six demos
that passed on 0.26.0 failed on 0.27.0, and nothing caught it, because the SDK
repository had no way to run these and this repository only tested against
whatever was already published.

So the list of what to run lives here, next to the demos, and both repositories
call it: this repository's CI on every PR, and the SDK's CI against a wheel
built from the branch under review. A change that breaks these now fails on the
pull request that causes it rather than after a release is on PyPI.

**Demos are discovered, not listed.** Every top-level module that is not a test
and not explicitly excluded gets run. A new demo is covered the day it lands,
which is the point: the gap was a change nobody happened to exercise. A demo
that genuinely cannot run offline has to be added to ``REQUIRES_NETWORK`` with a
reason, which is a visible decision rather than a silent omission.

Usage::

    python run_demos.py             # demos, then pytest
    python run_demos.py --list      # show what would run, and what is skipped
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent

#: Scripts that cannot run in a bare CI container, and why. Anything here is
#: reported as skipped rather than quietly dropped, so the exclusions stay
#: visible every run instead of living in a comment nobody re-reads.
REQUIRES_NETWORK = {
    "real_open_model.py": "downloads a real model from the Hugging Face Hub",
    "real_lora_custody.py": "trains a LoRA adapter; needs torch and a download",
}

#: This file.
SELF = pathlib.Path(__file__).name


def demos() -> list[pathlib.Path]:
    """Every runnable demo, sorted, excluding tests, shared helpers and this runner."""
    return sorted(
        path
        for path in HERE.glob("*.py")
        if path.name != SELF
        and not path.name.startswith(("test_", "_"))
        and path.name not in REQUIRES_NETWORK
    )


def run(command: list[str], label: str) -> tuple[bool, float, str]:
    started = time.perf_counter()
    completed = subprocess.run(
        command, cwd=HERE, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    elapsed = time.perf_counter() - started
    # Both streams: a demo that prints its refusal to stdout and traces to
    # stderr is the normal shape here, and reading only one of them has sent
    # people looking in the wrong place.
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, elapsed, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the plan and exit")
    parser.add_argument("--no-tests", action="store_true", help="skip the pytest run")
    args = parser.parse_args(argv)

    scripts = demos()

    if args.list:
        print(f"{len(scripts)} demo(s) would run:")
        for path in scripts:
            print(f"  {path.name}")
        print(f"\n{len(REQUIRES_NETWORK)} skipped:")
        for name, why in sorted(REQUIRES_NETWORK.items()):
            print(f"  {name}: {why}")
        return 0

    try:
        import wcm

        print(f"weight-custody-manifest {wcm.__version__}\n")
    except ImportError:
        print("weight-custody-manifest is not installed", file=sys.stderr)
        return 1

    failures: list[tuple[str, str]] = []

    for path in scripts:
        ok, elapsed, output = run([sys.executable, path.name], path.name)
        print(f"{'ok  ' if ok else 'FAIL'} {path.name:<32} {elapsed:5.1f}s")
        if not ok:
            failures.append((path.name, output))

    for name, why in sorted(REQUIRES_NETWORK.items()):
        print(f"skip {name:<32}       {why}")

    if not args.no_tests:
        ok, elapsed, output = run(
            [sys.executable, "-m", "pytest", ".", "-q"], "pytest"
        )
        print(f"{'ok  ' if ok else 'FAIL'} {'unit tests':<32} {elapsed:5.1f}s")
        if not ok:
            failures.append(("unit tests", output))

    if not failures:
        print(f"\nall {len(scripts)} demos and the unit tests pass")
        return 0

    # The output is printed after the summary, not interleaved, so the shape of
    # the failure is visible before the detail. Six demos failing the same way
    # is a different problem from one failing on its own, and that is the first
    # thing worth knowing.
    print(f"\n{len(failures)} failure(s): {', '.join(name for name, _ in failures)}\n")
    for name, output in failures:
        print("=" * 72)
        print(name)
        print("=" * 72)
        print(output.strip()[-4000:])
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
