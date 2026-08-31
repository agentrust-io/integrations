"""Emit a Level 0 TRACE record from a freshly sealed .epi (CI / reviewer)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    out_dir = Path("ci-out")
    out_dir.mkdir(exist_ok=True)
    epi = out_dir / "demo.epi"
    rec = Path(sys.argv[1]) if len(sys.argv) > 1 else out_dir / "trust-record.json"
    subprocess.run(
        [sys.executable, "-m", "epi_cli", "record", "--out", str(epi), "--", sys.executable, "-c", "print('epi-trace')"],
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "epi_cli", "export", "trace", str(epi), "--out", str(rec)],
        check=True,
    )
    print(rec.resolve())


if __name__ == "__main__":
    main()
