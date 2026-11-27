"""Emit a Level 0 TRACE record from a freshly written demo bundle (CI / reviewer).

    python emit_record.py --out trust-record.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import auditant_trace  # noqa: E402
import make_demo_bundle  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("trust-record.json"))
    ap.add_argument("--bundle", type=Path, default=Path("demo-bundle.json"))
    args = ap.parse_args()
    make_demo_bundle.build(args.bundle)
    # "declared": the demo bundle is synthetic, so no policy engine evaluated anything.
    return auditant_trace.main(
        [
            str(args.bundle),
            "--out",
            str(args.out),
            "--enforcement-mode",
            "declared",
            "--data-class",
            "internal",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
