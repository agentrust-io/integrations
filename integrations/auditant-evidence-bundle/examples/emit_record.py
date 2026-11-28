"""Emit a Level 0 TRACE record from the committed fixture (CI / reviewer).

The bundle is ``fixtures/auditant-full.json``, exported by Auditant's own TypeScript
core, not by this adapter. The operator inputs are demo stand-ins: a SPIFFE ID under
example.org, the policy file ``examples/demo-policy.cedar``, and the digest of
``examples/demo-workload.txt`` in place of an agent image.

    python emit_record.py --out trust-record.json
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import auditant_trace  # noqa: E402

FIXTURE = ROOT / "fixtures" / "auditant-full.json"
SUBJECT = "spiffe://example.org/agent/refund-agent"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("trust-record.json"))
    args = ap.parse_args()
    workload = "sha256:" + hashlib.sha256((HERE / "demo-workload.txt").read_bytes()).hexdigest()
    # advisory: the fixture records a policy decision, and nothing establishes that it held a call.
    return auditant_trace.main(
        [
            str(FIXTURE),
            "--out", str(args.out),
            "--subject", SUBJECT,
            "--policy-bundle", str(HERE / "demo-policy.cedar"),
            "--enforcement-mode", "advisory",
            "--workload-digest", workload,
            "--data-class", "internal",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
