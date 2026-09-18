#!/usr/bin/env python3
"""Emit a TRACE v0.2 record from the executed-ALLOW fixture.

Requires a signed authorization result plus an independent execution receipt.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ontoguard_trace import AdapterError, project  # noqa: E402

DEFAULT_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "allow_execution_proven.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    parser.add_argument("--unsigned", action="store_true")
    args = parser.parse_args()

    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    if not fixture.get("execution_receipt"):
        print("ERROR: fixture has no independent execution receipt", file=sys.stderr)
        return 2
    try:
        result = project(
            fixture["authorization_result"],
            signature_b64url=fixture["authorization_signature"],
            public_jwk=fixture["authorization_public_jwk"],
            claimed_digest=fixture["authorization_result_bytes_sha256"],
            result_bytes=fixture["authorization_result_exact"].encode("utf-8"),
            execution_receipt=fixture["execution_receipt"],
            sign_trace=not args.unsigned,
            allow_test_keys=True,
        )
    except AdapterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.unsigned:
        out = Path(args.out)
        out.write_text(json.dumps(result.get("trace_claim_candidate"), indent=2) + "\n", encoding="utf-8")
        print(f"WROTE_CANDIDATE {out}")
        print("TRACE_RECORD_EMITTED=false")
        return 0
    if not result.get("trace_record_emitted"):
        print(f"ERROR: no TRACE record emitted (state={result.get('state')})", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.write_text(json.dumps(result["trace_record"], indent=2) + "\n", encoding="utf-8")
    print(f"WROTE {out}")
    print(f"STATE={result['state']}")
    print(f"SIGNED={result.get('signed')}")
    print(f"RESULT_DIGEST={result['authorization']['result_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
