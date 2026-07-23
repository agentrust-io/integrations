#!/usr/bin/env python3
"""Emit a TRACE Trust Record from a ramen-ai V5 fixture receipt.

Loads ``examples/fixtures/vector1_allowed.json``, maps the receipt onto a TRACE
Trust Record via :func:`ramen_ai_trace.build_trace_record`, signs it with an
ephemeral Ed25519 key via ``agentrust_trace.sign_record``, verifies the
round-trip, and writes two files:

  <out>              Unsigned record for ``trace-tests verify``
  <out>.signed.json  Signed record, verifiable with
                     ``agentrust_trace.verify_record(..., allow_embedded_key=True)``

Usage:
    python examples/emit_record.py --out trust-record.jwt
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentrust_trace
from ramen_ai_trace import build_trace_record

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vector1_allowed.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path for the trace-tests-gradable record")
    args = parser.parse_args()

    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    receipt: dict = fixture["receipt"]

    key = agentrust_trace.generate_key()
    jwk = agentrust_trace.key_to_jwk(key)
    record = build_trace_record(receipt, iat=int(time.time()), jwk=jwk)

    signed = agentrust_trace.sign_record(dict(record), key)
    agentrust_trace.verify_record(signed, allow_embedded_key=True)

    out = Path(args.out)
    out.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    signed_out = out.with_name(out.name + ".signed.json")
    signed_out.write_text(
        json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    print(f"subject:  {record['subject']}")
    print(f"appraisal.status: {record['appraisal']['status']}")
    print(f"unsigned (for trace-tests): {out}")
    print(f"signed   (verify_record OK): {signed_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
