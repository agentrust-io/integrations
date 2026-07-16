#!/usr/bin/env python3
"""Emit a TRACE Trust Record from a SpendGuard evidence bundle.

Maps the committed example bundle (a signed SpendGuard allow decision) onto a
TRACE Trust Record, signs it with an ephemeral Ed25519 key via
`agentrust_trace.sign_record`, and verifies the signature round-trip with
`agentrust_trace.verify_record`.

Two files are written:

  <out>              unsigned record for `trace-tests verify` (the released
                     trace-tests 0.1.0 loader rejects any plain record carrying
                     a top-level `signature` field, so the graded record is the
                     unsigned payload; TR-SIG reports it UNVERIFIED at level 0)
  <out>.signed.json  the signed record, verifiable with
                     `agentrust_trace.verify_record(..., allow_embedded_key=True)`

The ephemeral key is generated per run and never persisted: this proves the
sign/verify path is real, not that the record chains to a trusted issuer.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import agentrust_trace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from spendguard_trace import build_trace_record  # noqa: E402

DEFAULT_BUNDLE = Path(__file__).resolve().parent / "fixtures" / "allow"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path for the trace-tests-gradable record")
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE), help="SpendGuard evidence bundle directory")
    args = parser.parse_args()

    key = agentrust_trace.generate_key()
    jwk = agentrust_trace.key_to_jwk(key)
    record = build_trace_record(Path(args.bundle), iat=int(time.time()), jwk=jwk)

    signed = agentrust_trace.sign_record(dict(record), key)
    agentrust_trace.verify_record(signed, allow_embedded_key=True)

    out = Path(args.out)
    out.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    signed_out = out.with_name(out.name + ".signed.json")
    signed_out.write_text(json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    print(f"subject:  {record['subject']}")
    print(f"unsigned (for trace-tests): {out}")
    print(f"signed   (verify_record OK): {signed_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
