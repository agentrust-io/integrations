#!/usr/bin/env python3
"""Emit a TRACE Trust Record from a comply54 ComplianceResult.

Maps the committed example fixture (a denied high-value transfer, exceeding
the CBN NIP transaction cap) onto a TRACE v0.2 Trust Record using the same
`comply54_to_trace_payload` mapping the adapter's own test suite already
verifies against agentrust-trace-tests Level 0.

Two files are written:

  <out>              unsigned record for `trace-tests verify` — this is the
                     plain payload dict (includes `cnf.jwk`, no `signature`
                     field), the same shape the adapter's own
                     TestLevel0Conformance suite grades via the internal
                     trace_tests API.
  <out>.signed.jwt   the same payload, compact-serialized and signed as an
                     Ed25519 JWT via PyJWT (comply54_to_trace.py's own
                     signing path), with an immediate decode-and-verify
                     round trip against the public key — proves the
                     sign/verify path is real, not just that the payload
                     shape is correct.

The ephemeral key is generated per run and never persisted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from comply54_to_trace import (
    comply54_to_trace_payload,
    load_or_generate_key,
)

DEFAULT_RESULT = Path(__file__).resolve().parent / "fixtures" / "deny-cbn-nip-cap.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path for the trace-tests-gradable record")
    parser.add_argument("--result", default=str(DEFAULT_RESULT), help="comply54 ComplianceResult JSON path")
    parser.add_argument("--agent-id", default="payments-agent", help="Agent SPIFFE identity suffix")
    parser.add_argument("--model", default="anthropic/claude-sonnet-4-6", help="Model in provider/model-id format")
    args = parser.parse_args()

    result = json.loads(Path(args.result).read_text(encoding="utf-8"))

    key = load_or_generate_key()
    payload = comply54_to_trace_payload(result, args.agent_id, args.model, key=key)

    token = pyjwt.encode(payload, key, algorithm="EdDSA", headers={"alg": "EdDSA", "typ": "JWT"})
    decoded = pyjwt.decode(token, key.public_key(), algorithms=["EdDSA"])
    assert decoded["eat_profile"] == payload["eat_profile"], "sign/verify round trip mismatch"

    out = Path(args.out)
    out.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    signed_out = out.with_name(out.name + ".signed.jwt")
    signed_out.write_text(token + "\n", encoding="utf-8")

    print(f"subject:  {payload['subject']}")
    print(f"appraisal: {payload['appraisal']['status']}")
    print(f"unsigned (for trace-tests): {out}")
    print(f"signed   (decode/verify OK): {signed_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
