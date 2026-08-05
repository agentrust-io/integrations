#!/usr/bin/env python3
"""Emit a signed TRACE v0.2 software-only record from a V5 receipt fixture."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentrust_trace
from _receipt_verify import CONFORMANCE_PUBLIC_KEYS, verify_v5_receipt
from ramen_ai_trace import build_trace_record

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vector1_allowed.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Signed TRACE JSON output path")
    parser.add_argument("--fixture", default=str(FIXTURE), help="V5 receipt fixture JSON")
    parser.add_argument("--model-provider", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--model-version")
    parser.add_argument("--data-class", required=True)
    parser.add_argument("--policy-bundle-hash", required=True)
    parser.add_argument("--slsa-level", required=True, type=int, choices=range(4))
    parser.add_argument("--build-digest", required=True)
    parser.add_argument("--builder")
    parser.add_argument("--provenance-uri")
    parser.add_argument("--appraisal-verifier", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    receipt: dict = fixture["receipt"]

    valid, reason = verify_v5_receipt(
        receipt,
        fixture["input"],
        extra_keys=CONFORMANCE_PUBLIC_KEYS,
    )
    if not valid:
        print(f"ERROR: fixture receipt failed verification: {reason}", file=sys.stderr)
        return 1
    print(f"Fixture receipt verified OK (kid={receipt['kid']})")

    model = {"provider": args.model_provider, "model_id": args.model_id}
    if args.model_version:
        model["version"] = args.model_version

    build_provenance = {
        "slsa_level": args.slsa_level,
        "digest": args.build_digest,
    }
    if args.builder:
        build_provenance["builder"] = args.builder
    if args.provenance_uri:
        build_provenance["provenance_uri"] = args.provenance_uri

    record = build_trace_record(
        receipt,
        original_input=fixture["input"],
        iat=int(time.time()),
        model=model,
        data_class=args.data_class,
        policy_bundle_hash=args.policy_bundle_hash,
        build_provenance=build_provenance,
        appraisal_verifier=args.appraisal_verifier,
        receipt_public_keys=CONFORMANCE_PUBLIC_KEYS,
    )

    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if not pem:
        print("ERROR: TRACE_PRIVATE_KEY_PEM is required", file=sys.stderr)
        return 1
    trusted_jwk = agentrust_trace.key_to_jwk(agentrust_trace.load_key(pem))
    agentrust_trace.verify_record(record, trusted_jwk)
    print("Native sign_record / pinned-key verify_record round-trip OK")

    out = Path(args.out)
    out.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"Signed TRACE v0.2 record: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
