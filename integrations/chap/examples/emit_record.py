#!/usr/bin/env python3
"""Emit a signed TRACE Trust Record citing a live CHAP approval.

Runs a CHAP review workspace through `chap-coordinator`, builds the
`approval-outcome` reference for the approval, signs it into a Level 0 Trust
Record, verifies the signature, and checks the reference against CHAP's exported
log before writing anything.

The record's `model`, `runtime`, `policy`, `data_class` and `build_provenance`
belong to the governed run, not to CHAP, so this example fills them with fixed
example values. The ephemeral key proves the sign and verify path; it does not
chain to a trusted issuer.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import agentrust_trace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import chap_demo  # noqa: E402
from chap_trace import CONFIRMED, approval_reference, check_approval  # noqa: E402


def build_record(reference: dict, key, iat: int) -> dict:
    return {
        "eat_profile": agentrust_trace.TRACE_PROFILE_V0_2,
        "iat": iat,
        "subject": "spiffe://trust.example.org/agent/refund-bot",
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "confidential",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": agentrust_trace.key_to_jwk(key)},
        "references": [reference],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path for the signed Trust Record")
    args = parser.parse_args()

    log = chap_demo.refund_review().export()
    approval = chap_demo.entry_for(log, "decide.approve")
    reference = approval_reference(approval, chap_demo.RESOLVER, retention="P1Y")

    key = agentrust_trace.generate_key()
    record = agentrust_trace.sign_record(build_record(reference, key, int(time.time())), key)
    agentrust_trace.verify_record(record, agentrust_trace.key_to_jwk(key))

    check = check_approval(record["references"][0], log["entries"], log["chain_head"])
    if check.verdict != CONFIRMED:
        sys.exit(f"the reference does not check out against the CHAP log: {check}")

    Path(args.out).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"CHAP approval: audit/{approval['seq']}  {reference['digest']}")
    print(f"check:         {check.verdict}")
    print(f"signed record: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
