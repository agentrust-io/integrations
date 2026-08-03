#!/usr/bin/env python3
"""Emit a TRACE Trust Record from a freshly evaluated APS policy decision.

Runs the real APS path with ephemeral keys: an agent declares an ActionIntent,
an evaluator evaluates it against the Values Floor with FloorValidatorV1, and
the resulting signed PolicyDecision is mapped onto a TRACE Trust Record by
:func:`aps_trace.build_trace_record`. No network access and no credentials.

The decision is minted at run time rather than loaded from a committed fixture
because an APS policy decision expires five minutes after evaluation, and
``build_trace_record`` refuses expired decisions. A committed fixture would be
permanently unmappable, which is the mapper behaving correctly.

Two files are written:

  <out>              Unsigned record, the artifact ``trace-tests verify`` grades
  <out>.signed.json  Signed record, verifiable with
                     ``agentrust_trace.verify_record(..., allow_embedded_key=True)``

Usage:
    python examples/emit_record.py --out trust-record.jwt
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agentrust_trace
from agent_passport.crypto import generate_key_pair
from agent_passport.policy import FloorValidatorV1, create_action_intent, evaluate_intent

from aps_trace import build_trace_record

FLOOR_VERSION = "floor-1.0"


def mint_decision() -> dict:
    """Run one full APS intent-to-decision cycle and return the signed decision."""
    agent = generate_key_pair()
    evaluator = generate_key_pair()

    intent = create_action_intent(
        agent_id="agent_example",
        agent_public_key=agent["publicKey"],
        delegation_id="dlg_example",
        action={"scopeRequired": "repo:read", "description": "read one repository file"},
        private_key=agent["privateKey"],
        context="agentrust-io integration example",
    )

    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    validation_context = {
        "floorVersion": FLOOR_VERSION,
        "agentRegistered": True,
        "agentAttestationValid": True,
        "delegation": {
            "scope": ["repo:read"],
            "revoked": False,
            "expiresAt": expires_at,
            "maxDepth": 3,
            "currentDepth": 1,
        },
    }

    return evaluate_intent(
        intent=intent,
        validator=FloorValidatorV1(),
        validation_context=validation_context,
        evaluator_id="eval_example",
        evaluator_public_key=evaluator["publicKey"],
        evaluator_private_key=evaluator["privateKey"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path for the trace-tests gradable record")
    args = parser.parse_args()

    decision = mint_decision()

    key = agentrust_trace.generate_key()
    jwk = agentrust_trace.key_to_jwk(key)
    record = build_trace_record(decision, trace_jwk=jwk)

    signed = agentrust_trace.sign_record(dict(record), key)
    agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)

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

    print(f"APS verdict:      {decision['verdict']}")
    print(f"appraisal.status: {record['appraisal']['status']}")
    print(f"subject:          {record['subject']}")
    print(f"unsigned (for trace-tests): {out}")
    print(f"signed   (verify_record OK): {signed_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
