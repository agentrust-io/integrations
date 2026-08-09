#!/usr/bin/env python3
"""DecisionAssure trace -> TRACE v0.2 Trust Record.

DecisionAssure is a software runtime governance engine. It does not attest
anything in hardware, and this adapter does not pretend otherwise: the record it
emits carries ``origin.kind: third-party-control-plane``,
``runtime.platform: software-only`` and ``appraisal.status: none``, so a consumer
can tell it apart from a TEE-backed record without reading this file.

Two inputs come from the operator rather than from the DecisionAssure trace,
because the trace does not contain them and inventing them was how the previous
version of this adapter produced records that failed validation on seven counts:

``--policy-bundle``  the policy bytes that were in force. ``policy.bundle_hash``
                     is a digest of the bundle, not of its name or of the
                     decision it produced.
``--subject``        the SPIFFE or DID identity of the workload. An adapter may
                     not mint an identity under a domain nobody controls.

Usage:
    python da_to_trace.py trace.json \\
        --subject spiffe://example.org/agent/da-1 \\
        --policy-bundle policy.json \\
        --workload-digest sha256:<64 hex> > record.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from agentrust_trace_adapters import MissingEvidence, PolicyEvidence, SourceSystem, build_record

PRODUCER = "decisionassure/1.2"


def map_trace(
    da_trace: dict,
    *,
    subject: str,
    policy_bundle: bytes,
    workload_digest: str,
    jwk: dict,
    model_provider: str,
    model_id: str,
) -> dict:
    """Map one DecisionAssure trace onto a Trust Record.

    The engine's own ALLOW/DENY is *not* mapped to ``appraisal.status``. That
    field says whether anybody appraised the evidence, and a control plane
    reporting its own decision has not. The decision is a property of the
    execution the record describes, and it travels in the tool transcript with
    the rest of the trace, hashed, rather than being promoted to a verdict.
    """
    steps = da_trace.get("steps") or []
    transcript = json.dumps(steps, sort_keys=True, separators=(",", ":")).encode()

    return build_record(
        source=SourceSystem(
            producer=PRODUCER,
            source_event_id=da_trace.get("trace_id"),
        ),
        subject=subject,
        model_provider=model_provider,
        model_id=model_id,
        policy=PolicyEvidence(bundle=policy_bundle, enforcement_mode="enforce"),
        data_class=da_trace.get("data_class", "unclassified"),
        workload_digest=workload_digest,
        transcript_bytes=transcript,
        tool_call_count=len(steps),
        jwk=jwk,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("trace", help="DecisionAssure trace JSON")
    ap.add_argument("--subject", required=True, help="spiffe:// or did: identity of the workload")
    ap.add_argument(
        "--policy-bundle",
        required=True,
        help="File holding the policy bytes that were in force",
    )
    ap.add_argument(
        "--workload-digest",
        required=True,
        help="sha256:/sha384: digest of the artifact that ran",
    )
    ap.add_argument(
        "--jwk",
        required=True,
        help="File holding the public confirmation key (JWK JSON) the record will be signed with",
    )
    ap.add_argument("--model-provider", default="unspecified")
    ap.add_argument("--model-id", default="unspecified")
    args = ap.parse_args()

    da_trace = json.loads(pathlib.Path(args.trace).read_text())
    try:
        record = map_trace(
            da_trace,
            subject=args.subject,
            policy_bundle=pathlib.Path(args.policy_bundle).read_bytes(),
            workload_digest=args.workload_digest,
            jwk=json.loads(pathlib.Path(args.jwk).read_text()),
            model_provider=args.model_provider,
            model_id=args.model_id,
        )
    except MissingEvidence as exc:
        print(f"cannot build a truthful record: {exc}", file=sys.stderr)
        return 2

    json.dump(record, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
