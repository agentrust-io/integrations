"""Build and verify a signed TRACE record from OpenShell and AGT evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentrust_trace import generate_key, key_to_jwk, sign_record, verify_record
from agentrust_trace_adapters import OpenShellEvidence, build_openshell_record

HERE = Path(__file__).resolve().parent
WORKLOAD_DIGEST = "sha256:" + "a" * 64


def build_signed_demo_record() -> dict:
    decisions = json.loads((HERE / "acs-decisions.json").read_text(encoding="utf-8"))
    key = generate_key()
    jwk = key_to_jwk(key)
    evidence = OpenShellEvidence(
        sandbox_id="sandbox-abc123",
        policy_revision="105",
        openshell_policy=(HERE / "effective-policy.yaml").read_bytes(),
        acs_manifest=(HERE / "agent-control.yaml").read_bytes(),
        ocsf_jsonl=(HERE / "openshell-ocsf.jsonl").read_bytes(),
        acs_decisions=tuple(decisions),
        capture_start=1_786_579_199_000,
        capture_end=1_786_579_201_000,
        capture_complete=True,
        openshell_version="0.0.105",
    )
    unsigned = build_openshell_record(
        evidence,
        subject="spiffe://demo.agentrust.io/agent/support-bot",
        model_provider="openai",
        model_id="gpt-5",
        data_class="internal",
        workload_digest=WORKLOAD_DIGEST,
        jwk=jwk,
    )
    signed = sign_record(unsigned, key)
    verify_record(signed, jwk)
    return signed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=HERE / "signed-record.json")
    args = parser.parse_args()
    record = build_signed_demo_record()
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"verified TRACE Level 0 record: {args.output}")


if __name__ == "__main__":
    main()
