#!/usr/bin/env python3
"""Generate the fixture set committed in trace-spec at examples/chap-approval-outcome/.

trace-spec cannot depend on CHAP, so its CI only re-verifies those files. This script
produces them from a live `chap-coordinator` workspace, and this integration's CI runs
it on every change, so the generator is exercised against the CHAP release it claims.

    python integrations/chap/examples/generate_trace_spec_fixtures.py \\
        --out ../trace-spec/examples/chap-approval-outcome

A run issues a new signing key and new CHAP identifiers, so it replaces the set
rather than reproducing it byte for byte. Every expected outcome below is checked
against `chap_trace.check_approval` before anything is written.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from importlib.metadata import version
from pathlib import Path

import agentrust_trace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import chap_demo  # noqa: E402
from chap_trace import (  # noqa: E402
    CONFIRMED, CONTRADICTED, NOT_AN_APPROVAL, REL, UNCONFIRMED,
    approval_reference, check_approval, envelope_digest,
)
from emit_record import build_record  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Directory to write the fixture set into")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    chap_version = version("chap-coordinator")
    exported = chap_demo.refund_review().export()
    log = {"format": "chap-audit-export/fixture-1",
           "generated_by": f"chap-coordinator {chap_version}",
           "workspace": chap_demo.WORKSPACE, **exported}
    approve = chap_demo.entry_for(log, "decide.approve")
    reject = chap_demo.entry_for(log, "decide.reject")

    altered = copy.deepcopy(log)
    chap_demo.entry_for(altered, "decide.approve")["envelope"]["params"]["comment"] = (
        "Approved after escalation.")
    altered["altered_after_export"] = (
        "decide.approve params.comment changed; chain_head left as exported")

    approval_ref = approval_reference(approve, chap_demo.RESOLVER, retention="P1Y")
    # The two negative references are built by hand on purpose: approval_reference
    # refuses to cite a rejection, and cannot cite an entry that does not exist.
    rejection_ref = {"rel": REL, "id": f"audit/{reject['seq']}", "resolver": chap_demo.RESOLVER,
                     "retention": "P1Y", "digest": envelope_digest(reject["envelope"])}
    missing_seq = max(e["seq"] for e in log["entries"]) + 50
    missing_ref = {**approval_ref, "id": f"audit/{missing_seq}"}

    cases = [
        ("01-approval-confirmed.json", approval_ref, "chap-audit-log.json", log, CONFIRMED),
        ("02-approval-altered-after-issue.json", approval_ref,
         "chap-audit-log-altered.json", altered, CONTRADICTED),
        ("03-decision-is-a-rejection.json", rejection_ref, "chap-audit-log.json", log,
         NOT_AN_APPROVAL),
        ("04-reference-unresolvable.json", missing_ref, "chap-audit-log.json", log, UNCONFIRMED),
    ]

    key = agentrust_trace.generate_key()
    jwk = agentrust_trace.key_to_jwk(key)
    iat = int(time.time())
    expected = {"trace_signer_jwk": jwk, "chap_version": chap_version,
                "resolver": chap_demo.RESOLVER, "cases": {}}
    records = {}
    for name, reference, log_name, log_used, want in cases:
        check = check_approval(reference, log_used["entries"], log_used["chain_head"])
        if check.verdict != want:
            sys.exit(f"{name}: expected {want}, check_approval says {check}")
        record = agentrust_trace.sign_record(build_record(reference, key, iat), key)
        agentrust_trace.verify_record(record, jwk, max_age_seconds=None)
        records[name] = record
        expected["cases"][name] = {
            "log": log_name, "trace_record_verifies": True,
            "reference_resolves": check.reference_resolves,
            "digest_matches": check.digest_matches, "decision": check.decision,
            "chain_replays": check.chain_replays, "verdict": check.verdict,
        }

    def write(name: str, obj: object) -> None:
        (out / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8", newline="\n")

    for stale in out.glob("*.json"):
        stale.unlink()
    write("chap-audit-log.json", log)
    write("chap-audit-log-altered.json", altered)
    for name, record in records.items():
        write(name, record)
    write("expected.json", expected)
    print(f"wrote {len(records)} records, 2 logs and expected.json to {out} "
          f"from chap-coordinator {chap_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
