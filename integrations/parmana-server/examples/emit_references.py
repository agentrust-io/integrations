#!/usr/bin/env python3
"""Write the TRACE `references` entries for the three fixture decisions.

For each Parmana record in fixtures/, checks its signature offline, then
writes the entries an agent runtime would sign into its own Trust Record
for that step to fixtures/references.json. It issues no Trust Record: the
runtime's subject, model, data class and build provenance are not Parmana's
to state, so nothing here fills them in.

The resolver is an example deployment URL. A real runtime names the Parmana
deployment that retains the record.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import parmana_evidence as pe  # noqa: E402

FIXTURES = ROOT / "fixtures"
RESOLVER = "https://parmana.example.org"
RETENTION = "P1Y"
CASES = {
    "valid-approval": "01-valid-approval.execution-trust-record.json",
    "refusal": "02-refusal.refusal-record.json",
    "replay": "03-replay.refusal-record.json",
}


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def main() -> int:
    signing = load("parmana-signing-key.json")
    keys = {signing["keyId"]: signing["pem"]}
    out = {}
    for case, name in CASES.items():
        record = load(name)
        check = (
            pe.verify_trust_record(record, keys)
            if "trustRecordId" in record
            else pe.verify_refusal_record(record, keys)
        )
        if not check.valid:
            sys.exit(f"{name} does not verify: {check.errors}")
        out[case] = pe.references_for(record, RESOLVER, RETENTION)
        for entry in out[case]:
            print(f"{case:15} {entry['rel']:18} {entry['digest']}")
    (FIXTURES / "references.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
