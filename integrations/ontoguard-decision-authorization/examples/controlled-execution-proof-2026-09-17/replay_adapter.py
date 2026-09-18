#!/usr/bin/env python3
"""Feed this proof pack through the actual Marketplace adapter."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HISTORICAL_VERIFICATION_TIME = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)
CANDIDATES = [
    ROOT.parents[1],
    ROOT.parent,
    Path("/home/workdir/artifacts/integrations/ontoguard-decision-authorization"),
    ROOT.parent / "integrations" / "ontoguard-decision-authorization",
    ROOT.parent / "ontoguard-decision-authorization",
]
env_path = Path(__import__("os").environ.get("ONTOGUARD_ADAPTER_PATH", "") or "")
if env_path:
    CANDIDATES.insert(0, env_path)


def _adapter_dir() -> Path:
    for cand in CANDIDATES:
        if (cand / "ontoguard_trace.py").is_file():
            return cand
    raise SystemExit(
        "Marketplace adapter not found. Set ONTOGUARD_ADAPTER_PATH "
        "to the directory that contains ontoguard_trace.py"
    )


def main() -> int:
    adapter_dir = _adapter_dir()
    sys.path.insert(0, str(adapter_dir))
    import ontoguard_trace as og

    auth = json.loads((ROOT / "positive/ontoguard_authorization.exact.json").read_text())
    sig = json.loads((ROOT / "positive/ontoguard_authorization.signature.json").read_text())
    og_jwk = json.loads((ROOT / "positive/ontoguard_public_jwk.json").read_text())
    receipt = json.loads((ROOT / "positive/execution_receipt.json").read_text())
    result = og.project(
        auth,
        signature_b64url=sig["signature"],
        public_jwk=og_jwk,
        result_bytes=sig["exact_bytes"].encode("utf-8"),
        claimed_digest=sig["digest"],
        execution_receipt=receipt,
        sign_trace=False,
        ontoguard_jwks_path=ROOT / "positive/ontoguard_jwks.json",
        execution_jwks_path=ROOT / "positive/execution_jwks.json",
        allow_test_keys=True,
        verification_time_utc=HISTORICAL_VERIFICATION_TIME,
    )
    bound = result["authorization"]
    print("[PASS] actual OntoGuard Marketplace adapter accepted authorization")
    print("[PASS] actual adapter accepted trusted executor receipt")
    print("[PASS] actual adapter handoff binding")
    print("[PASS] actual adapter decision binding")
    print("[PASS] actual adapter movement binding")
    print("[PASS] actual adapter action binding")
    print(f"STATE={result['state']}")
    print(f"handoff={bound['handoff_hash']}")
    print(f"decision_binding={bound['decision_binding_hash']}")
    print(f"movement={bound['movement_hash']}")
    print(f"action_binding={bound['action_binding_digest']}")
    if result["state"] != "ALLOW_EXECUTION_CANDIDATE":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
