"""Resolve a TRACE Trust Record's approval-outcome references against an xChk registry and report what a
relying party may conclude about each. Apache-2.0.

    python xchk_trace.py record.json                      # resolves each reference at its resolver
    python xchk_trace.py record.json --bundle b.json      # offline: use this bundle for the one reference
    python xchk_trace.py record.json --jwk expected.json  # verify the record with a pinned signer key

The Trust Record is verified with agentrust-trace. Each `approval-outcome` reference is resolved at
`<resolver>/api/receipt/<id>/bundle`, the bundle's record is canonicalized with RFC 8785 and its digest
compared with the reference, and the bundle is handed to the registry's own offline verifier,
`examples/verify_receipt.py`, as a subprocess. The verdict vocabulary is the one in trace-spec's
`docs/crosswalks/xchk-sealed-receipts.md`:

    approval-confirmed              the bundle verifies and the record's disposition is `approved`
    approval-confirmed-as-amended   as above, with `decision.amendment` present: the approval covers that command
    not-an-approval                 the bundle verifies; the person declined, or nobody answered in time
    approval-contradicted           the bundle fails a check, or its record is not the one the reference names
    approval-unconfirmed            the reference does not resolve (the record still stands: spec 3.1.2 rule 3)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import rfc8785
from agentrust_trace import verify_record
from cryptography.exceptions import InvalidSignature

VERIFIER = Path(__file__).resolve().parent / "examples" / "verify_receipt.py"


def jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def record_verifies(record: dict, jwk: dict | None) -> bool:
    key = jwk or record.get("cnf", {}).get("jwk")
    if not key:
        return False
    try:
        verify_record(record, key, max_age_seconds=None)
    except (InvalidSignature, ValueError):
        return False
    return True


def fetch_bundle(resolver: str, ref_id: str, timeout: float = 20.0) -> dict | None:
    url = f"{resolver.rstrip('/')}/api/receipt/{ref_id}/bundle"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (the resolver is the record's own claim)
            return json.load(r)
    except Exception:  # noqa: BLE001
        return None


def bundle_verifies(bundle: dict, verifier: Path = VERIFIER) -> bool:
    """Exit 0 from the registry's verifier is every offline check passed (pending steps allowed)."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(bundle, f)
        tmp = Path(f.name)
    try:
        proc = subprocess.run([sys.executable, "-I", str(verifier), str(tmp)], capture_output=True, text=True, check=False, timeout=120)
    finally:
        tmp.unlink(missing_ok=True)
    return proc.returncode == 0


def assess(reference: dict, bundle: dict | None) -> dict:
    """What a relying party concludes about one approval-outcome reference."""
    if bundle is None:
        return {"reference": reference["id"], "resolves": False, "digest_matches": None, "bundle_verifies": None,
                "disposition": None, "verdict": "approval-unconfirmed"}
    digest_matches = jcs_sha256(bundle["record"]) == reference["digest"]
    ok = bundle_verifies(bundle)
    disposition = bundle["record"].get("disposition")
    amended = bool(((bundle.get("decision") or {}).get("amendment") or {}).get("command"))
    if not (digest_matches and ok):
        verdict = "approval-contradicted"
    elif disposition != "approved":
        verdict = "not-an-approval"
    elif amended:
        verdict = "approval-confirmed-as-amended"
    else:
        verdict = "approval-confirmed"
    approver = bundle.get("approver") or {}
    return {"reference": reference["id"], "resolves": True, "digest_matches": digest_matches, "bundle_verifies": ok,
            "disposition": disposition, "verdict": verdict,
            "approver": approver.get("email"), "auth_level": approver.get("authLevel"),
            "challenge_rule": (approver.get("challenge") or {}).get("rule")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Resolve a Trust Record's approval-outcome references against an xChk registry.")
    ap.add_argument("record")
    ap.add_argument("--bundle", help="offline: a saved bundle for the record's single approval-outcome reference")
    ap.add_argument("--jwk", help="a JSON file with trace_signer_jwk (or a bare JWK) to verify the record with")
    a = ap.parse_args(argv)
    record = json.loads(Path(a.record).read_text(encoding="utf-8"))
    jwk = None
    if a.jwk:
        j = json.loads(Path(a.jwk).read_text(encoding="utf-8"))
        jwk = j.get("trace_signer_jwk", j)
    out = {"trace_record_verifies": record_verifies(record, jwk), "references": []}
    refs = [r for r in record.get("references", []) if r.get("rel") == "approval-outcome"]
    local = json.loads(Path(a.bundle).read_text(encoding="utf-8")) if a.bundle else None
    for ref in refs:
        bundle = local if local is not None else fetch_bundle(ref["resolver"], ref["id"])
        out["references"].append(assess(ref, bundle))
    print(json.dumps(out, indent=2))
    return 0 if out["trace_record_verifies"] else 1


if __name__ == "__main__":
    sys.exit(main())
