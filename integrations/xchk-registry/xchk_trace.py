"""Resolve a TRACE Trust Record's approval-outcome references against an xChk registry and report what a
relying party may conclude about each. Apache-2.0.

    python xchk_trace.py record.json                      # key from the resolver's published keys; references resolved there
    python xchk_trace.py record.json --jwk expected.json  # offline: a pinned signer key
    python xchk_trace.py record.json --bundle b.json      # offline: use this bundle for the one reference
    python xchk_trace.py record.json --allow-embedded-key # self-consistency only (exit 1): the record's own cnf.jwk

The Trust Record is verified with agentrust-trace against a key the caller trusts: pinned, or the one the record's
resolver publishes under the record's kid. The record's own `cnf.jwk` is used only on request and reported as
self-consistent, never as verified: a self-signed record always passes against its own key.

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
import base64
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


def record_verifies(record: dict, jwk: dict) -> bool:
    """True when the record's signature verifies with `jwk`. The caller chooses the key; this never reads one
    out of the record, because a record verified against its own `cnf.jwk` is only self-consistent (any
    self-signed record passes that), which the TRACE spec names as the operator-forgeable case."""
    try:
        verify_record(record, jwk, max_age_seconds=None)
    except (InvalidSignature, ValueError):
        return False
    return True


def published_key(resolver: str, kid: str, timeout: float = 20.0) -> dict | None:
    """The registry's published Ed25519 key with this id, as a JWK, from `<resolver>/.well-known/xchk-keys.json`;
    None when the document is unreachable or names no such key."""
    url = f"{resolver.rstrip('/')}/.well-known/xchk-keys.json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            doc = json.load(r)
    except Exception:  # noqa: BLE001
        return None
    return key_from_published(doc, kid)


def key_from_published(doc: dict, kid: str) -> dict | None:
    for k in doc.get("keys") or []:
        if k.get("keyId") == kid and k.get("alg") == "ed25519" and k.get("publicKeyRaw"):
            raw = base64.b64decode(k["publicKeyRaw"])
            if len(raw) != 32:
                return None
            return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="), "kid": kid}
    return None


def verify_with_key_source(record: dict, pinned: dict | None, allow_embedded: bool, fetch=published_key) -> dict:
    """Pick the key and say where it came from. Order: a pinned key; the key the record's resolver publishes under
    the record's kid; the record's own cnf.jwk only when the caller asked for it, reported as self-consistent."""
    cnf = (record.get("cnf") or {}).get("jwk") or {}
    kid = cnf.get("kid")
    if pinned:
        return {"status": "verified" if record_verifies(record, pinned) else "invalid", "key_source": "pinned", "kid": pinned.get("kid") or kid}
    refs = [r for r in record.get("references", []) if r.get("resolver")]
    resolver = refs[0]["resolver"] if refs else None
    if resolver and kid:
        key = fetch(resolver, kid)
        if key:
            return {"status": "verified" if record_verifies(record, key) else "invalid", "key_source": "published", "kid": kid, "resolver": resolver}
    if allow_embedded and cnf:
        return {"status": "self-consistent" if record_verifies(record, cnf) else "invalid", "key_source": "embedded", "kid": kid,
                "note": "verified against the key the record carries: integrity only, not origin"}
    return {"status": "no-key", "key_source": None, "kid": kid, "note": "pass --jwk, or let the record's resolver publish the key"}


def fetch_bundle(resolver: str, ref_id: str, timeout: float = 20.0) -> dict | None:
    url = f"{resolver.rstrip('/')}/api/receipt/{ref_id}/bundle"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
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
    ap.add_argument("--jwk", help="a JSON file with trace_signer_jwk (or a bare JWK): the pinned key to verify the record with")
    ap.add_argument("--allow-embedded-key", action="store_true",
                    help="with no pinned or published key, verify against the record's own cnf.jwk and report it as self-consistent (integrity only)")
    a = ap.parse_args(argv)
    record = json.loads(Path(a.record).read_text(encoding="utf-8"))
    jwk = None
    if a.jwk:
        j = json.loads(Path(a.jwk).read_text(encoding="utf-8"))
        jwk = j.get("trace_signer_jwk", j)
    signer = verify_with_key_source(record, jwk, a.allow_embedded_key)
    out = {"trace_record": signer, "trace_record_verifies": signer["status"] == "verified", "references": []}
    refs = [r for r in record.get("references", []) if r.get("rel") == "approval-outcome"]
    local = json.loads(Path(a.bundle).read_text(encoding="utf-8")) if a.bundle else None
    for ref in refs:
        bundle = local if local is not None else fetch_bundle(ref["resolver"], ref["id"])
        out["references"].append(assess(ref, bundle))
    print(json.dumps(out, indent=2))
    return 0 if out["trace_record_verifies"] else 1


if __name__ == "__main__":
    sys.exit(main())
