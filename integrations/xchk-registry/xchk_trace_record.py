"""Verify a Trust Record minted by an xChk registry against a key the relying party trusts. Apache-2.0.

    python xchk_trace_record.py record.json                      # the key the resolver publishes under the record's kid
    python xchk_trace_record.py record.json --jwk expected.json  # offline: a pinned signer key

The registry signs each record with its seal key. The record's `cnf.jwk` carries that key and its `kid`; the same
key is published at `<resolver>/.well-known/xchk-keys.json`, where `<resolver>` is the one the record's references
name. This tool verifies with the pinned key when given one, else with the published key under that `kid`. It never
verifies against the key the record itself carries: a self-signed record always passes that, which proves integrity
and not origin.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path

from agentrust_trace import verify_record
from cryptography.exceptions import InvalidSignature


def record_verifies(record: dict, jwk: dict) -> bool:
    try:
        verify_record(record, jwk, max_age_seconds=None)
    except (InvalidSignature, ValueError):
        return False
    return True


def key_from_published(doc: dict, kid: str) -> dict | None:
    """The Ed25519 key with this id from the registry's key document, as a JWK; None when absent."""
    for k in doc.get("keys") or []:
        if k.get("keyId") == kid and k.get("alg") == "ed25519" and k.get("publicKeyRaw"):
            raw = base64.b64decode(k["publicKeyRaw"])
            if len(raw) != 32:
                return None
            return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="), "kid": kid}
    return None


def published_key(resolver: str, kid: str, timeout: float = 20.0) -> dict | None:
    url = f"{resolver.rstrip('/')}/.well-known/xchk-keys.json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            doc = json.load(r)
    except Exception:  # noqa: BLE001
        return None
    return key_from_published(doc, kid) if isinstance(doc, dict) else None


def resolver_of(record: dict) -> str | None:
    refs = [r for r in record.get("references", []) if isinstance(r, dict) and r.get("resolver")]
    return refs[0]["resolver"] if refs else None


def verify_with_key_source(record: dict, pinned: dict | None, fetch=published_key) -> dict:
    cnf = (record.get("cnf") or {}).get("jwk") or {}
    kid = cnf.get("kid")
    if pinned:
        return {"status": "verified" if record_verifies(record, pinned) else "invalid", "key_source": "pinned", "kid": pinned.get("kid") or kid}
    resolver = resolver_of(record)
    if resolver and kid:
        key = fetch(resolver, kid)
        if key:
            return {"status": "verified" if record_verifies(record, key) else "invalid", "key_source": "published", "kid": kid, "resolver": resolver}
    return {"status": "no-key", "key_source": None, "kid": kid, "note": "pass --jwk, or let the record's resolver publish the key"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify an xChk registry's Trust Record against a pinned or published key.")
    ap.add_argument("record")
    ap.add_argument("--jwk", help="a JSON file with trace_signer_jwk (or a bare JWK): the pinned key to verify with")
    a = ap.parse_args(argv)
    record = json.loads(Path(a.record).read_text(encoding="utf-8"))
    jwk = None
    if a.jwk:
        j = json.loads(Path(a.jwk).read_text(encoding="utf-8"))
        jwk = j.get("trace_signer_jwk", j)
    out = verify_with_key_source(record, jwk)
    out["approval_outcome_references"] = [
        {"id": r.get("id"), "resolver": r.get("resolver"), "digest": r.get("digest")}
        for r in record.get("references", []) if isinstance(r, dict) and r.get("rel") == "approval-outcome"
    ]
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
