"""Verify a Trust Record minted by an xChk registry against a key the relying party trusts. Apache-2.0.

    python xchk_trace_record.py record.json                      # the key the resolver publishes under the record's kid
    python xchk_trace_record.py record.json --jwk expected.json  # offline: a pinned signer key

The registry signs each record with its seal key. The record's `cnf.jwk` carries that key and its `kid`; the same
key is published at `<resolver>/.well-known/xchk-keys.json`, where `<resolver>` is the one the record's references
name. This tool verifies with the pinned key when given one, else with the published key under that `kid`. It never
verifies against the key the record itself carries: a self-signed record always passes that, which proves integrity
and not origin. The record's age is bounded (default 24 hours, --max-age, never off; --now re-verifies a retained
record at its own time) and the revocation outcome is printed as the library reported it: with no revocation bundle
or store, `no_check_performed`, which is not an affirming appraisal (section 3.2.3).
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


# Section 3.2.2's default maximum record age, the library's own default. The age check is never disabled here: a
# record older than the bound is reported `invalid` with the reason, and a historical record is re-verified at its
# own time with --now, not by widening the bound to nothing. (18 Oct 2026, review of integrations#338.)
MAX_AGE_SECONDS = 86400


def verification(record: dict, jwk: dict, max_age_seconds: int = MAX_AGE_SECONDS, now: int | None = None) -> dict:
    """The library's verdict on a record under a trusted key: status, the revocation outcome as the library
    reported it (section 3.2.3: `no_check_performed` when no bundle or store was given, as here), and the reason
    for a refusal. `max_age_seconds` must be a positive bound."""
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive number of seconds; the age check cannot be disabled")
    try:
        result = verify_record(record, jwk, max_age_seconds=max_age_seconds, now=now)
    except InvalidSignature:
        return {"status": "invalid", "reason": "signature does not verify", "revocation": None}
    except ValueError as e:
        return {"status": "invalid", "reason": str(e), "revocation": None}
    revocation = getattr(result, "revocation", None)
    return {"status": "verified", "revocation": getattr(revocation, "outcome", None) or "no_check_performed"}


def record_verifies(record: dict, jwk: dict, max_age_seconds: int = MAX_AGE_SECONDS, now: int | None = None) -> bool:
    return verification(record, jwk, max_age_seconds, now)["status"] == "verified"


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


def verify_with_key_source(record: dict, pinned: dict | None, fetch=published_key,
                           max_age_seconds: int = MAX_AGE_SECONDS, now: int | None = None) -> dict:
    cnf = (record.get("cnf") or {}).get("jwk") or {}
    kid = cnf.get("kid")
    bounds = {"max_age_seconds": max_age_seconds}
    if pinned:
        return {**verification(record, pinned, max_age_seconds, now), "key_source": "pinned", "kid": pinned.get("kid") or kid, **bounds}
    resolver = resolver_of(record)
    if resolver and kid:
        key = fetch(resolver, kid)
        if key:
            return {**verification(record, key, max_age_seconds, now), "key_source": "published", "kid": kid, "resolver": resolver, **bounds}
    return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, **bounds,
            "note": "pass --jwk, or let the record's resolver publish the key"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify an xChk registry's Trust Record against a pinned or published key.")
    ap.add_argument("record")
    ap.add_argument("--jwk", help="a JSON file with trace_signer_jwk (or a bare JWK): the pinned key to verify with")
    ap.add_argument("--max-age", type=int, default=MAX_AGE_SECONDS, metavar="SECONDS",
                    help=f"how old the record's iat may be (default {MAX_AGE_SECONDS}, section 3.2.2); must be positive")
    ap.add_argument("--now", type=int, default=None, metavar="EPOCH_SECONDS",
                    help="verify as of this moment instead of the clock: a retained record re-verified at its own time")
    a = ap.parse_args(argv)
    if a.max_age <= 0:
        ap.error("--max-age must be positive; the age check cannot be disabled")
    record = json.loads(Path(a.record).read_text(encoding="utf-8"))
    jwk = None
    if a.jwk:
        j = json.loads(Path(a.jwk).read_text(encoding="utf-8"))
        jwk = j.get("trace_signer_jwk", j)
    out = verify_with_key_source(record, jwk, max_age_seconds=a.max_age, now=a.now)
    out["approval_outcome_references"] = [
        {"id": r.get("id"), "resolver": r.get("resolver"), "digest": r.get("digest")}
        for r in record.get("references", []) if isinstance(r, dict) and r.get("rel") == "approval-outcome"
    ]
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
