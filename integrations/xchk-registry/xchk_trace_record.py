"""Verify a Trust Record minted by an xChk registry against a key the relying party trusts. Apache-2.0.

    python xchk_trace_record.py record.json --registry https://in.xchk.io   # the key that registry publishes under the record's kid
    python xchk_trace_record.py record.json --jwk expected.json             # offline: a pinned signer key

The registry signs each record with its seal key. The record's `cnf.jwk` carries that key and its `kid`; the same
key is published at `<origin>/.well-known/xchk-keys.json`, where `<origin>` is the registry the relying party trusts,
given out of band with --registry; nothing in the record supplies it. The record's `subject` and `resolver` must
agree with that origin. This tool verifies with the pinned key when given one, else with the published key under
that `kid`. It never verifies against the key the record itself carries, and never fetches a key from a server the
record names, in its references or in its subject: either way a self-made record would pass, which proves integrity
and not origin. Without --registry or --jwk there is no trust anchor and the answer is `no-key`.

The record's age is bounded (default 24 hours, --max-age, never off; --now re-verifies a retained record at its own
time, and every verdict says which instant it was made against). A verified result reports the profile it verified
under and the whole accepted set (section 3.3), and the revocation outcome as the library reported it: with no
revocation bundle or store, `no_check_performed`, which is not an affirming appraisal (section 3.2.3).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
from pathlib import Path

from agentrust_trace import verify_record
from cryptography.exceptions import InvalidSignature


# Section 3.2.2's default maximum record age, the library's own default. The age check is never disabled here: a
# record older than the bound is reported `invalid` with the reason, and a historical record is re-verified at its
# own time with --now, not by widening the bound to nothing. (18 Oct 2026, review of integrations#338.)
MAX_AGE_SECONDS = 86400


def as_of_fields(now: int | None) -> dict:
    """The instant a verdict was made against, and whether the caller supplied it: on EVERY verdict, no-key included."""
    return {"verified_at": int(time.time()) if now is None else int(now), "verified_at_overridden": now is not None}


def verification(record: dict, jwk: dict, max_age_seconds: int = MAX_AGE_SECONDS, now: int | None = None) -> dict:
    """The library's verdict on a record under a trusted key: status, the revocation outcome as the library
    reported it (section 3.2.3: `no_check_performed` when no bundle or store was given, as here), and the reason
    for a refusal. `max_age_seconds` must be a positive bound."""
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive number of seconds; the age check cannot be disabled")
    # the instant every check is made against: the clock, or the one the caller supplied for a historical check.
    # It is in every verdict so two verdicts at different times are never the same JSON (review of #338, 18 Oct 2026).
    when = as_of_fields(now)
    try:
        result = verify_record(record, jwk, max_age_seconds=max_age_seconds, now=when["verified_at"])
    except InvalidSignature:
        return {"status": "invalid", "reason": "signature does not verify", "revocation": None, **when}
    except ValueError as e:
        return {"status": "invalid", "reason": str(e), "revocation": None, **when}
    revocation = getattr(result, "revocation", None)
    # section 3.3: a successful result reports the profile it verified under and the whole set the verifier accepts
    return {"status": "verified", "revocation": getattr(revocation, "outcome", None) or "no_check_performed",
            "profile": getattr(result, "profile", None), "accepted_profiles": list(getattr(result, "accepted_profiles", ()) or ()),
            "trusted_key_thumbprint": getattr(result, "trusted_key_thumbprint", None), **when}


def record_verifies(record: dict, jwk: dict, max_age_seconds: int = MAX_AGE_SECONDS, now: int | None = None) -> bool:
    return verification(record, jwk, max_age_seconds, now)["status"] == "verified"


def key_from_published(doc, kid: str) -> dict | None:
    """The Ed25519 key with this id from the registry's key document, as a JWK; None when absent or when the
    document is not the shape it should be. Nothing in here raises on a bad document: a key server that answers
    nonsense is no key, not a crash (review of #338, 18 Oct 2026)."""
    if not isinstance(doc, dict) or not isinstance(kid, str) or not kid:
        return None
    keys = doc.get("keys")
    if not isinstance(keys, list):
        return None
    for k in keys:
        if not isinstance(k, dict) or k.get("keyId") != kid or k.get("alg") != "ed25519":
            continue
        material = k.get("publicKeyRaw")
        if not isinstance(material, str) or not material:
            return None
        try:
            raw = base64.b64decode(material, validate=True)
        except (ValueError, TypeError):
            return None
        if len(raw) != 32:
            return None
        return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="), "kid": kid}
    return None


# The published-key path, bounded (18 Oct 2026). The key document is fetched from ONE origin, the one the relying
# party passed with --registry; nothing in the record supplies it (see trusted_origin). The record's `subject` and
# `resolver` are checked against it and never followed, because a record that names the server its key will be
# fetched from has chosen its own trust root, which is the embedded-key problem one hop away. Only https; no
# redirects; the document is read to a bound; a document of the wrong shape is no key.
KEY_DOC_MAX_BYTES = 256 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def origin_of_did_web(subject: str) -> str | None:
    """`did:web:host[:port-encoded][:path...]` -> `https://host[:port]`; None for anything else (did-core, did:web)."""
    if not isinstance(subject, str) or not subject.startswith("did:web:"):
        return None
    host = subject.split(":", 2)[2].split(":", 1)[0].replace("%3A", ":").replace("%3a", ":")
    if not host or "/" in host or "@" in host or host.startswith(".") or host.endswith(".") or ".." in host:
        return None
    return f"https://{host.lower()}"


def _same_origin(a: str, b: str) -> bool:
    return a.rstrip("/").lower() == b.rstrip("/").lower()


def published_key(origin: str, kid: str, timeout: float = 20.0) -> dict | None:
    """The key with this id from `<origin>/.well-known/xchk-keys.json`; None when it cannot be had safely."""
    if not isinstance(origin, str) or not origin.lower().startswith("https://"):
        return None
    url = f"{origin.rstrip('/')}/.well-known/xchk-keys.json"
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(url, timeout=timeout) as r:
            if r.status != 200:
                return None
            raw = r.read(KEY_DOC_MAX_BYTES + 1)
        if len(raw) > KEY_DOC_MAX_BYTES:
            return None
        doc = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    try:
        return key_from_published(doc, kid)
    except Exception:  # noqa: BLE001  a document shape nobody foresaw is still no key, never a crash
        return None


def resolver_of(record: dict) -> str | None:
    refs = [r for r in record.get("references", []) if isinstance(r, dict) and r.get("resolver")]
    return refs[0]["resolver"] if refs else None


def trusted_origin(record: dict, registry: str | None) -> tuple[str | None, str | None]:
    """(origin, refusal): the origin the published key may come from, or why there is none. The origin is the relying
    party's, given out of band with --registry; nothing in the record supplies it. (An earlier head derived it from
    the record's did:web subject, which only shows the record agrees with itself: a record signed under a publisher
    of its own choosing names that publisher in its subject too. Review of #338, 18 Oct 2026.) The record's `subject`
    and `resolver` must then agree with the origin, which catches a record that was minted for another registry."""
    if not registry:
        return None, "no trust anchor: pass --registry <https origin of the registry you trust>, or --jwk <its pinned key>"
    if not isinstance(registry, str) or not registry.lower().startswith("https://"):
        return None, "the trusted origin must be https"
    origin = registry.rstrip("/")
    subject_origin = origin_of_did_web(record.get("subject"))
    if subject_origin and not _same_origin(subject_origin, origin):
        return None, f"the record's subject lives under {subject_origin}, not the trusted origin {origin}"
    resolver = resolver_of(record)
    if resolver and not _same_origin(resolver, origin):
        return None, f"the record's resolver {resolver} is not the trusted origin {origin}"
    return origin, None


def verify_with_key_source(record: dict, pinned: dict | None, fetch=published_key,
                           max_age_seconds: int = MAX_AGE_SECONDS, now: int | None = None, registry: str | None = None) -> dict:
    cnf = (record.get("cnf") or {}).get("jwk") or {}
    kid = cnf.get("kid")
    bounds = {"max_age_seconds": max_age_seconds, **as_of_fields(now)}
    if pinned:
        return {**verification(record, pinned, max_age_seconds, now), "key_source": "pinned", "kid": pinned.get("kid") or kid, **bounds}
    origin, refusal = trusted_origin(record, registry)
    if refusal:
        return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, **bounds, "reason": refusal}
    if isinstance(kid, str) and kid:
        key = fetch(origin, kid)
        if key:
            return {**verification(record, key, max_age_seconds, now), "key_source": "published", "kid": kid, "trusted_origin": origin, **bounds}
    return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, "trusted_origin": origin, **bounds,
            "reason": f"no Ed25519 key {kid!r} published at {origin}/.well-known/xchk-keys.json (or pass --jwk)"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify an xChk registry's Trust Record against a pinned or published key.")
    ap.add_argument("record")
    ap.add_argument("--jwk", help="a JSON file with trace_signer_jwk (or a bare JWK): the pinned key to verify with")
    ap.add_argument("--max-age", type=int, default=MAX_AGE_SECONDS, metavar="SECONDS",
                    help=f"how old the record's iat may be (default {MAX_AGE_SECONDS}, section 3.2.2); must be positive")
    ap.add_argument("--registry", metavar="ORIGIN", default=None,
                    help="the https origin of the registry you trust, whose published key verifies the record; required unless "
                         "--jwk pins the key; the record's subject and resolver must agree with it")
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
    out = verify_with_key_source(record, jwk, max_age_seconds=a.max_age, now=a.now, registry=a.registry)
    out["approval_outcome_references"] = [
        {"id": r.get("id"), "resolver": r.get("resolver"), "digest": r.get("digest")}
        for r in record.get("references", []) if isinstance(r, dict) and r.get("rel") == "approval-outcome"
    ]
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
