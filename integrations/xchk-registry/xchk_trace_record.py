"""Verify a Trust Record minted by an xChk registry against a key the relying party trusts. Apache-2.0.

    python xchk_trace_record.py record.json --registry https://in.xchk.io   # the key that registry publishes under the record's kid
    python xchk_trace_record.py record.json --jwk expected.json             # offline: a pinned signer key

The registry signs each record with its seal key. The record's `cnf.jwk` carries that key and its `kid`; the same
key is published at `<origin>/.well-known/xchk-keys.json`, where `<origin>` is the registry the relying party trusts,
given out of band with --registry; nothing in the record supplies it. The record's `subject` must be a `did:web`
under that origin, and every `approval-outcome` reference must resolve there. This tool verifies with the pinned key when given one, else with the published key under
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
import urllib.parse
import urllib.request
from pathlib import Path

from agentrust_trace import jwk_thumbprint, verify_record
from cryptography.exceptions import InvalidSignature


# Section 3.2.2's default maximum record age, the library's own default. The age check is never disabled here: a
# record older than the bound is reported `invalid` with the reason, and a historical record is re-verified at its
# own time with --now, not by widening the bound to nothing. (18 Oct 2026, review of integrations#338.)
MAX_AGE_SECONDS = 86400


class Instant:
    """ONE effective verification instant, frozen where the caller's request enters and used for everything after:
    the library call and every emitted verdict, no-key included. The clock is read at most once per verdict, so the
    instant the library checked against and the instant the verdict reports can never differ (review of #338,
    18 Oct 2026: with a clock answering 100 then 101, the library had been given 101 while the verdict said 100).
    `overridden` says whether the caller supplied it (--now, a retained record re-verified at its own time)."""

    __slots__ = ("at", "overridden")

    def __init__(self, now: int | None = None):
        self.overridden = now is not None
        self.at = int(now) if self.overridden else int(time.time())

    def fields(self) -> dict:
        return {"verified_at": self.at, "verified_at_overridden": self.overridden}


def _instant(now) -> Instant:
    return now if isinstance(now, Instant) else Instant(now)


def verification(record: dict, jwk: dict, max_age_seconds: int = MAX_AGE_SECONDS, now: int | Instant | None = None) -> dict:
    """The library's verdict on a record under a trusted key: status, the revocation outcome as the library
    reported it (section 3.2.3: `no_check_performed` when no bundle or store was given, as here), and the reason
    for a refusal. `max_age_seconds` must be a positive bound. `now` may be an already-frozen Instant."""
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive number of seconds; the age check cannot be disabled")
    instant = _instant(now)
    when = instant.fields()
    if not isinstance(record, dict):
        return {"status": "invalid", "reason": f"record is not a JSON object ({type(record).__name__})", "revocation": None, **when}
    if not is_ed25519_jwk(jwk):
        return {"status": "invalid", "reason": "trusted key is not an Ed25519 JWK", "revocation": None, **when}
    try:
        result = verify_record(record, jwk, max_age_seconds=max_age_seconds, now=instant.at)
    except InvalidSignature:
        return {"status": "invalid", "reason": "signature does not verify", "revocation": None, **when}
    except ValueError as e:
        return {"status": "invalid", "reason": str(e), "revocation": None, **when}
    except Exception as e:  # noqa: BLE001  a record shape the library did not foresee is not verified, and says why
        return {"status": "invalid", "reason": f"{type(e).__name__}: {e}", "revocation": None, **when}
    revocation = getattr(result, "revocation", None)
    # section 3.3: a successful result reports the profile it verified under and the whole set the verifier accepts
    return {"status": "verified", "revocation": getattr(revocation, "outcome", None) or "no_check_performed",
            "profile": getattr(result, "profile", None), "accepted_profiles": list(getattr(result, "accepted_profiles", ()) or ()),
            # RFC 7638 thumbprint of the PUBLIC key the record verified under, from the library's own function (19 Oct
            # 2026: the attribute read was named like a secret to CodeQL's heuristics; the value is a public-key digest)
            "trusted_key_thumbprint": jwk_thumbprint(jwk), **when}


def record_verifies(record: dict, jwk: dict, max_age_seconds: int = MAX_AGE_SECONDS, now: int | Instant | None = None) -> bool:
    return verification(record, jwk, max_age_seconds, now)["status"] == "verified"


def is_ed25519_jwk(jwk) -> bool:
    """An OKP/Ed25519 JWK with base64url key material of 32 bytes; nothing else is a key this tool verifies with."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False
    x = jwk.get("x")
    if not isinstance(x, str) or not x:
        return False
    try:
        return len(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))) == 32
    except (ValueError, TypeError):
        return False


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
    if host.endswith(":443"):   # the same origin as without the port (RFC 6454), as https_origin also says
        host = host[: -len(":443")]
    return f"https://{host.lower()}"


def _same_origin(a, b) -> bool:
    return isinstance(a, str) and isinstance(b, str) and a.rstrip("/").lower() == b.rstrip("/").lower()


def https_origin(value) -> tuple[str | None, str | None]:
    """(origin, refusal): `https://host[:port]` and nothing else: no userinfo, path, query or fragment, because the
    key document's location is derived from it and anything more is a different document."""
    if not isinstance(value, str) or not value:
        return None, "the trusted origin must be an https origin"
    if value != value.strip() or any(c.isspace() or ord(c) < 32 for c in value):
        return None, "the trusted origin must not contain whitespace or control characters"   # urlsplit would quietly strip them
    try:
        u = urllib.parse.urlsplit(value)
        host, port = u.hostname, u.port   # both raise ValueError on a malformed netloc (bad bracket, non-numeric or out-of-range port)
    except ValueError as e:
        return None, f"the trusted origin could not be parsed: {e}"
    if u.scheme.lower() != "https":
        return None, "the trusted origin must be https"
    if not host or u.username is not None or u.password is not None:
        return None, "the trusted origin must be a host, with no credentials"
    if u.path not in ("", "/") or u.query or u.fragment:
        return None, "the trusted origin must be an origin only: no path, query or fragment"
    # the netloc must be exactly host or host:port: a trailing colon, an empty port or anything else in it is refused
    shown = f"[{host.lower()}]" if ":" in host else host.lower()
    if u.netloc.lower() != shown + (f":{port}" if port else ""):
        return None, "the trusted origin must be host or host:port and nothing else"
    # RFC 6454: https on 443 is the same origin with or without the port written
    return f"https://{shown}" + (f":{port}" if port and port != 443 else ""), None


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


def references_of(record) -> list:
    """The record's reference objects; anything that is not a list of objects reads as none."""
    refs = record.get("references") if isinstance(record, dict) else None
    return [r for r in refs if isinstance(r, dict)] if isinstance(refs, list) else []


def approval_resolvers(record) -> tuple[list, str | None]:
    """(resolvers, refusal): the resolver of EVERY approval-outcome reference, in order. A reference of that rel with
    no string resolver is a refusal: the registry is obliged to keep each one resolvable (section 3.1.2), so one that
    names no resolver is not a reference this tool can check against the origin. References of other kinds are
    ignored. (Review of #338, 18 Oct 2026: only the first resolver used to be checked, so the verdict depended on
    the order of the references.)"""
    out = []
    for i, r in enumerate(references_of(record)):
        if r.get("rel") != "approval-outcome":
            continue
        resolver = r.get("resolver")
        if not isinstance(resolver, str) or not resolver:
            return [], f"approval-outcome reference {i} names no resolver"
        out.append(resolver)
    return out, None


def resolver_of(record) -> str | None:
    """The first approval-outcome resolver, for display; trusted_origin checks all of them."""
    resolvers, _ = approval_resolvers(record)
    return resolvers[0] if resolvers else None


def record_kid(record) -> str | None:
    cnf = record.get("cnf") if isinstance(record, dict) else None
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    kid = jwk.get("kid") if isinstance(jwk, dict) else None
    return kid if isinstance(kid, str) and kid else None


def anchor_origin(record: dict, registry: str | None) -> tuple[str | None, str | None]:
    """(origin, refusal): the origin the published key may come from, or why there is none. The origin is the relying
    party's, given out of band with --registry; nothing in the record supplies it. (An earlier head derived it from
    the record's did:web subject, which only shows the record agrees with itself: a record signed under a publisher
    of its own choosing names that publisher in its subject too. Review of #338, 18 Oct 2026.) The record's `subject`
    and `resolver` must then agree with the origin, which catches a record that was minted for another registry."""
    origin, why = https_origin(registry)
    if why:
        return None, why
    # the subject must be a did:web under the trusted origin: this registry mints no other kind, and a record whose
    # subject is absent, unparseable or of another method cannot be bound to the origin at all (review of #338)
    subject = record.get("subject")
    subject_origin = origin_of_did_web(subject)
    if not subject_origin:
        return None, "the record's subject is not a did:web identifier, so it cannot be bound to the trusted origin"
    if subject_origin != origin:
        return None, f"the record's subject lives under {subject_origin}, not the trusted origin {origin}"
    # every approval-outcome reference must resolve at the trusted origin, whatever its position; compared in canonical
    # form, so an explicit :443 or a different case is the same origin (RFC 6454) and a resolver with a path is not one
    resolvers, why = approval_resolvers(record)
    if why:
        return None, why
    for i, resolver in enumerate(resolvers):
        canonical, bad = https_origin(resolver)
        if bad:
            return None, f"approval-outcome reference {i} resolver {resolver!r} is not an https origin: {bad}"
        if canonical != origin:
            return None, f"approval-outcome reference {i} resolves at {canonical}, not the trusted origin {origin}"
    return origin, None


def verify_with_key_source(record: dict, pinned: dict | None, fetch=published_key,
                           max_age_seconds: int = MAX_AGE_SECONDS, now: int | Instant | None = None, registry: str | None = None) -> dict:
    instant = _instant(now)   # frozen here, once; the same object reaches verification() and every verdict below
    bounds = {"max_age_seconds": max_age_seconds, **instant.fields()}
    if not isinstance(record, dict):
        return {"status": "invalid", "reason": f"record is not a JSON object ({type(record).__name__})", "key_source": None, "kid": None, "revocation": None, **bounds}
    kid = record_kid(record)   # always the key the RECORD names; the key actually used is trusted_key_thumbprint, and pinned_kid when pinned
    # an origin that is given is enforced, pinned key or not (review of 09c436b, 18 Oct 2026: with --jwk the
    # registry was only parsed, so a record for another registry verified under the pinned key with --registry
    # naming a third). The caller said which registry the record must belong to; the record must agree.
    origin = None
    if registry is not None:
        origin, refusal = anchor_origin(record, registry)
        if refusal:
            return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, **bounds, "reason": refusal}
    if pinned is not None:
        if isinstance(pinned, dict) and "d" in pinned:
            # 19 Oct 2026: a trust anchor is a PUBLIC key; a file carrying the private member is refused, and no part of it
            # is echoed (the reason is fixed text)
            return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, **bounds, "reason": "the pinned key file holds a private key (member d); pin the public key only"}
        if not is_ed25519_jwk(pinned):
            return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, **bounds, "reason": "the pinned key is not an Ed25519 JWK (kty OKP, crv Ed25519, x of 32 bytes)"}
        pk = pinned.get("kid")
        return {**verification(record, pinned, max_age_seconds, instant), "key_source": "pinned", "kid": kid, "pinned_kid": pk if isinstance(pk, str) else None,
                **({"trusted_origin": origin} if origin else {}), **bounds}
    if origin is None:
        return {"status": "no-key", "key_source": None, "kid": kid, "revocation": None, **bounds,
                "reason": "no trust anchor: pass --registry <https origin of the registry you trust>, or --jwk <its pinned key>"}
    if kid:
        key = fetch(origin, kid)
        if key:
            return {**verification(record, key, max_age_seconds, instant), "key_source": "published", "kid": kid, "trusted_origin": origin, **bounds}
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
                         "--jwk pins the key; when given, with or without --jwk, the record's subject and every approval-outcome "
                         "resolver must be under it")
    ap.add_argument("--now", type=int, default=None, metavar="EPOCH_SECONDS",
                    help="verify as of this moment instead of the clock: a retained record re-verified at its own time")
    a = ap.parse_args(argv)
    if a.max_age <= 0:
        ap.error("--max-age must be positive; the age check cannot be disabled")
    if a.now is not None and a.now < 0:
        ap.error("--now must be a Unix time in seconds")
    instant = Instant(a.now)   # the one instant for everything below
    record, why = load_json(a.record)
    if why:
        out = {"status": "invalid", "reason": f"record file: {why}", "key_source": None, "kid": None, "revocation": None, "max_age_seconds": a.max_age, **instant.fields()}
    else:
        jwk = None
        if a.jwk:
            j, why = load_json(a.jwk, detail=False)
            if why:
                out = {"status": "no-key", "reason": f"pinned key file: {why}", "key_source": None, "kid": record_kid(record), "revocation": None, "max_age_seconds": a.max_age, **instant.fields()}
                print(json.dumps(out, indent=2))
                return 1
            jwk = j.get("trace_signer_jwk", j) if isinstance(j, dict) else j   # a bare JWK, or {trace_signer_jwk: ...}; the shape is checked next
            if not is_ed25519_jwk(jwk) and not (isinstance(jwk, dict) and "d" in jwk):
                jwk = {"not": "a jwk"}   # verify_with_key_source says so, with the reason; never None (that would mean "no pin given")
        out = verify_with_key_source(record, jwk, max_age_seconds=a.max_age, now=instant, registry=a.registry)
        out["approval_outcome_references"] = [
            {"id": r.get("id"), "resolver": r.get("resolver"), "digest": r.get("digest")}
            for r in references_of(record) if r.get("rel") == "approval-outcome"
        ]
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "verified" else 1


def load_json(path: str, detail: bool = True) -> tuple:
    """(value, None) or (None, why): a local file that is not JSON is reported, not raised. detail=False reports the
    error class only: a decode error's message can quote bytes of the file, and a key file's bytes are not echoed."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), None
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return None, f"{type(e).__name__}: {str(e)[:120]}" if detail else type(e).__name__


if __name__ == "__main__":
    sys.exit(main())
