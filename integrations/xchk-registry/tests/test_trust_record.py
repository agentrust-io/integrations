"""Recomputed from the committed bytes with released agentrust-trace; nothing read from a generator's summary.
The live key fetch runs only with REGISTRY_LIVE=1, so CI never depends on the registry's uptime."""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import xchk_trace_record as x  # noqa: E402

EX = Path(__file__).resolve().parents[1] / "examples"
EXPECTED = json.loads((EX / "expected.json").read_text(encoding="utf-8"))
RECORD = json.loads((EX / "01-trust-record.json").read_text(encoding="utf-8"))
JWK = EXPECTED["trace_signer_jwk"]


def no_fetch(resolver, kid):
    return None


AT_ISSUE = RECORD["iat"] + 60   # the fixture is historical: verified as of a minute after it was minted, under the default bound


def test_the_record_verifies_with_the_pinned_registry_key_and_a_tampered_one_does_not():
    assert x.record_verifies(RECORD, JWK, now=AT_ISSUE)
    assert RECORD["cnf"]["jwk"]["kid"] == JWK["kid"]
    tampered = json.loads(json.dumps(RECORD))
    tampered["iat"] += 1
    assert not x.record_verifies(tampered, JWK, now=AT_ISSUE)


def test_a_stale_record_is_not_verified_and_the_bound_cannot_be_switched_off():
    """Section 3.2.2: the verifier enforces a finite maximum age. The default is the library's 24 hours."""
    assert x.MAX_AGE_SECONDS == 86400
    fresh = x.verification(RECORD, JWK, now=RECORD["iat"] + x.MAX_AGE_SECONDS - 1)
    assert fresh["status"] == "verified"
    stale = x.verification(RECORD, JWK, now=RECORD["iat"] + x.MAX_AGE_SECONDS + 1)
    assert stale["status"] == "invalid" and ("stale" in stale["reason"].lower() or "age" in stale["reason"].lower())
    assert x.verification(RECORD, JWK, max_age_seconds=3600, now=RECORD["iat"] + 3601)["status"] == "invalid"
    assert x.verification(RECORD, JWK, max_age_seconds=315360000, now=RECORD["iat"] + 30 * 86400)["status"] == "verified"
    for bad in (0, -1, None, True):
        with pytest.raises(ValueError):
            x.verification(RECORD, JWK, max_age_seconds=bad, now=AT_ISSUE)
    with pytest.raises(SystemExit):
        x.main([str(EX / "01-trust-record.json"), "--jwk", str(EX / "expected.json"), "--max-age", "0"])


def test_the_revocation_outcome_is_reported_as_no_check_performed_when_nothing_was_checked():
    """Section 3.2.3: no bundle and no store were given, so the result says so rather than implying a clean key."""
    got = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE)
    assert got["status"] == "verified" and got["revocation"] == "no_check_performed"
    assert got["max_age_seconds"] == x.MAX_AGE_SECONDS
    invalid = x.verify_with_key_source({**RECORD, "iat": RECORD["iat"] + 1}, JWK, fetch=no_fetch, now=AT_ISSUE)
    assert invalid["status"] == "invalid" and invalid["revocation"] is None


def test_the_record_is_software_only_level_0_and_names_its_resolver():
    assert RECORD["eat_profile"].endswith("trace-v0.2")
    assert "origin" not in RECORD
    assert RECORD["runtime"]["platform"] == "software-only"
    assert RECORD["appraisal"]["status"] == "none"
    assert x.resolver_of(RECORD) == EXPECTED["resolver"]
    refs = [r for r in RECORD["references"] if r["rel"] == "approval-outcome"]
    assert len(refs) == 1 and len(refs[0]["id"]) == 64 and refs[0]["digest"] == "sha256:" + refs[0]["id"]


def test_the_embedded_key_is_never_used_without_a_pinned_or_published_key():
    assert x.verify_with_key_source(RECORD, None, fetch=no_fetch, now=AT_ISSUE)["status"] == "no-key"
    got = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE)
    assert got["status"] == "verified" and got["key_source"] == "pinned"


def published_doc():
    raw = base64.urlsafe_b64decode(JWK["x"] + "=" * (-len(JWK["x"]) % 4))
    return {"keys": [{"keyId": JWK["kid"], "alg": "ed25519", "publicKeyRaw": base64.b64encode(raw).decode("ascii")},
                     {"keyId": "other", "alg": "ml-dsa-65", "publicKeyRaw": "AAAA"}]}


def test_the_published_key_document_converts_to_the_pinned_jwk():
    doc = published_doc()
    assert x.key_from_published(doc, JWK["kid"]) == {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"], "kid": JWK["kid"]}
    assert x.key_from_published(doc, "other") is None
    got = x.verify_with_key_source(RECORD, None, fetch=lambda origin, kid: x.key_from_published(doc, kid), now=AT_ISSUE)
    assert got["status"] == "verified" and got["key_source"] == "published" and got["trusted_origin"] == EXPECTED["resolver"]


def test_the_published_key_comes_from_the_subjects_origin_never_from_a_server_the_record_names():
    """A record that names the server its key is fetched from has chosen its own trust root. The origin is the
    relying party's (--registry) or the did:web subject's; the record's resolver must agree and is never followed."""
    assert x.origin_of_did_web("did:web:in.xchk.io:plate:ENG-WNP3") == "https://in.xchk.io"
    assert x.origin_of_did_web("did:web:example.com%3A8443:x") == "https://example.com:8443"
    for bad in ("did:key:z6Mk", "did:web:", "did:web:a/b:c", "did:web:..:x", "", None, 7):
        assert x.origin_of_did_web(bad) is None, repr(bad)
    doc = published_doc()
    asked = []

    def fetch(origin, kid):
        asked.append(origin)
        return x.key_from_published(doc, kid)

    elsewhere = json.loads(json.dumps(RECORD))
    elsewhere["references"][0]["resolver"] = "https://attacker.example"
    got = x.verify_with_key_source(elsewhere, None, fetch=fetch, now=AT_ISSUE)
    assert got["status"] == "no-key" and "attacker.example" in got["reason"] and asked == [], "nothing fetched from the record's server"
    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE, registry="https://other.example")
    assert got["status"] == "no-key" and asked == [], "the relying party's origin wins, and the record's resolver disagrees with it"
    foreign = json.loads(json.dumps(RECORD))
    foreign["subject"] = "did:web:attacker.example:plate:X"
    got = x.verify_with_key_source(foreign, None, fetch=fetch, now=AT_ISSUE)
    assert got["status"] == "no-key" and asked == [], "a subject moved to another host disagrees with the resolver, and the signature would fail anyway"
    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE, registry="http://in.xchk.io")
    assert got["status"] == "no-key" and "https" in got["reason"] and asked == []
    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE, registry="https://in.xchk.io/")
    assert got["status"] == "verified" and asked == ["https://in.xchk.io"]
    nokid = json.loads(json.dumps(RECORD))
    del nokid["cnf"]["jwk"]["kid"]
    assert x.verify_with_key_source(nokid, None, fetch=fetch, now=AT_ISSUE)["status"] == "no-key"


def test_the_key_document_fetch_refuses_http_redirects_and_oversize(monkeypatch):
    assert x.published_key("http://in.xchk.io", JWK["kid"]) is None
    assert x.published_key("ftp://in.xchk.io", JWK["kid"]) is None

    class Resp:
        def __init__(self, status, body): self.status, self._b = status, body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return self._b if n < 0 else self._b[:n]

    class Opener:
        def __init__(self, resp): self.resp = resp
        def open(self, url, timeout=0): return self.resp

    monkeypatch.setattr(x.urllib.request, "build_opener", lambda *h: Opener(Resp(200, b"x" * (x.KEY_DOC_MAX_BYTES + 1))))
    assert x.published_key("https://in.xchk.io", JWK["kid"]) is None, "a document past the bound is not read"
    monkeypatch.setattr(x.urllib.request, "build_opener", lambda *h: Opener(Resp(302, b"{}")))
    assert x.published_key("https://in.xchk.io", JWK["kid"]) is None
    monkeypatch.setattr(x.urllib.request, "build_opener", lambda *h: Opener(Resp(200, json.dumps(published_doc()).encode())))
    assert x.published_key("https://in.xchk.io", JWK["kid"]) == {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"], "kid": JWK["kid"]}
    assert x._NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere") is None


def test_the_cli_runs_offline_with_a_pinned_key(capsys):
    rc = x.main([str(EX / "01-trust-record.json"), "--jwk", str(EX / "expected.json"), "--now", str(AT_ISSUE)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "verified" and out["key_source"] == "pinned"
    assert out["revocation"] == "no_check_performed" and out["max_age_seconds"] == x.MAX_AGE_SECONDS
    capsys.readouterr()
    long_after = RECORD["iat"] + 30 * 86400
    assert x.main([str(EX / "01-trust-record.json"), "--jwk", str(EX / "expected.json"), "--now", str(long_after)]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "invalid", "a month on, under the default bound, the record is stale"
    assert len(out["approval_outcome_references"]) == 1


@pytest.mark.skipif(os.environ.get("REGISTRY_LIVE") != "1", reason="set REGISTRY_LIVE=1 to fetch the published key")
def test_the_published_key_at_the_registry_matches_the_pinned_one():
    assert x.published_key(EXPECTED["resolver"], JWK["kid"]) == {**JWK, "kid": JWK["kid"]}
