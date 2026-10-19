"""Recomputed from the committed bytes with released agentrust-trace; nothing read from a generator's summary.
The live key fetch runs only with REGISTRY_LIVE=1, so CI never depends on the registry's uptime."""
from __future__ import annotations

import base64
import copy
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


def signed_with(key, record_fields: dict, kid: str) -> dict:
    """A record signed end to end by `key`, the way the library signs (Ed25519 over the JCS form, `signature` absent)."""
    import agentrust_trace as t
    jwk = {**t.key_to_jwk(key), "kid": kid}
    payload = {**record_fields, "cnf": {"jwk": jwk}}
    return {**payload, "signature": base64.urlsafe_b64encode(key.sign(t.sign._canonical_bytes(payload))).rstrip(b"=").decode()}


def doc_for(jwk: dict, kid: str) -> dict:
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return {"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": base64.b64encode(raw).decode("ascii")}]}


def published_doc():
    raw = base64.urlsafe_b64decode(JWK["x"] + "=" * (-len(JWK["x"]) % 4))
    return {"keys": [{"keyId": JWK["kid"], "alg": "ed25519", "publicKeyRaw": base64.b64encode(raw).decode("ascii")},
                     {"keyId": "other", "alg": "ml-dsa-65", "publicKeyRaw": "AAAA"}]}


REGISTRY = EXPECTED["resolver"]


def test_the_published_key_document_converts_to_the_pinned_jwk():
    doc = published_doc()
    assert x.key_from_published(doc, JWK["kid"]) == {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"], "kid": JWK["kid"]}
    assert x.key_from_published(doc, "other") is None
    got = x.verify_with_key_source(RECORD, None, fetch=lambda origin, kid: x.key_from_published(doc, kid), now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "verified" and got["key_source"] == "published" and got["trusted_origin"] == REGISTRY


def test_a_malformed_key_document_is_no_key_never_a_crash():
    """The fetch may answer anything. Every shape here used to raise out of key_from_published."""
    kid = JWK["kid"]
    for doc in (None, [], "keys", 7, {"keys": None}, {"keys": "x"}, {"keys": {}}, {"keys": [None]}, {"keys": ["x"]}, {"keys": [7]},
                {"keys": [{"keyId": kid, "alg": "ed25519"}]}, {"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": None}]},
                {"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": 12}]}, {"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": "not base64!"}]},
                {"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": "AAAA"}]}, {"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": ["x"]}]}):
        assert x.key_from_published(doc, kid) is None, repr(doc)
    assert x.key_from_published(published_doc(), None) is None
    got = x.verify_with_key_source(RECORD, None, fetch=lambda origin, kid: x.key_from_published({"keys": [{"keyId": kid, "alg": "ed25519", "publicKeyRaw": 12}]}, kid),
                                   now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "no-key"


def test_a_verified_result_carries_the_profile_fields_and_the_time_it_was_made_at():
    """Section 3.3: the profile and the complete accepted set; and the as-of instant, so a historical verdict is
    never the same JSON as a current one."""
    got = x.verification(RECORD, JWK, now=AT_ISSUE)
    assert got["profile"] == RECORD["eat_profile"] and got["accepted_profiles"] == [RECORD["eat_profile"]]
    assert got["trusted_key_thumbprint"]
    assert got["verified_at"] == AT_ISSUE and got["verified_at_overridden"] is True
    later = RECORD["iat"] + 30 * 86400
    stale = x.verification(RECORD, JWK, now=later)
    assert stale["status"] == "invalid" and stale["verified_at"] == later and stale["verified_at_overridden"] is True
    assert "profile" not in stale
    current = x.verification(RECORD, JWK)
    assert current["verified_at_overridden"] is False and abs(current["verified_at"] - int(x.time.time())) < 5


def test_one_instant_is_frozen_at_the_boundary_and_is_what_the_library_was_given(monkeypatch):
    """A clock answering 100 then 101 (the review's two-value control): the library must be given the instant the
    verdict reports, with no override and with --now, on every path (pinned, published, no-key)."""
    given = []
    real = x.verify_record

    def spy(record, jwk, **kw):
        given.append(kw["now"])
        return real(record, jwk, **kw)

    monkeypatch.setattr(x, "verify_record", spy)
    base = RECORD["iat"]
    ticks = iter([base + 100, base + 101, base + 102, base + 103, base + 104, base + 105])
    monkeypatch.setattr(x.time, "time", lambda: next(ticks))
    got = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch)
    assert given == [base + 100] and got["verified_at"] == base + 100 and got["verified_at_overridden"] is False, "pinned, no override"
    doc = published_doc()
    got = x.verify_with_key_source(RECORD, None, fetch=lambda o, k: x.key_from_published(doc, k), registry=REGISTRY)
    assert given == [base + 100, base + 101] and got["verified_at"] == base + 101 and got["verified_at_overridden"] is False, "published, no override"
    got = x.verify_with_key_source(RECORD, None, fetch=no_fetch)
    assert given == [base + 100, base + 101] and got["verified_at"] == base + 102 and got["status"] == "no-key", "no-key: one clock read, no library call"
    got = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE)
    assert given[-1] == AT_ISSUE and got["verified_at"] == AT_ISSUE and got["verified_at_overridden"] is True, "explicit --now"
    assert x.verification(RECORD, JWK)["verified_at"] == given[-1] == base + 103, "verification() alone reads the clock once"


def test_the_cli_freezes_one_instant_too(monkeypatch, capsys):
    given = []
    real = x.verify_record
    monkeypatch.setattr(x, "verify_record", lambda record, jwk, **kw: (given.append(kw["now"]), real(record, jwk, **kw))[1])
    ticks = iter([RECORD["iat"] + 7, RECORD["iat"] + 8])
    monkeypatch.setattr(x.time, "time", lambda: next(ticks))
    assert x.main([str(EX / "01-trust-record.json"), "--jwk", str(EX / "expected.json")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert given == [RECORD["iat"] + 7] and out["verified_at"] == RECORD["iat"] + 7 and out["verified_at_overridden"] is False
    assert x.main([str(EX / "01-trust-record.json"), "--jwk", str(EX / "expected.json"), "--now", str(AT_ISSUE)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert given[-1] == AT_ISSUE and out["verified_at"] == AT_ISSUE and out["verified_at_overridden"] is True


def test_the_trust_origin_is_the_relying_partys_and_nothing_in_the_record_supplies_it():
    """A record names its subject and its resolver; a record signed under a publisher of its own choosing names that
    publisher in both. So the origin comes from --registry alone, and the record must agree with it."""
    assert x.origin_of_did_web("did:web:in.xchk.io:plate:ENG-WNP3") == "https://in.xchk.io"
    assert x.origin_of_did_web("did:web:example.com%3A8443:x") == "https://example.com:8443"
    for bad in ("did:key:z6Mk", "did:web:", "did:web:a/b:c", "did:web:..:x", "", None, 7):
        assert x.origin_of_did_web(bad) is None, repr(bad)
    doc = published_doc()
    asked = []

    def fetch(origin, kid):
        asked.append(origin)
        return x.key_from_published(doc, kid)

    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE)
    assert got["status"] == "no-key" and "--registry" in got["reason"] and asked == [], "no --registry: no trust anchor, nothing fetched"
    assert got["verified_at"] == AT_ISSUE and got["verified_at_overridden"] is True, "the as-of time is on every verdict, no-key included"
    elsewhere = json.loads(json.dumps(RECORD))
    elsewhere["references"][0]["resolver"] = "https://attacker.example"
    got = x.verify_with_key_source(elsewhere, None, fetch=fetch, now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "no-key" and "attacker.example" in got["reason"] and asked == [], "nothing fetched from the record's server"
    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE, registry="https://other.example")
    assert got["status"] == "no-key" and asked == [], "the record's subject and resolver disagree with the relying party's origin"
    foreign = json.loads(json.dumps(RECORD))
    foreign["subject"] = "did:web:attacker.example:plate:X"
    got = x.verify_with_key_source(foreign, None, fetch=fetch, now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "no-key" and "subject" in got["reason"] and asked == []
    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE, registry="http://in.xchk.io")
    assert got["status"] == "no-key" and "https" in got["reason"] and asked == []
    got = x.verify_with_key_source(RECORD, None, fetch=fetch, now=AT_ISSUE, registry="https://in.xchk.io/")
    assert got["status"] == "verified" and asked == ["https://in.xchk.io"]
    nokid = json.loads(json.dumps(RECORD))
    del nokid["cnf"]["jwk"]["kid"]
    assert x.verify_with_key_source(nokid, None, fetch=fetch, now=AT_ISSUE, registry=REGISTRY)["status"] == "no-key"


def test_a_record_signed_under_its_own_chosen_publisher_is_never_verified():
    """The negative control the review asked for: a record signed, end to end, by a key the attacker made, with a
    subject and resolver under a host the attacker runs and that host publishing the key. Without --registry
    there is no anchor; with the relying party's registry the record disagrees with it; and if the attacker's host
    is named as the registry, that is the relying party's own choice, which no verifier can second-guess."""
    import agentrust_trace as t
    key = t.generate_key()
    unsigned = {k: v for k, v in RECORD.items() if k not in ("signature", "cnf")}
    unsigned["subject"] = "did:web:attacker.example:plate:EVIL"
    unsigned["references"] = [{**unsigned["references"][0], "resolver": "https://attacker.example"}]
    # signed the way the library signs (Ed25519 over the JCS form with `signature` absent), with a kid in cnf.jwk
    attacker_jwk = {**t.key_to_jwk(key), "kid": "evil-kid"}
    payload = {**unsigned, "cnf": {"jwk": attacker_jwk}}
    forged = {**payload, "signature": base64.urlsafe_b64encode(key.sign(t.sign._canonical_bytes(payload))).rstrip(b"=").decode()}
    assert x.record_verifies(forged, attacker_jwk, now=AT_ISSUE), "the forgery is internally consistent"
    raw = base64.urlsafe_b64decode(attacker_jwk["x"] + "=" * (-len(attacker_jwk["x"]) % 4))
    attacker_doc = {"keys": [{"keyId": "evil-kid", "alg": "ed25519", "publicKeyRaw": base64.b64encode(raw).decode("ascii")}]}
    served = {"https://attacker.example": attacker_doc, REGISTRY: published_doc()}
    asked = []

    def fetch(origin, kid):
        asked.append(origin)
        return x.key_from_published(served.get(origin, {}), kid)

    got = x.verify_with_key_source(forged, None, fetch=fetch, now=AT_ISSUE)
    assert got["status"] == "no-key" and asked == [], "no anchor, no fetch"
    got = x.verify_with_key_source(forged, None, fetch=fetch, now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "no-key" and asked == [], "the forgery does not agree with the registry the relying party trusts"
    got = x.verify_with_key_source(forged, JWK, fetch=fetch, now=AT_ISSUE)
    assert got["status"] == "invalid", "pinned to the real registry key, the forgery's signature fails"


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


# 18 Oct 2026, after four review rounds found input shapes one at a time: every top-level field, the key fields and the
# reference fields set to each odd value, through main() on all three paths. A verdict and an exit code, or it is a bug.
ODD = [None, [], {}, "", "x", 0, 1, -1, True, 1.5, [1], {"a": 1}, "did:web:in.xchk.io:plate:ENG-WNP3", "https://in.xchk.io"]


def _mutations():
    for k in list(RECORD) + ["cnf.jwk", "cnf.jwk.kid", "references.0", "references.0.resolver", "references.0.rel"]:
        for v in ODD:
            r = copy.deepcopy(RECORD)
            parts = k.split(".")
            tgt = r
            for p in parts[:-1]:
                tgt = tgt[int(p)] if p.isdigit() else tgt[p]
            last = parts[-1]
            if last.isdigit():
                tgt[int(last)] = v
            else:
                tgt[last] = v
            yield f"{k}={v!r}", r
    for whole in ODD:
        yield f"<record>={whole!r}", whole


def test_no_mutation_of_the_record_crashes_the_cli_on_any_path(tmp_path, capsys, monkeypatch):
    doc = published_doc()

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return json.dumps(doc).encode()

    class Opener:
        def open(self, url, timeout=0): return Resp()

    monkeypatch.setattr(x.urllib.request, "build_opener", lambda *h: Opener())
    paths = (["--jwk", str(EX / "expected.json")], ["--registry", REGISTRY], [])
    n = 0
    for label, record in _mutations():
        f = tmp_path / "r.json"
        f.write_text(json.dumps(record), encoding="utf-8")
        for extra in paths:
            try:
                rc = x.main([str(f), "--now", str(AT_ISSUE)] + extra)
            except SystemExit as e:
                rc = e.code
            except Exception as e:  # noqa: BLE001
                raise AssertionError(f"{label} with {extra[:1]} crashed: {type(e).__name__}: {e}") from e
            out = json.loads(capsys.readouterr().out)
            assert rc in (0, 1) and out["status"] in ("verified", "invalid", "no-key"), label
            assert "verified_at" in out and out["verified_at"] == AT_ISSUE, label
            n += 1
    assert n > 700


def test_local_input_files_and_arguments_fail_closed_with_a_verdict(tmp_path, capsys):
    rec = str(EX / "01-trust-record.json")
    def cli(args):
        try:
            rc = x.main(args)
        except SystemExit as e:
            rc = e.code
        return rc, json.loads(capsys.readouterr().out or "{}")
    bad = tmp_path / "bad.json"
    for body in ("not json", "[]", "null", "7", '"x"'):
        bad.write_text(body, encoding="utf-8")
        rc, out = cli([bad.as_posix(), "--jwk", str(EX / "expected.json"), "--now", str(AT_ISSUE)])
        assert rc == 1 and out["status"] == "invalid" and out["verified_at"] == AT_ISSUE, body
    rc, out = cli([str(tmp_path / "missing.json"), "--jwk", str(EX / "expected.json")])
    assert rc == 1 and out["status"] == "invalid" and "record file" in out["reason"]
    for body in ("not json", "[]", "null", "7", '{"trace_signer_jwk": []}', '{"kty":"RSA"}', '{"trace_signer_jwk": {"kty":"OKP","crv":"Ed25519","x":12}}',
                 '{"trace_signer_jwk": {"kty":"OKP","crv":"Ed25519","x":"!!"}}', '{"kty":"OKP","crv":"Ed25519","x":"AAAA"}'):
        bad.write_text(body, encoding="utf-8")
        rc, out = cli([rec, "--jwk", bad.as_posix(), "--now", str(AT_ISSUE)])
        assert rc == 1 and out["status"] == "no-key" and out["kid"] == RECORD["cnf"]["jwk"]["kid"], body
    for reg in ("http://in.xchk.io", "https://user@in.xchk.io", "https://user:pw@in.xchk.io", "https://in.xchk.io/path", "https://in.xchk.io?x=1", "https://in.xchk.io#f", "https://", "in.xchk.io", ""):
        rc, out = cli([rec, "--registry", reg, "--now", str(AT_ISSUE)])
        assert rc == 1 and out["status"] == "no-key", reg
    assert x.https_origin("HTTPS://In.xchk.io/") == ("https://in.xchk.io", None)
    assert x.https_origin("https://in.xchk.io:8443") == ("https://in.xchk.io:8443", None)
    with pytest.raises(SystemExit):
        x.main([rec, "--jwk", str(EX / "expected.json"), "--now", "-5"])
    capsys.readouterr()


def test_the_verdict_names_the_key_the_record_claims_and_the_key_actually_used():
    got = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE)
    assert got["kid"] == RECORD["cnf"]["jwk"]["kid"] and got["pinned_kid"] == JWK["kid"] and got["trusted_key_thumbprint"]
    unnamed = {k: v for k, v in JWK.items() if k != "kid"}
    got = x.verify_with_key_source(RECORD, unnamed, fetch=no_fetch, now=AT_ISSUE)
    assert got["status"] == "verified" and got["kid"] == RECORD["cnf"]["jwk"]["kid"] and got["pinned_kid"] is None
    assert x.verify_with_key_source(RECORD, {"kty": "RSA"}, fetch=no_fetch, now=AT_ISSUE)["status"] == "no-key"


# Review of 2dcb159 (noah-ing, dinakarjs): three bounded cases, each with a freshly signed synthetic record and a valid twin.
def _fresh_signed(**changes):
    import agentrust_trace as t
    key = t.generate_key()
    fields = {k: v for k, v in RECORD.items() if k not in ("signature", "cnf")}
    fields.update(changes)
    return signed_with(key, fields, "fresh-kid"), {**t.key_to_jwk(key), "kid": "fresh-kid"}


def test_malformed_registry_origins_are_refusals_with_a_verdict_and_no_fetch(capsys):
    rec = str(EX / "01-trust-record.json")
    asked = []
    for reg in ("https://in.xchk.io:bad", "https://in.xchk.io:65536", "https://in.xchk.io:-1", "https://[broken", "https://[::1", "https://in.xchk.io:", "https://:443", "https://in.xchk.io:80:80"):
        origin, why = x.https_origin(reg)
        assert origin is None and why, reg
        got = x.verify_with_key_source(RECORD, None, fetch=lambda o, k: asked.append(o), now=AT_ISSUE, registry=reg)
        assert got["status"] == "no-key" and got["reason"] and asked == [], reg
        try:
            rc = x.main([rec, "--registry", reg, "--now", str(AT_ISSUE)])
        except SystemExit as e:
            rc = e.code
        out = json.loads(capsys.readouterr().out)
        assert rc == 1 and out["status"] == "no-key" and out["verified_at"] == AT_ISSUE, reg
    assert x.https_origin("https://[::1]:8443") == ("https://[::1]:8443", None)
    assert x.https_origin("https://in.xchk.io:443") == ("https://in.xchk.io", None), "443 is the same origin with or without the port (RFC 6454)"
    assert x.origin_of_did_web("did:web:in.xchk.io%3A443:plate:X") == "https://in.xchk.io"
    assert x.https_origin("https://in.xchk.io:8443") == ("https://in.xchk.io:8443", None)
    # a malformed --registry is refused even beside a pinned key: an option that is given is checked
    got = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE, registry="https://in.xchk.io:bad")
    assert got["status"] == "no-key" and "parsed" in got["reason"]
    assert x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE, registry="https://in.xchk.io:443")["status"] == "verified"
    # the valid twin: same record, well-formed origin, the key fetched once
    doc = published_doc()
    got = x.verify_with_key_source(RECORD, None, fetch=lambda o, k: (asked.append(o), x.key_from_published(doc, k))[1], now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "verified" and asked == [REGISTRY]


def test_the_subject_must_be_a_did_web_under_the_trusted_origin():
    asked = []
    for subject in ("did:key:z6Mkunbound", "", None, 7, "did:web:", "urn:x", "did:web:other.example:plate:X"):
        rec, jwk = _fresh_signed(subject=subject)
        if subject in ("did:key:z6Mkunbound", "did:web:other.example:plate:X"):
            assert x.record_verifies(rec, jwk, now=AT_ISSUE), "the control is validly signed under its own key (the library's schema rejects the malformed ones on its own)"
        doc = doc_for(jwk, "fresh-kid")
        got = x.verify_with_key_source(rec, None, fetch=lambda o, k: (asked.append(o), x.key_from_published(doc, k))[1], now=AT_ISSUE, registry=REGISTRY)
        assert got["status"] == "no-key" and "subject" in got["reason"] and asked == [], repr(subject)
    rec, jwk = _fresh_signed(subject="did:web:in.xchk.io:plate:TWIN")
    doc = doc_for(jwk, "fresh-kid")
    got = x.verify_with_key_source(rec, None, fetch=lambda o, k: (asked.append(o), x.key_from_published(doc, k))[1], now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "verified" and asked == [REGISTRY], "the twin: a did:web under the origin, verified with the fetched key"


def test_every_approval_outcome_reference_must_resolve_at_the_trusted_origin_whatever_its_order():
    on = RECORD["references"][0]
    off = {**on, "id": "b" * 64, "digest": "sha256:" + "b" * 64, "resolver": "https://attacker.example"}
    unnamed = {k: v for k, v in on.items() if k != "resolver"}
    other_kind = {"rel": "something-else", "id": "c" * 64, "digest": "sha256:" + "c" * 64, "resolver": "https://attacker.example"}
    asked = []
    def check(refs, expect, why=None):
        rec, jwk = _fresh_signed(references=refs)
        doc = doc_for(jwk, "fresh-kid")
        got = x.verify_with_key_source(rec, None, fetch=lambda o, k: (asked.append(o), x.key_from_published(doc, k))[1], now=AT_ISSUE, registry=REGISTRY)
        assert got["status"] == expect, (refs, got.get("reason"))
        if why:
            assert why in got["reason"], got["reason"]
    check([on, off], "no-key", "reference 1")
    check([off, on], "no-key", "reference 0")
    check([on, on, off], "no-key", "reference 2")
    assert asked == [], "nothing fetched for any order"
    check([on, unnamed], "no-key", "names no resolver")
    check([unnamed], "no-key", "names no resolver")
    check([on, other_kind], "verified")
    check([on, on], "verified")
    check([], "verified")
    assert asked == [REGISTRY, REGISTRY, REGISTRY], "the twins fetched the key once each"
    assert x.approval_resolvers({"references": [on, off]}) == ([on["resolver"], "https://attacker.example"], None)


# The sweep that should have come first: many origin strings, subjects and reference orderings, on signed synthetic
# records, through verify_with_key_source and main(). A verdict every time, and a fetch only for a well-formed origin
# that the record agrees with.
ORIGINS = ["https://in.xchk.io", "https://in.xchk.io/", "HTTPS://IN.XCHK.IO", "https://in.xchk.io:443", "https://in.xchk.io:8443", "https://[::1]:8443",
           "https://in.xchk.io:", "https://in.xchk.io:bad", "https://in.xchk.io:65536", "https://in.xchk.io:-1", "https://in.xchk.io:80:80", "https://[broken", "https://[::1",
           "https://", "https:///", "https://:443", "https://in.xchk.io/path", "https://in.xchk.io?x=1", "https://in.xchk.io#f", "https://u@in.xchk.io", "https://u:p@in.xchk.io",
           "http://in.xchk.io", "ftp://in.xchk.io", "in.xchk.io", "//in.xchk.io", "", " ", " https://in.xchk.io", "https://in.xchk.io ", "https://in.xchk.io\n", "https://in.xchk.io.",
           "https://xn--nxasmq6b.example", "https://ïn.xchk.io", "https://in.xchk.io\x00", "https://in.xchk.io:0", "https://in.xchk.io:00443", "https://127.0.0.1", "https://[::ffff:1.2.3.4]",
           "https://in.xchk.io%2Fx", "https://in.xchk.io\\x", "https://in.xchk.io;x", "https://in.xchk.io:443/", "https://IN.xchk.IO:443"]
SUBJECTS = [RECORD["subject"], "did:web:IN.XCHK.IO:plate:X", "did:web:in.xchk.io", "did:web:in.xchk.io%3A443:plate:X", "did:web:in.xchk.io%3A8443:plate:X", "did:key:z6Mk", "did:web:", "did:web:other.example:x",
            "", None, 7, [], {}, "did:web:in.xchk.io/plate", "did:web:in.xchk.io@x", "did:web:..", "did:web:in.xchk.io.", "DID:WEB:in.xchk.io:plate:X"]


def test_an_origin_given_beside_a_pinned_key_is_enforced_not_just_parsed():
    """Review of 09c436b: with --jwk the registry was only parsed. The caller named the registry the record must
    belong to; the record must agree, pinned key or not."""
    ok = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE, registry=REGISTRY)
    assert ok["status"] == "verified" and ok["key_source"] == "pinned" and ok["trusted_origin"] == REGISTRY
    ok443 = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE, registry="https://in.xchk.io:443")
    assert ok443["status"] == "verified" and ok443["trusted_origin"] == REGISTRY
    bad = x.verify_with_key_source(RECORD, JWK, fetch=no_fetch, now=AT_ISSUE, registry="https://other.example")
    assert bad["status"] == "no-key" and "subject lives under" in bad["reason"]
    for subject in ("did:key:z6Mkunbound", None, "did:web:other.example:plate:X"):
        rec, jwk = _fresh_signed(subject=subject)
        got = x.verify_with_key_source(rec, jwk, fetch=no_fetch, now=AT_ISSUE, registry=REGISTRY)
        assert got["status"] == "no-key" and "subject" in got["reason"], repr(subject)
        assert x.verify_with_key_source(rec, jwk, fetch=no_fetch, now=AT_ISSUE)["status"] in ("verified", "invalid"), "pinned alone: the key decides, as before"
    on = RECORD["references"][0]
    off = {**on, "id": "b" * 64, "digest": "sha256:" + "b" * 64, "resolver": "https://attacker.example"}
    rec, jwk = _fresh_signed(references=[on, off])
    got = x.verify_with_key_source(rec, jwk, fetch=no_fetch, now=AT_ISSUE, registry=REGISTRY)
    assert got["status"] == "no-key" and "reference 1" in got["reason"]
    assert x.verify_with_key_source(rec, jwk, fetch=no_fetch, now=AT_ISSUE)["status"] == "verified", "pinned alone verifies it; the origin is what refuses it"


def test_resolvers_are_compared_as_origins_so_an_explicit_443_is_the_same_origin():
    on = RECORD["references"][0]
    rec, jwk = _fresh_signed(subject="did:web:in.xchk.io%3A443:plate:X", references=[{**on, "resolver": "https://in.xchk.io:443"}])
    doc = doc_for(jwk, "fresh-kid")
    asked = []
    got = x.verify_with_key_source(rec, None, fetch=lambda o, k: (asked.append(o), x.key_from_published(doc, k))[1], now=AT_ISSUE, registry="https://in.xchk.io:443")
    assert got["status"] == "verified" and asked == [REGISTRY], got.get("reason")
    rec, jwk = _fresh_signed(references=[{**on, "resolver": "HTTPS://IN.XCHK.IO/"}])
    doc = doc_for(jwk, "fresh-kid")
    assert x.verify_with_key_source(rec, None, fetch=lambda o, k: x.key_from_published(doc, k), now=AT_ISSUE, registry=REGISTRY)["status"] == "verified"
    for resolver in ("https://in.xchk.io/api", "http://in.xchk.io", "https://in.xchk.io:8443", "https://u@in.xchk.io", "in.xchk.io"):
        rec, jwk = _fresh_signed(references=[{**on, "resolver": resolver}])
        got = x.verify_with_key_source(rec, None, fetch=no_fetch, now=AT_ISSUE, registry=REGISTRY)
        assert got["status"] == "no-key" and "reference 0" in got["reason"], resolver


def expected_origin(value):
    """An oracle for the sweep that shares no code with the verifier: what a careful reader expects an https origin
    string to mean, or None. Written from RFC 6454 and the README, not from https_origin."""
    import re
    m = re.fullmatch(r"(?i)https://(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::(\d{1,5}))?/?", value or "")
    if not m or "@" in value or value != value.strip():
        return None
    host, port = m.group(1).lower(), m.group(2)
    if port is not None and (int(port) > 65535 or port != str(int(port))):
        return None
    if host.startswith(".") or host.endswith(".") or ".." in host:
        return None
    return f"https://{host}" + (f":{int(port)}" if port and int(port) != 443 else "")


def test_sweep_origins_subjects_and_references_on_signed_records(tmp_path, capsys, monkeypatch):
    import agentrust_trace as t
    key = t.generate_key()
    jwk = {**t.key_to_jwk(key), "kid": "fresh-kid"}
    doc = doc_for(jwk, "fresh-kid")
    asked = []

    def fetch(o, k):
        asked.append(o)
        return x.key_from_published(doc, k)

    base = {k: v for k, v in RECORD.items() if k not in ("signature", "cnf")}
    on = RECORD["references"][0]
    off = {**on, "id": "b" * 64, "digest": "sha256:" + "b" * 64, "resolver": "https://attacker.example"}
    noresolver = {k: v for k, v in on.items() if k != "resolver"}
    ref_sets = [[on], [on, on], [on, off], [off, on], [on, noresolver], [], [off], [on, {**on, "resolver": "https://IN.xchk.io/"}]]
    def expected_subject_origin(subject):
        import re
        m = re.fullmatch(r"did:web:([^:/@]+?)(?:%3[aA](\d+))?(?::.*)?", subject or "") if isinstance(subject, str) else None
        if not m:
            return None
        host = m.group(1).lower()
        if host.startswith(".") or host.endswith(".") or ".." in host:
            return None
        return f"https://{host}" + (f":{m.group(2)}" if m.group(2) and m.group(2) != "443" else "")

    runs = 0
    for origin in ORIGINS:
        want = expected_origin(origin)   # the oracle, independent of https_origin
        for subject in SUBJECTS:
            for refs in ref_sets:
                rec = signed_with(key, {**base, "subject": subject, "references": refs}, "fresh-kid")
                agrees = bool(want) and expected_subject_origin(subject) == want and all(
                    expected_origin(r.get("resolver")) == want for r in refs if r.get("rel") == "approval-outcome")
                for pinned in (None, jwk):
                    before = len(asked)
                    got = x.verify_with_key_source(rec, pinned, fetch=fetch, now=AT_ISSUE, registry=origin)
                    runs += 1
                    assert got["status"] in ("verified", "invalid", "no-key") and got["verified_at"] == AT_ISSUE, (origin, subject, refs, pinned is not None)
                    fetched = len(asked) - before
                    if pinned is None:
                        assert fetched == (1 if agrees else 0), (origin, subject, refs, got.get("reason"))
                    else:
                        assert fetched == 0, "a pinned key never fetches"
                    if not agrees:
                        assert got["status"] == "no-key", (origin, subject, refs, pinned is not None, got.get("reason"))
                    elif pinned is not None:
                        assert got["status"] in ("verified", "invalid"), "agreeing record, pinned key: the key decides"
    assert runs == 2 * len(ORIGINS) * len(SUBJECTS) * len(ref_sets)
    # the same origins through the CLI, pinned and published, no crash
    f = tmp_path / "r.json"
    f.write_text(json.dumps(RECORD), encoding="utf-8")

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return json.dumps(published_doc()).encode()

    class Opener:
        def open(self, url, timeout=0): return Resp()

    monkeypatch.setattr(x.urllib.request, "build_opener", lambda *h: Opener())
    for origin in ORIGINS:
        for extra in (["--registry", origin], ["--registry", origin, "--jwk", str(EX / "expected.json")]):
            try:
                rc = x.main([str(f), "--now", str(AT_ISSUE)] + extra)
            except SystemExit as e:
                rc = e.code
            except Exception as e:  # noqa: BLE001
                raise AssertionError(f"{origin!r} crashed the CLI: {type(e).__name__}: {e}") from e
            out = json.loads(capsys.readouterr().out)
            assert rc in (0, 1) and out["status"] in ("verified", "invalid", "no-key"), origin


def test_the_thumbprint_is_the_rfc7638_digest_of_the_public_key_the_library_verified_with():
    """The reported trusted_key_thumbprint is the library's own RFC 7638 function over the public key, and equals the
    thumbprint on the library's verification result (19 Oct 2026: computed rather than read off the result)."""
    from agentrust_trace import verify_record
    got = x.verification(RECORD, JWK, now=AT_ISSUE)
    lib = verify_record(RECORD, JWK, max_age_seconds=x.MAX_AGE_SECONDS, now=AT_ISSUE)
    assert got["trusted_key_thumbprint"] == lib.trusted_key_thumbprint
    assert got["trusted_key_thumbprint"] == x.verification(RECORD, {k: v for k, v in JWK.items() if k != "kid"}, now=AT_ISSUE)["trusted_key_thumbprint"]


def test_a_pinned_private_key_is_refused_and_not_echoed(tmp_path, capsys):
    """A trust anchor is a public key. A key file that carries the private member d is refused with fixed text,
    through the function and through the command line, and no part of the file reaches the output."""
    synthetic_d = "c3ludGhldGljLXByaXZhdGUtbWVtYmVyLW5vdC1hLWtleQ"
    private = dict(JWK, d=synthetic_d)
    got = x.verify_with_key_source(RECORD, private, fetch=no_fetch, now=AT_ISSUE)
    assert got["status"] == "no-key" and "private key" in got["reason"]
    assert synthetic_d not in json.dumps(got)
    for doc in (private, {"trace_signer_jwk": private}):
        p = tmp_path / "pinned.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        assert x.main([str(EX / "01-trust-record.json"), "--jwk", str(p), "--now", str(AT_ISSUE)]) == 1
        out = capsys.readouterr().out
        assert '"no-key"' in out and "private key" in out and synthetic_d not in out


def test_a_key_file_that_does_not_decode_is_reported_by_error_class_only(tmp_path, capsys):
    p = tmp_path / "pinned.json"
    p.write_bytes(b'{"kty": "OKP", "x": "\xff\xfe-synthetic-bytes"}')
    assert x.main([str(EX / "01-trust-record.json"), "--jwk", str(p), "--now", str(AT_ISSUE)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "no-key" and out["reason"] == "pinned key file: UnicodeDecodeError"
