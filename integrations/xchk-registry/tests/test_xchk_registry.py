"""Recomputed from the committed bytes: the Trust Record with released agentrust-trace, the digest with rfc8785,
the bundle with the registry's own verifier. Nothing is read from a generator's summary. The live resolution test
runs only with REGISTRY_LIVE=1, because CI must not depend on a third party's uptime."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import xchk_trace

EX = Path(__file__).resolve().parents[1] / "examples"
EXPECTED = json.loads((EX / "expected.json").read_text(encoding="utf-8"))
RECORD = json.loads((EX / "01-approval-confirmed.json").read_text(encoding="utf-8"))
BUNDLE = json.loads((EX / "01-approval-confirmed.bundle.json").read_text(encoding="utf-8"))
CROSSED = json.loads((EX / "08-assertion-over-another-ask.bundle.json").read_text(encoding="utf-8"))


def reference() -> dict:
    refs = [r for r in RECORD["references"] if r["rel"] == "approval-outcome"]
    assert len(refs) == 1
    return refs[0]


def test_the_record_verifies_with_the_pinned_registry_key():
    assert xchk_trace.record_verifies(RECORD, EXPECTED["trace_signer_jwk"])
    assert RECORD["cnf"]["jwk"]["kid"] == EXPECTED["trace_signer_jwk"]["kid"]
    tampered = json.loads(json.dumps(RECORD))
    tampered["iat"] += 1
    assert not xchk_trace.record_verifies(tampered, EXPECTED["trace_signer_jwk"])


def test_the_embedded_key_is_never_reported_as_verified():
    """A record checked against its own cnf.jwk is self-consistent, not verified: any self-signed record passes that."""
    def no_fetch(resolver, kid):
        return None
    assert xchk_trace.verify_with_key_source(RECORD, None, False, fetch=no_fetch)["status"] == "no-key"
    got = xchk_trace.verify_with_key_source(RECORD, None, True, fetch=no_fetch)
    assert got["status"] == "self-consistent" and got["key_source"] == "embedded"
    pinned = xchk_trace.verify_with_key_source(RECORD, EXPECTED["trace_signer_jwk"], False, fetch=no_fetch)
    assert pinned["status"] == "verified" and pinned["key_source"] == "pinned"


def test_the_published_key_document_converts_to_the_pinned_jwk():
    import base64
    jwk = EXPECTED["trace_signer_jwk"]
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    doc = {"keys": [{"keyId": jwk["kid"], "alg": "ed25519", "publicKeyRaw": base64.b64encode(raw).decode("ascii")},
                    {"keyId": "other", "alg": "ml-dsa-65", "publicKeyRaw": "AAAA"}]}
    got = xchk_trace.key_from_published(doc, jwk["kid"])
    assert got == {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"], "kid": jwk["kid"]}
    assert xchk_trace.key_from_published(doc, "other") is None
    served = xchk_trace.verify_with_key_source(RECORD, None, False, fetch=lambda resolver, kid: xchk_trace.key_from_published(doc, kid))
    assert served["status"] == "verified" and served["key_source"] == "published" and served["resolver"] == EXPECTED["resolver"]


def test_the_reference_digest_is_the_registry_record_hash():
    ref = reference()
    assert ref["resolver"] == EXPECTED["resolver"]
    assert xchk_trace.jcs_sha256(BUNDLE["record"]) == ref["digest"] == "sha256:" + BUNDLE["recordHash"]


def test_a_confirmed_approval_names_the_person_and_the_ask_they_signed_over():
    got = xchk_trace.assess(reference(), BUNDLE)
    assert got["verdict"] == "approval-confirmed"
    assert got["bundle_verifies"] and got["digest_matches"]
    assert got["approver"] == BUNDLE["approver"]["email"]
    assert got["challenge_rule"] == "ask-v1"


def test_the_same_persons_assertion_over_another_ask_is_contradicted():
    """Key, binding and user verification are all genuine; the challenge the device signed names another ask."""
    assert CROSSED["approver"]["publicKey"] == BUNDLE["approver"]["publicKey"]
    assert CROSSED["approver"]["assertion"] != BUNDLE["approver"]["assertion"]
    got = xchk_trace.assess(reference(), CROSSED)
    assert got["verdict"] == "approval-contradicted"
    assert got["digest_matches"] is True and got["bundle_verifies"] is False


def test_an_unresolvable_reference_is_unconfirmed_not_rejected():
    got = xchk_trace.assess(reference(), None)
    assert got["verdict"] == "approval-unconfirmed"
    assert xchk_trace.record_verifies(RECORD, EXPECTED["trace_signer_jwk"])


def test_the_cli_runs_offline(tmp_path, capsys):
    jwk = tmp_path / "jwk.json"
    jwk.write_text(json.dumps(EXPECTED), encoding="utf-8")
    rc = xchk_trace.main([str(EX / "01-approval-confirmed.json"), "--bundle", str(EX / "01-approval-confirmed.bundle.json"), "--jwk", str(jwk)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["trace_record"]["key_source"] == "pinned"
    assert out["references"][0]["verdict"] == "approval-confirmed"
    rc = xchk_trace.main([str(EX / "01-approval-confirmed.json"), "--bundle", str(EX / "01-approval-confirmed.bundle.json"), "--allow-embedded-key"])
    out = json.loads(capsys.readouterr().out)
    assert out["trace_record"]["status"] in ("self-consistent", "verified")  # verified only if the resolver's keys were reachable
    assert rc == (0 if out["trace_record"]["status"] == "verified" else 1)


@pytest.mark.skipif(os.environ.get("REGISTRY_LIVE") != "1", reason="set REGISTRY_LIVE=1 to resolve the reference at the registry")
def test_live_resolution_matches_the_committed_bundle():
    ref = reference()
    assert xchk_trace.published_key(ref["resolver"], RECORD["cnf"]["jwk"]["kid"]) == {**EXPECTED["trace_signer_jwk"], "kid": RECORD["cnf"]["jwk"]["kid"]}
    live = xchk_trace.fetch_bundle(ref["resolver"], ref["id"])
    assert live is not None
    assert live["record"] == BUNDLE["record"]
    assert xchk_trace.assess(ref, live)["verdict"] == "approval-confirmed"
