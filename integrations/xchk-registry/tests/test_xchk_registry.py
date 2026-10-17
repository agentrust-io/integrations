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
import xchk_trace  # noqa: E402

EX = Path(__file__).resolve().parents[1] / "examples"
EXPECTED = json.loads((EX / "expected.json").read_text(encoding="utf-8"))
RECORD = json.loads((EX / "01-approval-confirmed.json").read_text(encoding="utf-8"))
BUNDLE = json.loads((EX / "01-approval-confirmed.bundle.json").read_text(encoding="utf-8"))
CROSSED = json.loads((EX / "08-assertion-over-another-ask.bundle.json").read_text(encoding="utf-8"))


def reference() -> dict:
    refs = [r for r in RECORD["references"] if r["rel"] == "approval-outcome"]
    assert len(refs) == 1
    return refs[0]


def test_the_record_verifies_with_the_registry_key_and_with_its_own_cnf():
    assert xchk_trace.record_verifies(RECORD, EXPECTED["trace_signer_jwk"])
    assert xchk_trace.record_verifies(RECORD, None)
    assert RECORD["cnf"]["jwk"]["kid"] == EXPECTED["trace_signer_jwk"]["kid"]


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
    assert out["references"][0]["verdict"] == "approval-confirmed"


@pytest.mark.skipif(os.environ.get("REGISTRY_LIVE") != "1", reason="set REGISTRY_LIVE=1 to resolve the reference at the registry")
def test_live_resolution_matches_the_committed_bundle():
    ref = reference()
    live = xchk_trace.fetch_bundle(ref["resolver"], ref["id"])
    assert live is not None
    assert live["record"] == BUNDLE["record"]
    assert xchk_trace.assess(ref, live)["verdict"] == "approval-confirmed"
