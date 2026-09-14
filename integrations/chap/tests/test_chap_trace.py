"""CHAP approval-outcome references, against a live chap-coordinator."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import agentrust_trace
import pytest
from chap_coordinator.canonical import content_hash
from cryptography.exceptions import InvalidSignature

import chap_demo
from chap_trace import (
    CONFIRMED, CONTRADICTED, NOT_AN_APPROVAL, UNCONFIRMED,
    approval_reference, chain_replays, check_approval, envelope_digest,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture(scope="module")
def log() -> dict:
    return chap_demo.refund_review().export()


def _ref(log: dict, method: str, **kwargs) -> dict:
    return approval_reference(chap_demo.entry_for(log, method), chap_demo.RESOLVER, **kwargs)


def test_the_digest_agrees_with_chaps_own_canonicalizer(log):
    """The reference digest is only portable if rfc8785 and CHAP's canonicalizer
    produce the same bytes. Checked on every envelope CHAP wrote, not a sample."""
    for entry in log["entries"]:
        assert envelope_digest(entry["envelope"]) == content_hash(entry["envelope"])


def test_the_chain_replay_agrees_with_chap(log):
    assert log["chap_verify_chain"]["status"] == "verified"
    assert chain_replays(log["entries"], log["chain_head"])


def test_the_reference_carries_the_registered_fields(log):
    approval = chap_demo.entry_for(log, "decide.approve")
    reference = _ref(log, "decide.approve")
    assert reference == {"rel": "approval-outcome", "id": f"audit/{approval['seq']}",
                         "resolver": chap_demo.RESOLVER,
                         "digest": envelope_digest(approval["envelope"])}
    assert _ref(log, "decide.approve", retention="P1Y")["retention"] == "P1Y"


def test_a_rejection_is_never_cited_as_an_approval(log):
    with pytest.raises(ValueError, match="not an approval"):
        _ref(log, "decide.reject")


def test_an_override_is_cited_only_when_the_caller_accepts_overrides(log):
    with pytest.raises(ValueError, match="not an approval"):
        _ref(log, "decide.override")
    assert _ref(log, "decide.override", accept_override=True)["rel"] == "approval-outcome"


@pytest.mark.parametrize("resolver", ["", None])
def test_a_reference_without_a_resolver_is_refused(log, resolver):
    with pytest.raises(ValueError, match="resolver"):
        approval_reference(chap_demo.entry_for(log, "decide.approve"), resolver)


def test_a_confirmed_approval(log):
    check = check_approval(_ref(log, "decide.approve"), log["entries"], log["chain_head"])
    assert (check.verdict, check.reference_resolves, check.digest_matches,
            check.decision, check.chain_replays) == (CONFIRMED, True, True, "decide.approve", True)


def test_an_approval_altered_after_the_reference_was_made(log):
    reference = _ref(log, "decide.approve")
    altered = copy.deepcopy(log)
    chap_demo.entry_for(altered, "decide.approve")["envelope"]["params"]["comment"] = "edited"
    check = check_approval(reference, altered["entries"], altered["chain_head"])
    assert (check.verdict, check.digest_matches, check.chain_replays) == (CONTRADICTED, False, False)


def test_a_rejection_in_the_approvals_place(log):
    reject = chap_demo.entry_for(log, "decide.reject")
    reference = {**_ref(log, "decide.approve"), "id": f"audit/{reject['seq']}",
                 "digest": envelope_digest(reject["envelope"])}
    check = check_approval(reference, log["entries"], log["chain_head"])
    assert (check.verdict, check.digest_matches, check.decision) == (
        NOT_AN_APPROVAL, True, "decide.reject")


def test_an_override_is_not_an_approval_unless_the_relying_party_accepts_it(log):
    reference = _ref(log, "decide.override", accept_override=True)
    assert check_approval(reference, log["entries"], log["chain_head"]).verdict == NOT_AN_APPROVAL
    assert check_approval(reference, log["entries"], log["chain_head"],
                          accept_override=True).verdict == CONFIRMED


def test_a_reference_with_no_entry_behind_it(log):
    reference = {**_ref(log, "decide.approve"), "id": "audit/9999"}
    check = check_approval(reference, log["entries"], log["chain_head"])
    assert (check.verdict, check.reference_resolves, check.digest_matches, check.decision) == (
        UNCONFIRMED, False, None, None)


def test_a_head_that_does_not_match_contradicts_the_approval(log):
    check = check_approval(_ref(log, "decide.approve"), log["entries"], "sha256:" + "1" * 64)
    assert (check.verdict, check.chain_replays) == (CONTRADICTED, False)


@pytest.mark.parametrize("bad", [{"rel": "behavior-trace"}, {"id": "audit/x"},
                                 {"id": "7"}, {"id": "audit/-1"}])
def test_a_reference_that_is_not_this_profile_is_refused(log, bad):
    with pytest.raises(ValueError):
        check_approval({**_ref(log, "decide.approve"), **bad}, log["entries"], log["chain_head"])


def test_the_signed_record_covers_the_reference(log):
    sys.path.insert(0, str(EXAMPLES))
    from emit_record import build_record

    key = agentrust_trace.generate_key()
    jwk = agentrust_trace.key_to_jwk(key)
    record = agentrust_trace.sign_record(
        build_record(_ref(log, "decide.approve"), key, 1789400000), key)
    agentrust_trace.verify_record(record, jwk, max_age_seconds=None)
    record["references"][0]["digest"] = "sha256:" + "2" * 64
    with pytest.raises(InvalidSignature):
        agentrust_trace.verify_record(record, jwk, max_age_seconds=None)


def test_the_trace_spec_fixture_set_is_generated_and_checks_out(tmp_path):
    subprocess.run([sys.executable, str(EXAMPLES / "generate_trace_spec_fixtures.py"),
                    "--out", str(tmp_path)], check=True, capture_output=True)
    expected = json.loads((tmp_path / "expected.json").read_text(encoding="utf-8"))
    verdicts = set()
    for name, case in expected["cases"].items():
        record = json.loads((tmp_path / name).read_text(encoding="utf-8"))
        chap_log = json.loads((tmp_path / case["log"]).read_text(encoding="utf-8"))
        agentrust_trace.verify_record(record, expected["trace_signer_jwk"], max_age_seconds=None)
        check = check_approval(record["references"][0], chap_log["entries"],
                               chap_log["chain_head"])
        assert check.verdict == case["verdict"]
        verdicts.add(check.verdict)
    assert verdicts == {CONFIRMED, CONTRADICTED, NOT_AN_APPROVAL, UNCONFIRMED}
