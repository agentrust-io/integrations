"""musubi-trace-terms-v0 against released agentrust-trace 0.11.0.

All 55 vectors in vendor/trace-terms-v0/vectors/vectors.json are evaluated and
compared with their expected result, exactly as `trace_terms_v0.py --selftest`
does. Every PIC/TRACE authorization in them was signed by agentrust-trace's
own sign_bridge and is checked by its own verify_bridge. The named tests below
are the cases a per-call check cannot see.
"""

from __future__ import annotations

import pytest

from hs_trace_terms_support import VECTORS, acts, evaluate, signature

WITHIN = ("within_terms", [])


def test_there_are_55_vectors():
    assert len(VECTORS) == 55


@pytest.mark.parametrize("vector_id", sorted(VECTORS))
def test_vector_matches_expected(vector_id):
    assert signature(vector_id) == VECTORS[vector_id]["expect"]


def test_every_call_allowed_and_inside_the_terms_is_within():
    assert signature("TT01")["verdict"] == "within_terms"
    assert acts("TT01") == [WITHIN, WITHIN, WITHIN]


def test_each_call_allowed_but_the_count_agreed_is_exceeded():
    assert acts("TT02") == [WITHIN, WITHIN, ("outside_terms", ["calls_exceed_terms"])]
    assert acts("TT03")[2:] == [("outside_terms", ["calls_exceed_terms"])] * 2


def test_trace_allows_a_call_the_contract_prohibits():
    assert acts("TT04") == [("outside_terms", ["prohibited_action"])]


def test_authorizer_the_principal_never_agreed_to():
    assert acts("TT07") == [("outside_terms", ["authorizer_not_agreed", "executed_without_valid_authorization"])]


def test_trace_verify_bridge_refusals_are_reported_by_kind():
    assert acts("TT08") == [("outside_terms", ["authorization_denied", "executed_without_valid_authorization"])]
    assert acts("TT09") == [("outside_terms", ["authorization_invalid", "executed_without_valid_authorization"])]
    assert acts("TT10") == [("outside_terms", ["authorization_mismatch", "executed_without_valid_authorization"])]


def test_one_authorization_carried_two_calls():
    assert acts("TT12") == [WITHIN, ("outside_terms", ["authorization_reused"])]


def test_real_registry_record_outside_and_inside_the_agreed_runtime():
    (status, codes), = acts("TT15")
    assert status == "outside_terms" and "producer_not_agreed" in codes
    assert acts("TT16") == [WITHIN]


def test_whoever_assembles_the_bundle_can_only_make_an_act_undetermined():
    assert acts("TT11") == [("undetermined", ["evidence_not_as_signed"])]
    assert acts("TT36") == [("undetermined", ["authorizer_key_not_supplied"])]
    assert acts("TT43") == [WITHIN, ("undetermined", ["evidence_not_as_signed"])]


def test_terms_not_signed_by_both_parties_are_refused():
    assert signature("TT25") == {"verdict": "refused", "refusals": ["terms_one_sided"], "acts": []}


def test_no_acts_is_not_within():
    assert signature("TT41") == {"verdict": "undetermined", "refusals": [], "acts": []}


def test_the_evaluator_reports_the_agentrust_trace_it_ran_against():
    import agentrust_trace

    out = evaluate("TT01")
    assert out["agentrust_trace"] == agentrust_trace.__version__
    pinned = agentrust_trace.__version__ == "0.11.0"
    assert ("agentrust_trace_not_the_pinned_version" in out["findings"]) is (not pinned)
