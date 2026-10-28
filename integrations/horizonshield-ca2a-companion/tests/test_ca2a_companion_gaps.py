"""The four gaps the companion covers, run against released ca2a-runtime.

Every vector in vendor/ca2a-companion-v0/vectors/vectors.json is settled and
compared with its expected output, exactly as `companion_v0.py --selftest`
does. Each vector is assigned to the gap it exercises, and each gap has named
tests for a case where the evidence holds and cases where it is refused or a
violation is reported. Every delegation credential and revocation statement in
the vectors was built and signed by ca2a-runtime itself
(tests/test_ca2a_companion_vendored.py rebuilds the file byte for byte).
"""

from __future__ import annotations

import inspect

import pytest
from ca2a_runtime.delegation import credential as ca2a_credential

from hs_ca2a_support import EVIDENCE_VECTORS, SETTLEMENT_VECTORS, companion, evidence, settle

# Gap 1: revocation publication. Revocations are entries of an append-only log
# signed by its operator; a checkpoint is anchored in a Bitcoin block header;
# the RevocationSnapshot handed to cA2A is built from the log.
REVOCATION_PUBLICATION = [
    "CA04_published_revocation",
    "CA05_backdated_revocation",
    "CA06_delegate_cannot_revoke",
    "CA17_log_entry_rewritten",
    "CA18_entry_withheld",
    "CA19_checkpoint_resigned_after_anchor",
    "CA20_anchor_too_shallow",
    "CA21_as_of_after_anchor",
    "CA22_revocation_dated_after_logging",
    "CA28_ancestor_revoked",
    "CA33_early_logged_revocation_still_applies",
    "CA45_logged_revocation_in_force_whatever_its_date",
    "EV01_consistent",
    "EV02_equivocation_same_size",
    "EV03_promise_kept",
    "EV04_promise_broken",
    "EV05_newer_checkpoint_smaller",
    "EV06_fork_with_smaller_log_supplied",
    "EV07_fork_detected_in_either_order",
    "EV08_edited_entries_do_not_frame",
    "EV09_entry_from_another_key",
    "EV10_entries_not_of_the_checkpoint",
    "EV11_withheld_entry",
    "EV12_deep_nesting_is_input_error",
]

# Gap 2: single use across requests. Holder-signed credential-use items carry
# the whole chain; issuer-signed use limits count every use of a credential
# under any chain that contains it and with any responder.
SINGLE_USE = [
    "CA01_within",
    "CA02_single_use_across_requests",
    "CA11_use_not_logged",
    "CA12_use_logged_late",
    "CA26_tightest_policy",
    "CA27_policy_by_non_issuer",
    "CA31_same_use_logged_twice",
    "CA32_redelegation_does_not_reset_a_limit",
    "CA35_use_names_its_responder",
    "CA37_policy_is_not_retroactive",
    "CA43_one_use_per_responder",
    "CA44_reissued_ancestor_does_not_reset_a_limit",
]

# Gap 3: portable execution receipts. Ed25519 receipts signed by the responder,
# naming caller, lineage, capability, request occurrence, a seen Bitcoin block
# and the outcome.
EXECUTION_RECEIPTS = [
    "CA03_duplicate_execution",
    "CA10_caller_not_leaf",
    "CA13_chain_not_supplied",
    "CA14_receipt_altered",
    "CA15_request_mismatch",
    "CA16_denial_then_result",
    "CA34_hex_with_trailing_newline",
    "CA39_capability_not_in_scope",
    "CA40_logged_before_seen_block",
    "CA41_seen_block_not_in_view",
]

# Gap 4: a commitment step. Commit and reveal items in a session whose
# identifier binds its participants.
COMMITMENT_STEP = [
    "CA23_commit_reveal_ok",
    "CA24_reveal_before_commit",
    "CA25_reveal_mismatch",
    "CA38_outsider_cannot_spoil_a_session",
]

# Not a gap: cA2A's own refusals reported unchanged, and input handling.
CA2A_RULES_AND_INPUT = [
    "CA07_scope_escalation",
    "CA08_untrusted_root",
    "CA09_expired_at_log_time",
    "CA29_chain_signature_forged",
    "CA30_unknown_item",
    "CA36_forged_chain_copy_does_not_displace",
    "CA42_malformed_trust_is_refused",
]

GROUPS = {
    "revocation_publication": REVOCATION_PUBLICATION,
    "single_use": SINGLE_USE,
    "execution_receipts": EXECUTION_RECEIPTS,
    "commitment_step": COMMITMENT_STEP,
    "ca2a_rules_and_input": CA2A_RULES_AND_INPUT,
}
ALL_IDS = [(group, vid) for group, ids in GROUPS.items() for vid in ids]


def test_every_vector_is_assigned_to_exactly_one_group():
    assigned = [vid for _, vid in ALL_IDS]
    assert len(assigned) == len(set(assigned))
    assert set(assigned) == set(SETTLEMENT_VECTORS) | set(EVIDENCE_VECTORS)
    assert len(assigned) == 57


@pytest.mark.parametrize(("group", "vector_id"), ALL_IDS, ids=[f"{g}:{v}" for g, v in ALL_IDS])
def test_vector_matches_expected(group, vector_id):
    if vector_id in SETTLEMENT_VECTORS:
        assert settle(vector_id) == SETTLEMENT_VECTORS[vector_id]["expected"]
    else:
        assert evidence(vector_id) == EVIDENCE_VECTORS[vector_id]["expected"]


def _receipts(vector_id):
    return [(r["disposition"], r["reasons"]) for r in settle(vector_id)["receipts"]]


# ---------------------------------------------------------------- gap 1
def test_revocation_kept_promise_and_consistent_checkpoints():
    assert evidence("EV03_promise_kept") == {"result": "kept", "seq": 2}
    assert evidence("EV01_consistent") == {"result": "consistent", "prefix": 3}


def test_revocation_withheld_from_a_covering_checkpoint_is_provable():
    assert evidence("EV11_withheld_entry") == {"result": "operator_withheld", "seq": 2}


def test_revocation_changed_after_the_operator_signed_it_is_provable():
    assert evidence("EV04_promise_broken") == {"result": "operator_equivocation", "seq": 2}
    assert evidence("EV02_equivocation_same_size")["result"] == "operator_equivocation"


def test_log_missing_an_entry_under_its_checkpoint_is_refused():
    log = settle("CA18_entry_withheld")["log"]
    assert log == {"verified": False, "problem": "size_mismatch"}


def test_revocation_logged_before_execution_is_in_force_through_ca2a():
    result = settle("CA04_published_revocation")["receipts"][0]
    assert result["ca2a_at_execution"] == "CREDENTIAL_REVOKED"
    assert (result["disposition"], result["reasons"]) == ("outside", ["executed_after_published_revocation"])


def test_revocation_dated_early_but_logged_late_is_reported_separately():
    result = settle("CA05_backdated_revocation")["receipts"][0]
    assert result["ca2a_at_execution"] == "ok"
    assert result["ca2a_audit"] == "CREDENTIAL_REVOKED"
    assert (result["disposition"], result["reasons"]) == ("late_revocation_only", ["revocation_published_late"])


def test_revocation_by_the_delegate_itself_has_no_authority():
    assert _receipts("CA06_delegate_cannot_revoke") == [("within_delegation", [])]


# ---------------------------------------------------------------- gap 2
def test_single_use_credential_used_once_is_within():
    assert _receipts("CA01_within") == [("within_delegation", [])]
    assert _receipts("CA31_same_use_logged_twice") == [("within_delegation", [])]


@pytest.mark.parametrize("vector_id", [
    "CA02_single_use_across_requests",
    "CA43_one_use_per_responder",
    "CA32_redelegation_does_not_reset_a_limit",
    "CA44_reissued_ancestor_does_not_reset_a_limit",
])
def test_single_use_credential_used_twice_exceeds_its_limit(vector_id):
    assert _receipts(vector_id) == [("within_delegation", []), ("outside", ["use_limit_exceeded"])]


def test_use_limit_signed_by_a_non_issuer_is_no_limit():
    assert _receipts("CA27_policy_by_non_issuer") == [("within_delegation", []), ("within_delegation", [])]


def test_use_not_logged_before_execution_is_outside():
    assert _receipts("CA12_use_logged_late") == [("outside", ["use_not_logged_before_execution"])]


# ---------------------------------------------------------------- gap 3
def test_signed_denial_then_result_are_both_receipts_and_not_a_duplicate():
    settlement = settle("CA16_denial_then_result")
    assert [r["outcome"] for r in settlement["receipts"]] == ["denial", "result"]
    assert _receipts("CA16_denial_then_result") == [("within_delegation", []), ("within_delegation", [])]


def test_receipt_changed_after_signing_is_rejected():
    settlement = settle("CA14_receipt_altered")
    assert settlement["receipts"] == []
    assert settlement["items_rejected"] == [{"reason": "signature_invalid", "seq": 2}]


def test_second_result_for_one_request_is_a_duplicate_execution():
    assert _receipts("CA03_duplicate_execution") == [("within_delegation", []), ("outside", ["duplicate_execution"])]


def test_receipt_bound_to_its_request_and_its_seen_block():
    assert _receipts("CA15_request_mismatch") == [("outside", ["request_does_not_match_receipt"])]
    assert _receipts("CA40_logged_before_seen_block") == [("outside", ["logged_before_seen_block"])]
    assert _receipts("CA41_seen_block_not_in_view") == [("unassessed", ["seen_block_not_in_view"])]


# ---------------------------------------------------------------- gap 4
def _session(vector_id):
    (session,) = settle(vector_id)["sessions"]
    return session["simultaneous"], session["problems"]


def test_commit_then_reveal_by_every_participant_is_simultaneous():
    assert _session("CA23_commit_reveal_ok") == (True, [])
    assert _session("CA38_outsider_cannot_spoil_a_session") == (True, [])


def test_reveal_before_another_commit_is_not_simultaneous():
    assert _session("CA24_reveal_before_commit") == (False, ["a_reveal_preceded_a_commit"])


def test_reveal_that_does_not_open_its_commitment_is_not_simultaneous():
    assert _session("CA25_reveal_mismatch") == (False, ["reveal_does_not_match"])


# ---------------------------------------------------------------- the pin
def test_the_private_ca2a_call_this_entry_is_pinned_for():
    """companion_v0.py calls ca2a_runtime.delegation.credential._check_revocation.

    If this fails on a newer ca2a-runtime, the private call moved or changed;
    see agentrust-io/ca2a#263 for the public call this entry should switch to.
    """
    private = ca2a_credential._check_revocation
    assert companion.ca2a_check_revocation is private
    params = inspect.signature(private).parameters
    assert list(params) == ["chain", "revocations", "at_time", "now", "max_staleness"]
    assert all(params[name].kind is inspect.Parameter.KEYWORD_ONLY for name in ("at_time", "now", "max_staleness"))
