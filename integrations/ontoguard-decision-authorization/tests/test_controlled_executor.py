from pathlib import Path
import sys

PROOF = Path(__file__).resolve().parents[1] / "examples" / "controlled-execution-proof-2026-09-17"
sys.path.insert(0, str(PROOF))
sys.path.insert(0, str(PROOF.parents[1]))

from controlled_executor import (  # noqa: E402
    AUTHORIZED_ACTION,
    MUTATED_ACTION,
    ControlledExecutor,
    HarnessAuthorizer,
    run_live,
    verify_authorization_pre_commit,
)
from ontoguard_trace import partner_action_binding_digest  # noqa: E402


def test_positive_commits_and_negative_refuses():
    digest = partner_action_binding_digest(AUTHORIZED_ACTION)
    assert digest != partner_action_binding_digest(MUTATED_ACTION)

    pos = ControlledExecutor()
    ok = pos.attempt(AUTHORIZED_ACTION, digest)
    assert ok["result"] == "EXECUTED"
    assert pos.store.commit_count == 1
    assert pos.store.status == "RELEASED"
    assert pos.store.protected_effect_formed is True

    neg = ControlledExecutor()
    refused = neg.attempt(MUTATED_ACTION, digest)
    assert refused["result"] == "EXECUTION_REFUSED"
    assert neg.store.commit_count == 0
    assert neg.store.status == "PENDING"
    assert neg.store.protected_effect_formed is False


def test_live_harness_verifies_fresh_auth_then_commits(tmp_path):
    live = run_live()
    assert live["authorization_source"] == "ephemeral-harness-test-only"
    assert live["not_a_live_decision_api_result"] is True
    assert live["positive"]["authorization_verified_before_commit"] is True
    assert live["positive"]["after"]["commit_count"] == 1
    assert live["negative"]["after"]["commit_count"] == 0
    assert live["negative"]["adapter_rejected_mutated_receipt"] is True


def test_harness_authorizer_is_verifiable_before_attempt(tmp_path):
    authorizer = HarnessAuthorizer()
    minted = authorizer.mint(AUTHORIZED_ACTION)
    jwks = authorizer.write_ontoguard_jwks(tmp_path / "og.json")
    bound = verify_authorization_pre_commit(minted, jwks)
    assert bound["action"] == "ALLOW"
    assert bound["action_binding_digest"] == partner_action_binding_digest(AUTHORIZED_ACTION)
    store = ControlledExecutor()
    assert store.store.commit_count == 0
    store.attempt(AUTHORIZED_ACTION, bound["action_binding_digest"])
    assert store.store.commit_count == 1
