"""Bounded pre-commit enforcement tests. No OntoGuard semantic engine."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

PROOF = Path(__file__).resolve().parents[1] / "examples" / "controlled-execution-proof-2026-09-17"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "precommit-enforcement"
sys.path.insert(0, str(PROOF))
sys.path.insert(0, str(EXAMPLE))
sys.path.insert(0, str(PROOF.parents[1]))

from controlled_executor import ControlledExecutor  # noqa: E402
from gate import (  # noqa: E402
    ACTION_ALLOW_250K,
    ACTION_BLOCK_260K,
    ACTION_ESCALATE_NEW_COUNTERPARTY,
    SignedTestAuthorizer,
    attempt_protected,
    evaluate_precommit,
)
from ontoguard_trace import partner_action_binding_digest  # noqa: E402


def _ctx(tmp_path: Path):
    authorizer = SignedTestAuthorizer()
    jwks = authorizer.write_ontoguard_jwks(tmp_path / "og.json")
    return authorizer, jwks


def test_same_capability_allow_block_escalate_on_different_actions(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")
    block = authorizer.mint(ACTION_BLOCK_260K, "BLOCK")
    escalate = authorizer.mint(ACTION_ESCALATE_NEW_COUNTERPARTY, "ESCALATE")

    assert partner_action_binding_digest(ACTION_ALLOW_250K) != partner_action_binding_digest(ACTION_BLOCK_260K)
    assert partner_action_binding_digest(ACTION_ALLOW_250K) != partner_action_binding_digest(
        ACTION_ESCALATE_NEW_COUNTERPARTY
    )

    permitted = evaluate_precommit(
        ACTION_ALLOW_250K,
        result_bytes=allow["result_bytes"],
        signature_b64url=allow["signature"],
        public_jwk=allow["public_jwk"],
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    denied_block = evaluate_precommit(
        ACTION_BLOCK_260K,
        result_bytes=block["result_bytes"],
        signature_b64url=block["signature"],
        public_jwk=block["public_jwk"],
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    denied_escalate = evaluate_precommit(
        ACTION_ESCALATE_NEW_COUNTERPARTY,
        result_bytes=escalate["result_bytes"],
        signature_b64url=escalate["signature"],
        public_jwk=escalate["public_jwk"],
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert permitted.permit is True and permitted.action == "ALLOW"
    assert denied_block.permit is False and denied_block.action == "BLOCK"
    assert denied_escalate.permit is False and denied_escalate.action == "ESCALATE"


def test_allow_for_one_action_does_not_authorize_different_action(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow_250 = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")
    decision = evaluate_precommit(
        ACTION_BLOCK_260K,
        result_bytes=allow_250["result_bytes"],
        signature_b64url=allow_250["signature"],
        public_jwk=allow_250["public_jwk"],
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert decision.permit is False
    assert "payload mismatch" in decision.reason


def test_bypass_without_verified_authorization_cannot_commit(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    executor = ControlledExecutor()

    none = attempt_protected(executor, ACTION_ALLOW_250K, minted=None, ontoguard_jwks_path=jwks)
    assert none["result"] == "EXECUTION_REFUSED"
    assert executor.store.commit_count == 0
    assert executor.store.protected_effect_formed is False

    digest_only = attempt_protected(
        executor,
        ACTION_ALLOW_250K,
        minted={
            "action_binding_digest": partner_action_binding_digest(ACTION_ALLOW_250K),
        },
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert digest_only["result"] == "EXECUTION_REFUSED"
    assert executor.store.commit_count == 0

    direct_digest = executor.attempt(
        ACTION_BLOCK_260K,
        partner_action_binding_digest(ACTION_BLOCK_260K),
    )
    assert direct_digest["result"] == "EXECUTION_REFUSED"
    assert "signed OntoGuard authorization is required" in direct_digest["reason"]
    assert executor.store.commit_count == 0
    assert executor.store.protected_effect_formed is False

    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")
    tampered = dict(allow)
    raw = allow["result_bytes"]
    tampered["result_bytes"] = raw[:-1] + (b"X" if raw[-1:] != b"X" else b"Y")
    bad = attempt_protected(
        executor,
        ACTION_ALLOW_250K,
        minted=tampered,
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert bad["result"] == "EXECUTION_REFUSED"
    assert executor.store.commit_count == 0

    block = authorizer.mint(ACTION_BLOCK_260K, "BLOCK")
    blocked = attempt_protected(
        executor,
        ACTION_BLOCK_260K,
        minted=block,
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert blocked["result"] == "EXECUTION_REFUSED"
    assert blocked["action"] == "BLOCK"
    assert executor.store.commit_count == 0

    escalate = authorizer.mint(ACTION_ESCALATE_NEW_COUNTERPARTY, "ESCALATE")
    escalated = attempt_protected(
        executor,
        ACTION_ESCALATE_NEW_COUNTERPARTY,
        minted=escalate,
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert escalated["result"] == "EXECUTION_REFUSED"
    assert escalated["action"] == "ESCALATE"
    assert executor.store.commit_count == 0

    wrong_action = attempt_protected(
        executor,
        ACTION_BLOCK_260K,
        minted=allow,
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert wrong_action["result"] == "EXECUTION_REFUSED"
    assert executor.store.commit_count == 0
    assert executor.store.status == "PENDING"


def test_exact_allow_commits_only_through_protected_entry(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")
    executor = ControlledExecutor()
    result = attempt_protected(
        executor,
        ACTION_ALLOW_250K,
        minted=allow,
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert result["result"] == "EXECUTED"
    assert executor.store.commit_count == 1
    assert executor.store.protected_effect_formed is True


def test_expired_untrusted_malformed_refuse(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")

    expired = evaluate_precommit(
        ACTION_ALLOW_250K,
        result_bytes=allow["result_bytes"],
        signature_b64url=allow["signature"],
        public_jwk=allow["public_jwk"],
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
        verification_time_utc=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    assert expired.permit is False
    assert "expired" in expired.reason

    empty = tmp_path / "empty.json"
    empty.write_text('{"keys": []}', encoding="utf-8")
    untrusted = evaluate_precommit(
        ACTION_ALLOW_250K,
        result_bytes=allow["result_bytes"],
        signature_b64url=allow["signature"],
        public_jwk=allow["public_jwk"],
        ontoguard_jwks_path=empty,
        allow_test_keys=True,
    )
    assert untrusted.permit is False

    malformed = evaluate_precommit(
        {"operation": "RELEASE_PAYMENT", "amount": "250000.00"},
        result_bytes=allow["result_bytes"],
        signature_b64url=allow["signature"],
        public_jwk=allow["public_jwk"],
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert malformed.permit is False
    assert "partner action binding missing" in malformed.reason



def test_malformed_cross_border_values_fail_closed_before_commit(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")

    malformed_values = ("false", 1, ["false"], {"value": False})
    for malformed_value in malformed_values:
        proposed = dict(ACTION_ALLOW_250K)
        proposed["cross_border"] = malformed_value
        executor = ControlledExecutor()

        decision = evaluate_precommit(
            proposed,
            result_bytes=allow["result_bytes"],
            signature_b64url=allow["signature"],
            public_jwk=allow["public_jwk"],
            ontoguard_jwks_path=jwks,
            allow_test_keys=True,
        )
        assert decision.permit is False
        assert "cross_border must be a boolean" in decision.reason

        attempted = attempt_protected(
            executor,
            proposed,
            minted=allow,
            ontoguard_jwks_path=jwks,
            allow_test_keys=True,
        )
        assert attempted["result"] == "EXECUTION_REFUSED"
        assert executor.store.commit_count == 0
        assert executor.store.protected_effect_formed is False


def test_unbound_extra_action_field_fails_closed(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")
    proposed = dict(ACTION_ALLOW_250K)
    proposed["unbound_instruction"] = "execute anyway"

    executor = ControlledExecutor()
    attempted = attempt_protected(
        executor,
        proposed,
        minted=allow,
        ontoguard_jwks_path=jwks,
        allow_test_keys=True,
    )
    assert attempted["result"] == "EXECUTION_REFUSED"
    assert "unexpected fields" in attempted["reason"]
    assert executor.store.commit_count == 0
    assert executor.store.protected_effect_formed is False


def test_default_rejects_test_keys(tmp_path: Path) -> None:
    authorizer, jwks = _ctx(tmp_path)
    allow = authorizer.mint(ACTION_ALLOW_250K, "ALLOW")
    decision = evaluate_precommit(
        ACTION_ALLOW_250K,
        result_bytes=allow["result_bytes"],
        signature_b64url=allow["signature"],
        public_jwk=allow["public_jwk"],
        ontoguard_jwks_path=jwks,
    )
    assert decision.permit is False
