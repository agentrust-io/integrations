"""Regenerate the committed delegation chain fixtures, byte for byte.

Keys are Ed25519 seeds derived from published labels, so every fixture is
deterministic and carries no secret material. Anyone can regenerate the
private keys from this file. These chains are test evidence for the verifier
in ``delegation_verify.py``. They prove nothing about any real principal,
employee or agent.

Two record families are minted.

``simple_chain`` is a two-record chain, root then leaf. A principal delegates
to a delegate, who delegates onward to an agent. ``tests/test_delegation_verify.py``
reuses this one committed chain for the valid, revoked-ancestor,
revocation-unknown and delegation_ref-mismatch cases, varying only the
resolver each test supplies, not the chain. The root (index 0) is the
delegate's own authority, issued by the principal. The leaf (index 1) is the
agent's authority, issued by the delegate. Revoking index 0 revokes an
ancestor of the leaf without touching the leaf record itself.

The second family is the sponsor handover scenario from
Agent-Authority-Conformance/aps-conformance-suite PR #108. An org delegates
to an employee, who delegates to an agent. When the employee leaves, the org
revokes the record naming that employee as subject, the root of that
employee's chain, which invalidates everything issued under it. A
replacement org and employee, entirely independently keyed, delegate to the
same agent identity again. ``old_root`` is the OLD org's grant to the OLD
employee. ``old_leaf_agent_x`` and ``old_leaf_agent_y`` are two sibling
delegations the OLD employee issued to two different agents, sharing that
same root. ``new_root`` and ``new_leaf_agent_x`` are a NEW org and NEW
employee's independent chain to the same ``agent-x`` identity. That agent has
no successor in this fixture, so no chain is minted replacing
``old_leaf_agent_y``.

Every record uses the same scope, spend, reputation, values and
reversibility facets, so the only things that change between a parent and
its child are ``depth.remaining`` (down by exactly one hop) and the ``time``
window (contained in the parent's, and never starting before the child's own
``issued_at``, which draft-pidlisnyi-aps-03 section 3.2 requires of a
non-root record).

Run from the integration directory:

    python fixtures/delegation-chain/generate.py

Then ``git diff`` should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent

SCOPE = {"profile": "aps-hierarchical-v1", "grants": ["agent:act"]}
SPEND = {"mode": "unbounded"}
REPUTATION = {"profile": "aps-score-0-100-v1", "ceiling": 100}
VALUES = {"profile": "aps-values-identifiers-v1", "required": []}
REVERSIBILITY = {"profile": "aps-tci-v1", "ceiling": "irreversible"}

HORIZON = "2026-09-21T00:00:00.000Z"

PRINCIPAL = "did:aps:example:principal-01"
DELEGATE = "did:aps:example:delegate-01"
AGENT = "did:aps:example:agent-01"

OLD_ORG = "did:aps:example:org-old-01"
OLD_EMPLOYEE = "did:aps:example:employee-old-01"
NEW_ORG = "did:aps:example:org-new-01"
NEW_EMPLOYEE = "did:aps:example:employee-new-01"
AGENT_X = "did:aps:example:agent-x-01"
AGENT_Y = "did:aps:example:agent-y-01"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aeoess-aps-integration:delegation-chain-fixture:{label}".encode()).hexdigest()


def _vm(entity: str) -> str:
    return entity + "#key-1"


def _body(
    *,
    issuer: str,
    subject: str,
    parent_id: str | None,
    issued_at: str,
    nonce_label: str,
    depth_remaining: int,
    not_before: str,
) -> dict:
    return {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "parent_delegation_id": parent_id,
        "issuer": issuer,
        "subject": subject,
        "verification_method": _vm(issuer),
        "issued_at": issued_at,
        "nonce": _seed(nonce_label)[:32],
        "authority": {
            "scope": SCOPE,
            "spend": SPEND,
            "depth": {"remaining": depth_remaining},
            "time": {"not_before": not_before, "not_after": HORIZON},
            "reputation": REPUTATION,
            "values": VALUES,
            "reversibility": REVERSIBILITY,
        },
    }


def _issue_root(entity: str, subject: str, issued_at: str, nonce_label: str) -> tuple[dict, str]:
    private_key = _seed(f"{entity}:private")
    record = issue_authority_delegation(
        _body(
            issuer=entity,
            subject=subject,
            parent_id=None,
            issued_at=issued_at,
            nonce_label=nonce_label,
            depth_remaining=1,
            not_before=issued_at,
        ),
        private_key,
    )
    return record, private_key


def _issue_leaf(
    parent: dict,
    *,
    issuer: str,
    subject: str,
    issued_at: str,
    nonce_label: str,
    resolve_verification_key,
) -> dict:
    return issue_sub_authority_delegation(
        parent,
        _body(
            issuer=issuer,
            subject=subject,
            parent_id=parent["delegation_id"],
            issued_at=issued_at,
            nonce_label=nonce_label,
            depth_remaining=0,
            not_before=issued_at,
        ),
        _seed(f"{issuer}:private"),
        now=parent["issued_at"],
        resolve_verification_key=resolve_verification_key,
        resolve_revocation=lambda _d: "active",
    )


def main() -> None:
    keys: dict[str, str] = {}

    def resolve_verification_key(_issuer, verification_method, _issued_at):
        return keys[verification_method]

    def pin(entity: str, private_key: str) -> None:
        keys[_vm(entity)] = public_key_from_private(private_key)

    # simple_chain: principal -> delegate -> agent
    simple_root, principal_key = _issue_root(PRINCIPAL, DELEGATE, "2026-09-20T00:00:00.000Z", "simple-root-nonce")
    pin(PRINCIPAL, principal_key)
    delegate_key = _seed(f"{DELEGATE}:private")
    pin(DELEGATE, delegate_key)
    simple_leaf = _issue_leaf(
        simple_root,
        issuer=DELEGATE,
        subject=AGENT,
        issued_at="2026-09-20T01:00:00.000Z",
        nonce_label="simple-leaf-nonce",
        resolve_verification_key=resolve_verification_key,
    )

    # OLD sponsor chain: org-old -> employee-old -> {agent-x, agent-y}
    old_root, old_org_key = _issue_root(OLD_ORG, OLD_EMPLOYEE, "2026-09-20T00:00:00.000Z", "old-root-nonce")
    pin(OLD_ORG, old_org_key)
    old_employee_key = _seed(f"{OLD_EMPLOYEE}:private")
    pin(OLD_EMPLOYEE, old_employee_key)
    old_leaf_agent_x = _issue_leaf(
        old_root,
        issuer=OLD_EMPLOYEE,
        subject=AGENT_X,
        issued_at="2026-09-20T01:00:00.000Z",
        nonce_label="old-leaf-agent-x-nonce",
        resolve_verification_key=resolve_verification_key,
    )
    old_leaf_agent_y = _issue_leaf(
        old_root,
        issuer=OLD_EMPLOYEE,
        subject=AGENT_Y,
        issued_at="2026-09-20T01:00:00.000Z",
        nonce_label="old-leaf-agent-y-nonce",
        resolve_verification_key=resolve_verification_key,
    )

    # NEW sponsor chain: org-new -> employee-new -> agent-x (independent, same agent-x identity)
    new_root, new_org_key = _issue_root(NEW_ORG, NEW_EMPLOYEE, "2026-09-20T00:00:00.000Z", "new-root-nonce")
    pin(NEW_ORG, new_org_key)
    new_employee_key = _seed(f"{NEW_EMPLOYEE}:private")
    pin(NEW_EMPLOYEE, new_employee_key)
    new_leaf_agent_x = _issue_leaf(
        new_root,
        issuer=NEW_EMPLOYEE,
        subject=AGENT_X,
        issued_at="2026-09-20T01:00:00.000Z",
        nonce_label="new-leaf-agent-x-nonce",
        resolve_verification_key=resolve_verification_key,
    )

    records = {
        "simple_root": simple_root,
        "simple_leaf": simple_leaf,
        "old_root": old_root,
        "old_leaf_agent_x": old_leaf_agent_x,
        "old_leaf_agent_y": old_leaf_agent_y,
        "new_root": new_root,
        "new_leaf_agent_x": new_leaf_agent_x,
    }
    meta = {
        "reference_time": "2026-09-20T12:00:00.000Z",
        "generated_by": "fixtures/delegation-chain/generate.py",
        "sdk": "agent-passport-system 4.0.0",
        "trusted_roots": [PRINCIPAL, OLD_ORG, NEW_ORG],
        "simple_leaf_delegation_ref": simple_leaf["delegation_id"],
        "old_leaf_agent_x_delegation_ref": old_leaf_agent_x["delegation_id"],
        "old_leaf_agent_y_delegation_ref": old_leaf_agent_y["delegation_id"],
        "new_leaf_agent_x_delegation_ref": new_leaf_agent_x["delegation_id"],
    }
    keys_out = {
        "note": "Public keys only. Seeds are sha256 over the labels in generate.py, so the material is public by construction.",
        "pinned": keys,
    }
    for name, value in (
        ("records.json", records),
        ("keys.json", keys_out),
        ("meta.json", meta),
    ):
        (HERE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
