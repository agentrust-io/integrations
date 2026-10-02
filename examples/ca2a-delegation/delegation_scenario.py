#!/usr/bin/env python3
"""
cA2A delegation scenario for the credit-risk workflow.

cMCP governs the agent-to-tool boundary (what one agent may call). cA2A governs
the agent-to-agent boundary: when a lead agent hands part of a task to a
sub-agent, each hop carries a signed delegation credential whose scope is a
provable subset of its parent. This module builds that chain for the credit
scenario and a deliberately invalid variant that tries to widen scope.

What runs here is the part of cA2A that is built today: attenuated delegation
credentials and offline chain verification (``ca2a_runtime.delegation``). The
live peer path (attesting an inbound peer, sealing the payload to its
measurement) and the per-hop TRACE provenance record are cA2A roadmap; see the
README.
"""

from __future__ import annotations

from typing import Any

from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain

# Capabilities in the credit workflow. The authority to WRITE the risk report
# is the sensitive one: it is granted to the lead agent at the root but is
# deliberately never delegated onward, so no sub-agent can regain it.
CAP_READ_DOCS = "read:documents"
CAP_SCREEN = "screen:sanctions"
CAP_READ_BUREAU = "read:bureau"
CAP_RUN_MODEL = "run:risk-model"
CAP_WRITE_REPORT = "write:risk-report"

# depth 0: the credit platform grants the lead agent full assessment authority.
# depth 1: the lead agent delegates evidence-gathering to a screening sub-agent,
#          withholding run:risk-model and write:risk-report (separation of duties).
# depth 2: the screening sub-agent delegates only the bureau pull to a connector.
CREDIT_CHAIN_SCOPES = [
    frozenset({CAP_READ_DOCS, CAP_SCREEN, CAP_READ_BUREAU, CAP_RUN_MODEL, CAP_WRITE_REPORT}),
    frozenset({CAP_READ_DOCS, CAP_SCREEN, CAP_READ_BUREAU}),
    frozenset({CAP_READ_BUREAU}),
]

# The credit platform's root key. A verifier trusts this issuer, and only this
# issuer, to start a chain. In a deployment it is configured, not generated;
# here it is minted once per process so the demo stays offline.
_PLATFORM_ROOT_PRIV, PLATFORM_ROOT = new_keypair()

HOP_LABELS = [
    "credit-platform -> lead-credit-agent",
    "lead-credit-agent -> screening-sub-agent",
    "screening-sub-agent -> bureau-connector",
]


def _build(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """Sign a linear delegation chain over the given per-hop scopes.

    Continuity is preserved: each hop's issuer is the previous hop's subject.
    """
    chain: list[DelegationCredential] = []
    priv, pub = _PLATFORM_ROOT_PRIV, PLATFORM_ROOT
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"credit-cred-{depth}",
            issuer=pub,
            subject=next_pub,
            scope=scope,
            depth=depth,
            parent_id=parent_id,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


def build_credit_chain() -> list[DelegationCredential]:
    """A valid, attenuating credit delegation chain (verify_chain passes)."""
    return _build(CREDIT_CHAIN_SCOPES)


def build_escalation_attempt() -> list[DelegationCredential]:
    """An invalid chain: the bureau connector tries to grant itself
    write:risk-report, which its parent (the screening sub-agent) never held.
    verify_chain raises ScopeEscalation."""
    scopes = list(CREDIT_CHAIN_SCOPES)
    scopes[2] = frozenset({CAP_READ_BUREAU, CAP_WRITE_REPORT})
    return _build(scopes)


def as_chain_document(chain: list[DelegationCredential]) -> dict[str, Any]:
    """Serialize a chain to the {"chain": [...]} shape ca2a verify-chain reads."""
    return {"chain": [c.body() | {"signature": c.signature} for c in chain]}


def verify(chain: list[DelegationCredential]) -> None:
    """Raise a ca2a_runtime error on the first invariant violation.

    trusted_root_issuers is what makes this an authorization check. Without it
    verify_chain is structural only, and a self-consistent chain an attacker
    signs from a key of their own passes every other invariant.
    """
    verify_chain(chain, trusted_root_issuers={PLATFORM_ROOT})
