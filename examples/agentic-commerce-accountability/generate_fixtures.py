#!/usr/bin/env python3
"""Generate deterministic fixtures for the commerce accountability example."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from verify_purchase import digest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"


def build(amount_minor: int = 12_500) -> dict:
    grant = {"grant_id": "grant-2026-08-24-001", "principal": "user:alice", "delegate": "spiffe://buyer.example/agent/travel", "allowed_operations": ["ucp.checkout.complete"], "allowed_merchants": ["merchant:hotel-example"], "currency": "USD", "max_amount_minor": 20_000, "expires_at": "2026-08-25T00:00:00Z"}
    request = {"request_id": "checkout-001", "operation": "ucp.checkout.complete", "merchant_id": "merchant:hotel-example", "currency": "USD", "amount_minor": amount_minor, "cart_digest": "sha256:" + "a1" * 32}
    decision = {"decision_id": "agt-decision-001", "outcome": "allow", "policy_id": "commerce-spend-v1", "authority_digest": digest(grant), "request_digest": digest(request)}
    evidence = {"evidence_id": "trace-record-001", "profile": "illustrative-trace-reference", "runtime_identity": "spiffe://buyer.example/agent/travel", "policy_decision_digest": digest(decision), "attestation_reference": "urn:example:attestation:tdx:001"}
    receipt = {"receipt_id": "merchant-receipt-001", "status": "completed", "request_digest": digest(request), "runtime_evidence_digest": digest(evidence)}
    return {"authority_grant": grant, "purchase_request": request, "policy_decision": decision, "runtime_evidence": evidence, "purchase_receipt": receipt}


def write(name: str, value: dict) -> None:
    FIXTURES.mkdir(exist_ok=True)
    (FIXTURES / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    valid = build()
    write("valid-purchase.json", valid)
    overspend = deepcopy(valid)
    overspend["purchase_request"]["amount_minor"] = 50_000
    write("overspend-tamper.json", overspend)
