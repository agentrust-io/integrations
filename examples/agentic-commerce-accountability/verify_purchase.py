#!/usr/bin/env python3
"""Offline verifier for the agentic-commerce accountability example."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def verify(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    grant = bundle["authority_grant"]
    request = bundle["purchase_request"]
    decision = bundle["policy_decision"]
    evidence = bundle["runtime_evidence"]
    receipt = bundle["purchase_receipt"]
    # A string here would turn membership into a substring test.
    operations = grant["allowed_operations"]
    merchants = grant["allowed_merchants"]
    if not isinstance(operations, list) or not isinstance(merchants, list):
        errors.append("authority grant allow-lists are not lists")
        operations, merchants = [], []
    if request["operation"] not in operations:
        errors.append("operation is outside delegated authority")
    if request["currency"] != grant["currency"]:
        errors.append("currency differs from delegated authority")
    if request["merchant_id"] not in merchants:
        errors.append("merchant is outside delegated authority")
    amount = request["amount_minor"]
    ceiling = grant["max_amount_minor"]
    # bool is an int subclass; a negative or zero amount would pass the ceiling,
    # and every amount compares false against a NaN ceiling.
    if type(amount) is not int or amount <= 0:
        errors.append("amount is not a positive integer in minor units")
    elif type(ceiling) is not int:
        errors.append("authority grant ceiling is not an integer")
    elif amount > ceiling:
        errors.append("amount exceeds delegated authority")
    if evidence["runtime_identity"] != grant["delegate"]:
        errors.append("runtime is not the delegate named in the authority grant")
    if decision["request_digest"] != digest(request):
        errors.append("policy decision is not bound to the purchase request")
    if decision["authority_digest"] != digest(grant):
        errors.append("policy decision is not bound to the authority grant")
    if evidence["policy_decision_digest"] != digest(decision):
        errors.append("runtime evidence is not bound to the policy decision")
    if receipt["request_digest"] != digest(request):
        errors.append("receipt is not bound to the purchase request")
    if receipt["runtime_evidence_digest"] != digest(evidence):
        errors.append("receipt is not bound to the runtime evidence")
    if decision["outcome"] != "allow":
        errors.append("policy decision did not allow the purchase")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python verify_purchase.py <bundle.json>", file=sys.stderr)
        return 2
    bundle = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    errors = verify(bundle)
    if errors:
        print("REJECTED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("ACCEPTED: authority, decision, runtime evidence, and receipt are linked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
