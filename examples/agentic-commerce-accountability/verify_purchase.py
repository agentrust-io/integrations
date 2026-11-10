#!/usr/bin/env python3
"""Offline verifier for the agentic-commerce accountability example."""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any


_MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON object key: {k!r}")
        out[k] = v
    return out


def _no_nonfinite_constant(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant is not allowed: {token}")


def _finite_float(token: str) -> float:
    val = float(token)
    if not math.isfinite(val):
        raise ValueError(f"non-finite JSON float is not allowed: {token}")
    return val


def _loads_strict(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_no_nonfinite_constant,
        parse_float=_finite_float,
    )


def digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _matches_digest(expected: Any, section: dict[str, Any]) -> bool:
    try:
        return expected == digest(section)
    except (TypeError, ValueError):
        return False


def verify(bundle: dict[str, Any]) -> list[str]:
    if not isinstance(bundle, dict):
        return ["bundle must be a JSON object"]
    errors: list[str] = []
    for section in (
        "authority_grant",
        "purchase_request",
        "policy_decision",
        "runtime_evidence",
        "purchase_receipt",
    ):
        if not isinstance(bundle.get(section), dict):
            return [f"{section} must be a JSON object"]
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
    if type(amount) is not int or amount <= 0 or amount > _MAX_SAFE_INTEGER:
        errors.append("amount is not a positive integer in minor units")
    elif type(ceiling) is not int or ceiling <= 0 or ceiling > _MAX_SAFE_INTEGER:
        errors.append("authority grant ceiling is not an integer")
    elif amount > ceiling:
        errors.append("amount exceeds delegated authority")
    if evidence["runtime_identity"] != grant["delegate"]:
        errors.append("runtime is not the delegate named in the authority grant")
    if not _matches_digest(decision["request_digest"], request):
        errors.append("policy decision is not bound to the purchase request")
    if not _matches_digest(decision["authority_digest"], grant):
        errors.append("policy decision is not bound to the authority grant")
    if not _matches_digest(evidence["policy_decision_digest"], decision):
        errors.append("runtime evidence is not bound to the policy decision")
    if not _matches_digest(receipt["request_digest"], request):
        errors.append("receipt is not bound to the purchase request")
    if not _matches_digest(receipt["runtime_evidence_digest"], evidence):
        errors.append("receipt is not bound to the runtime evidence")
    if decision["outcome"] != "allow":
        errors.append("policy decision did not allow the purchase")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python verify_purchase.py <bundle.json>", file=sys.stderr)
        return 2
    try:
        bundle = _loads_strict(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"REJECTED\n- {exc}")
        return 1
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
