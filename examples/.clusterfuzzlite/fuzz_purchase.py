#!/usr/bin/python3
"""Fuzz the agentic-commerce purchase verifier.

verify() decides whether a purchase bundle (authority grant, request, policy
decision, runtime evidence, merchant receipt) hangs together. An empty error
list is an acceptance, so the property checked is the one that matters: when it
accepts, every constraint it claims to check really holds. Malformed shapes may
raise KeyError, TypeError, AttributeError or RecursionError, which the CLI turns
into a non-zero exit; that is a refusal, not an acceptance.

A NaN spending ceiling, a negative amount and a string allow-list (which turns
membership into a substring test) each used to be accepted.
"""
import json
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agentic-commerce-accountability"))

with atheris.instrument_imports():
    from verify_purchase import digest, verify

_REFUSALS = (KeyError, TypeError, AttributeError, RecursionError)


def _check_acceptance(bundle: dict) -> None:
    grant = bundle["authority_grant"]
    request = bundle["purchase_request"]
    decision = bundle["policy_decision"]
    evidence = bundle["runtime_evidence"]
    receipt = bundle["purchase_receipt"]
    amount, ceiling = request["amount_minor"], grant["max_amount_minor"]
    assert type(amount) is int and type(ceiling) is int, (amount, ceiling)
    assert 0 < amount <= ceiling, (amount, ceiling)
    assert isinstance(grant["allowed_operations"], list)
    assert isinstance(grant["allowed_merchants"], list)
    assert request["operation"] in grant["allowed_operations"]
    assert request["merchant_id"] in grant["allowed_merchants"]
    assert request["currency"] == grant["currency"]
    assert evidence["runtime_identity"] == grant["delegate"]
    assert decision["outcome"] == "allow"
    assert decision["request_digest"] == digest(request)
    assert decision["authority_digest"] == digest(grant)
    assert evidence["policy_decision_digest"] == digest(decision)
    assert receipt["request_digest"] == digest(request)
    assert receipt["runtime_evidence_digest"] == digest(evidence)


def _rebind(bundle: dict) -> None:
    """Re-derive every digest link from the fuzzed content.

    A fuzzer cannot find SHA-256 preimages, so without this nearly every
    mutation dies on a digest mismatch and the constraint checks behind it are
    never reached with a consistent chain.
    """
    request, grant = bundle["purchase_request"], bundle["authority_grant"]
    decision, evidence = bundle["policy_decision"], bundle["runtime_evidence"]
    decision["request_digest"] = digest(request)
    decision["authority_digest"] = digest(grant)
    evidence["policy_decision_digest"] = digest(decision)
    receipt = bundle["purchase_receipt"]
    receipt["request_digest"] = digest(request)
    receipt["runtime_evidence_digest"] = digest(evidence)


def _check(bundle: dict) -> None:
    try:
        errors = verify(bundle)
    except _REFUSALS:
        return
    assert isinstance(errors, list), errors
    if not errors:
        _check_acceptance(bundle)


def TestOneInput(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
        _check(json.loads(text))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return
    # The same document again with its digest chain made consistent.
    rebound = json.loads(text)
    try:
        _rebind(rebound)
    except _REFUSALS:
        return
    _check(rebound)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
