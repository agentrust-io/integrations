"""Functional merchant/audit regressions: real signatures, local SQLite effects.

No payment provider, network merchant, hardware attestation, or crypto test
double is used. Instrumentation observes actual private-handler entry, not just
committed counters, so a rollback cannot masquerade as pre-handler denial.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event, Lock
from types import SimpleNamespace
from typing import Any

import pytest
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms

from ucp_commerce import flow
from ucp_commerce.evidence import (
    create_trace,
    sign_decision,
    sign_grant,
    verify_decision,
    verify_grant,
    verify_trace,
)
from ucp_commerce.flow import (
    GRANT_KID,
    MERCHANT,
    MERCHANT_KID,
    PLATFORM_KID,
    PLATFORM_PROFILE,
    POLICY,
    RECEIPT_KID,
    AuditError,
    Bundle,
    Denied,
    Keys,
    Merchant,
    audit,
    completion_request,
    make_grant,
)
from ucp_commerce.schema import sample_checkout, sample_complete_request
from ucp_commerce.wire import (
    SignedMessage,
    sign_request,
    sign_response,
    verify_request,
    verify_response,
)

NOW = datetime(2026, 9, 7, 12, tzinfo=UTC)
CHECKOUT = "checkout-001"


@dataclass
class Harness:
    merchant: Merchant
    keys: Keys
    quote: SignedMessage
    request: SignedMessage
    grant: str
    calls: list[tuple[str, int]]

    def complete(self, **changes: Any) -> Bundle:
        arguments = {"token": self.grant, "checkout": self.quote, "request": self.request}
        arguments.update(changes)
        return self.merchant.complete(**arguments)

    def assert_denial(self, reason: str, **changes: Any) -> None:
        with pytest.raises(Denied) as error:
            self.complete(**changes)
        assert error.value.reason == reason
        assert str(error.value) == reason
        assert self.calls == []
        assert self.merchant.counts() == (0, 0)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    keys = Keys.generate()
    merchant = Merchant(tmp_path / "merchant.sqlite", keys, clock=lambda: NOW)
    merchant.seed_checkout(sample_checkout())
    calls: list[tuple[str, int]] = []
    call_lock = Lock()
    actual = merchant._complete_checkout

    def observed(connection: sqlite3.Connection, checkout: dict, invocation: int) -> dict:
        with call_lock:
            calls.append((checkout["id"], invocation))
        return actual(connection, checkout, invocation)

    monkeypatch.setattr(merchant, "_complete_checkout", observed)
    return Harness(
        merchant,
        keys,
        merchant.quote(CHECKOUT),
        completion_request(keys, NOW, CHECKOUT),
        make_grant(keys, NOW, grant_id="grant-one"),
        calls,
    )


def changed_grant(harness: Harness, **changes: Any) -> str:
    original = verify_grant(harness.grant, harness.keys.authority.public_key(), GRANT_KID)
    return sign_grant(original.model_copy(update=changes), harness.keys.authority, GRANT_KID)


def signed_quote(harness: Harness, body: dict, *, status: int = 200) -> SignedMessage:
    return sign_response(harness.request, status, body, harness.keys.merchant, MERCHANT_KID, NOW)


def changed_request(
    harness: Harness, *, body: dict | None = None, url: str | None = None, method: str = "POST"
) -> SignedMessage:
    return sign_request(
        method,
        url or harness.request.url,
        sample_complete_request() if body is None else body,
        harness.keys.platform,
        PLATFORM_KID,
        harness.request.header("idempotency-key"),
        NOW,
        ucp_agent=PLATFORM_PROFILE,
    )


def differently_serialized_request(harness: Harness) -> SignedMessage:
    """Independent released-library signing of equivalent but different raw JSON."""

    class Resolver(HTTPSignatureKeyResolver):
        def resolve_private_key(self, key_id: str) -> Any:
            assert key_id == PLATFORM_KID
            return harness.keys.platform

    body = json.dumps(sample_complete_request(), indent=2).encode()
    transport = SimpleNamespace(
        method="POST",
        url=harness.request.url,
        headers={
            "content-type": "application/json",
            "content-digest": "sha-256=:"
            + base64.b64encode(hashlib.sha256(body).digest()).decode()
            + ":",
            "idempotency-key": harness.request.header("idempotency-key"),
            "ucp-agent": f'profile="{PLATFORM_PROFILE}"',
        },
    )
    HTTPMessageSigner(
        signature_algorithm=algorithms.ECDSA_P256_SHA256, key_resolver=Resolver()
    ).sign(
        transport,
        key_id=PLATFORM_KID,
        created=NOW,
        expires=NOW + timedelta(minutes=5),
        include_alg=False,
        covered_component_ids=(
            "@method",
            "@authority",
            "@path",
            "content-type",
            "content-digest",
            "idempotency-key",
            "ucp-agent",
        ),
    )
    return SignedMessage(
        method="POST",
        url=harness.request.url,
        status=None,
        headers=tuple((name.lower(), value) for name, value in transport.headers.items()),
        body_b64=base64.b64encode(body).decode(),
    )


def test_allow_round_trip_and_repeatable_read_only_audit(harness: Harness) -> None:
    bundle = harness.complete()
    restored = Bundle.model_validate_json(bundle.model_dump_json())
    first = audit(restored, harness.keys.trust(), NOW)
    assert first == audit(restored, harness.keys.trust(), NOW)
    assert first.decision == "allow"
    assert first.invocation_number == 1
    assert first.grant_id == "grant-one"
    assert first.checkout_id == CHECKOUT
    assert (
        verify_response(bundle.response, harness.keys.trust().merchant, MERCHANT_KID, NOW)["status"]
        == "completed"
    )
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)
    with sqlite3.connect(harness.merchant.path) as connection:
        assert connection.execute("SELECT count(*) FROM retries").fetchone()[0] == 1


def test_correctly_signed_overspend_is_policy_denial(harness: Harness) -> None:
    token = changed_grant(harness, max_amount_minor=12_499)
    assert verify_grant(token, harness.keys.trust().authority, GRANT_KID).max_amount_minor == 12_499
    assert (
        verify_response(harness.quote, harness.keys.trust().merchant, MERCHANT_KID, NOW)["totals"][
            -1
        ]["amount"]
        == 12_500
    )
    harness.assert_denial("OVERSPEND", token=token)


@pytest.mark.parametrize(
    "updates,reason",
    [
        ({"merchant_origin": "https://other.example"}, "MERCHANT_AUTHORITY"),
        ({"merchant_key_sha256": "0" * 64}, "MERCHANT_AUTHORITY"),
        ({"platform_key_sha256": "0" * 64}, "PLATFORM_AUTHORITY"),
        ({"currency": "GBP"}, "CURRENCY"),
        ({"expires_at": int(NOW.timestamp())}, "GRANT_EXPIRED"),
    ],
)
def test_signed_authority_constraints_are_enforced(
    harness: Harness, updates: dict, reason: str
) -> None:
    harness.assert_denial(reason, token=changed_grant(harness, **updates))


@pytest.mark.parametrize("role", ["merchant", "platform", "authority"])
def test_untrusted_keys_cannot_self_authorize(harness: Harness, role: str) -> None:
    other = Keys.generate()
    if role == "merchant":
        quote = sign_response(
            harness.request, 200, sample_checkout(), other.merchant, MERCHANT_KID, NOW
        )
        harness.assert_denial("AUTHENTICATION_FAILED", checkout=quote)
    elif role == "platform":
        request = completion_request(other, NOW, CHECKOUT)
        harness.assert_denial("AUTHENTICATION_FAILED", request=request)
    else:
        original = verify_grant(harness.grant, harness.keys.trust().authority, GRANT_KID)
        token = sign_grant(original, other.authority, GRANT_KID)
        harness.assert_denial("AUTHENTICATION_FAILED", token=token)


@pytest.mark.parametrize(
    "updates",
    [
        {"url": "https://other.example/checkout-sessions/checkout-001/complete"},
        {"url": f"{MERCHANT}/checkout-sessions/different/complete"},
        {"method": "PUT"},
    ],
)
def test_authenticated_target_substitution_is_denied(harness: Harness, updates: dict) -> None:
    request = changed_request(harness, **updates)
    assert (
        verify_request(request, harness.keys.trust().platform, PLATFORM_KID, NOW)
        == sample_complete_request()
    )
    harness.assert_denial("REQUEST_TARGET", request=request)


@pytest.mark.parametrize("profile", [None, "https://other-platform.example/.well-known/ucp"])
def test_missing_or_wrong_authenticated_platform_profile_is_denied(
    harness: Harness, profile: str | None
) -> None:
    request = sign_request(
        "POST",
        harness.request.url,
        sample_complete_request(),
        harness.keys.platform,
        PLATFORM_KID,
        harness.request.header("idempotency-key"),
        NOW,
        ucp_agent=profile,
    )
    assert (
        verify_request(request, harness.keys.trust().platform, PLATFORM_KID, NOW)
        == sample_complete_request()
    )
    harness.assert_denial("PLATFORM_PROFILE", request=request)


def test_response_transport_annotations_are_not_used_as_authority(harness: Harness) -> None:
    annotated = harness.quote.model_copy(
        update={"url": "https://other.example/unrelated", "method": "DELETE"}
    )
    bundle = harness.complete(checkout=annotated)
    assert audit(bundle, harness.keys.trust(), NOW).checkout_id == CHECKOUT
    assert harness.calls == [(CHECKOUT, 1)]
    # The merchant key, signed checkout ID, and authenticated request target are
    # authoritative. Default UCP response method/URL annotations are not signed.


def test_signed_schema_invalid_completion_denied_before_handler(harness: Harness) -> None:
    request = changed_request(harness, body={"payment": {"instruments": "not-an-array"}})
    assert (
        verify_request(request, harness.keys.trust().platform, PLATFORM_KID, NOW)["payment"][
            "instruments"
        ]
        == "not-an-array"
    )
    harness.assert_denial("SCHEMA_INVALID", request=request)


def test_signed_unsupported_checkout_profile_denied(harness: Harness) -> None:
    terms = sample_checkout()
    terms["line_items"][0]["item"]["title"] = "Different fictional item"
    harness.assert_denial("UNSUPPORTED_CHECKOUT", checkout=signed_quote(harness, terms))


def test_signed_wrong_quote_status_denied(harness: Harness) -> None:
    harness.assert_denial(
        "CHECKOUT_STATUS", checkout=signed_quote(harness, sample_checkout(), status=201)
    )


def test_signed_unknown_checkout_denied(harness: Harness) -> None:
    quote = signed_quote(harness, sample_checkout("unknown-checkout"))
    request = completion_request(harness.keys, NOW, "unknown-checkout")
    harness.assert_denial("CHECKOUT_UNKNOWN", checkout=quote, request=request)


def test_stale_signed_quote_is_rejected_against_current_checkout(harness: Harness) -> None:
    with sqlite3.connect(harness.merchant.path) as connection:
        connection.execute(
            "UPDATE checkouts SET body=? WHERE id=?",
            (json.dumps(sample_checkout(amount_minor=15_000)), CHECKOUT),
        )
    assert (
        verify_response(harness.quote, harness.keys.trust().merchant, MERCHANT_KID, NOW)
        == sample_checkout()
    )
    harness.assert_denial("STALE_CHECKOUT")


def test_identical_retry_returns_original_signed_bundle(harness: Harness) -> None:
    first = harness.complete()
    retry = harness.complete()
    assert retry.model_dump_json() == first.model_dump_json()
    assert audit(retry, harness.keys.trust(), NOW).invocation_number == 1
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_idempotency_survives_merchant_restart(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = harness.complete()
    reopened = Merchant(harness.merchant.path, harness.keys, clock=lambda: NOW)
    unexpected_calls: list[bool] = []

    def forbidden(*args: Any) -> None:
        unexpected_calls.append(True)
        raise AssertionError("cached retry must not invoke the handler")

    monkeypatch.setattr(reopened, "_complete_checkout", forbidden)
    retry = reopened.complete(harness.grant, harness.quote, harness.request)
    assert retry.model_dump_json() == first.model_dump_json()
    assert audit(retry, harness.keys.trust(), NOW).invocation_number == 1
    assert unexpected_calls == []
    assert harness.calls == [(CHECKOUT, 1)]
    assert reopened.counts() == (1, 1)


def test_new_idempotency_key_does_not_redeem_spent_grant(harness: Harness) -> None:
    harness.complete()
    with pytest.raises(Denied) as error:
        harness.complete(request=completion_request(harness.keys, NOW, CHECKOUT))
    assert error.value.reason == "GRANT_SPENT"
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_same_idempotency_key_with_changed_raw_payload_conflicts(harness: Harness) -> None:
    harness.complete()
    # A new authenticated but changed body must not return a previous success.
    request = changed_request(
        harness, body={"payment": {"instruments": []}, "example_changed": True}
    )
    with pytest.raises(Denied) as error:
        harness.complete(request=request)
    assert error.value.reason == "IDEMPOTENCY_CONFLICT"
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_equivalent_json_with_same_idempotency_key_still_conflicts(harness: Harness) -> None:
    harness.complete()
    changed = differently_serialized_request(harness)
    assert (
        verify_request(changed, harness.keys.trust().platform, PLATFORM_KID, NOW)
        == sample_complete_request()
    )
    assert changed.body_b64 != harness.request.body_b64
    with pytest.raises(Denied) as error:
        harness.complete(request=changed)
    assert error.value.reason == "IDEMPOTENCY_CONFLICT"
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_concurrent_identical_requests_have_one_handler_call(harness: Harness) -> None:
    barrier = Barrier(8)

    def complete() -> Bundle:
        barrier.wait(timeout=5)
        return harness.complete()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: complete(), range(8)))
    assert len({result.model_dump_json() for result in results}) == 1
    assert all(
        audit(result, harness.keys.trust(), NOW).invocation_number == 1 for result in results
    )
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_concurrent_fresh_keys_still_spend_grant_once(harness: Harness) -> None:
    barrier = Barrier(8)
    requests = [completion_request(harness.keys, NOW, CHECKOUT) for _ in range(8)]

    def complete(request: SignedMessage) -> Bundle | str:
        barrier.wait(timeout=5)
        try:
            return harness.complete(request=request)
        except Denied as error:
            return error.reason

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(complete, requests))
    allowed = [result for result in results if isinstance(result, Bundle)]
    assert len(allowed) == 1
    assert results.count("GRANT_SPENT") == 7
    assert audit(allowed[0], harness.keys.trust(), NOW).invocation_number == 1
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_parallel_purchases_receipts_match_each_own_invocation(harness: Harness) -> None:
    second_id = "checkout-002"
    harness.merchant.seed_checkout(sample_checkout(second_id))
    inputs = [
        (harness.grant, harness.quote, harness.request),
        (
            make_grant(harness.keys, NOW, grant_id="grant-two"),
            harness.merchant.quote(second_id),
            completion_request(harness.keys, NOW, second_id),
        ),
    ]
    barrier = Barrier(2)

    def complete(arguments: tuple) -> Bundle:
        barrier.wait(timeout=5)
        return harness.merchant.complete(*arguments)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(complete, inputs))
    decisions = [audit(result, harness.keys.trust(), NOW) for result in results]
    assert {decision.invocation_number for decision in decisions} == {1, 2}
    with sqlite3.connect(harness.merchant.path) as connection:
        rows = connection.execute(
            "SELECT s.grant_id, s.checkout_id, s.number, e.number "
            "FROM spends AS s JOIN effects AS e ON s.checkout_id=e.checkout_id"
        ).fetchall()
    for decision in decisions:
        assert (
            decision.grant_id,
            decision.checkout_id,
            decision.invocation_number,
            decision.invocation_number,
        ) in rows
        assert (decision.checkout_id, decision.invocation_number) in harness.calls
    assert len(harness.calls) == 2
    assert harness.merchant.counts() == (2, 2)
    with pytest.raises(AuditError):
        audit(
            results[0].model_copy(update={"receipt": results[1].receipt}), harness.keys.trust(), NOW
        )


@pytest.mark.parametrize("role", ["merchant", "platform", "authority", "receipt"])
def test_auditor_requires_each_independently_configured_trust_key(
    harness: Harness, role: str
) -> None:
    bundle = harness.complete()
    wrong = getattr(Keys.generate().trust(), role)
    with pytest.raises(AuditError, match="^purchase evidence rejected$"):
        audit(bundle, replace(harness.keys.trust(), **{role: wrong}), NOW)


@pytest.mark.parametrize(
    "component", ["grant", "checkout", "request", "response", "runtime_record"]
)
def test_auditor_rejects_cross_bound_signed_artifact_substitution(
    harness: Harness, component: str
) -> None:
    bundle = harness.complete()
    if component == "grant":
        value = changed_grant(harness, grant_id="different-valid-grant")
    elif component == "checkout":
        value = signed_quote(harness, sample_checkout(amount_minor=12_000))
    elif component == "request":
        value = completion_request(harness.keys, NOW, CHECKOUT)
    elif component == "response":
        value = signed_quote(harness, sample_checkout("other-checkout", status="completed"))
    else:
        value = create_trace({"policy": POLICY}, harness.keys.receipt, NOW - timedelta(seconds=1))
        verify_trace(value, harness.keys.trust().receipt, NOW, {"policy": POLICY})
    with pytest.raises(AuditError, match="^purchase evidence rejected$"):
        audit(bundle.model_copy(update={component: value}), harness.keys.trust(), NOW)


def test_audit_authenticates_controller_assertion_not_database_state(harness: Harness) -> None:
    bundle = harness.complete()
    payload = verify_decision(bundle.receipt, harness.keys.trust().receipt, RECEIPT_KID)
    payload["invocation_number"] += 1
    receipt = sign_decision(payload, harness.keys.receipt, RECEIPT_KID)
    # A trusted controller can sign a different invocation claim; without
    # independent DB evidence this is an assertion, not proof of execution.
    assert (
        audit(
            bundle.model_copy(update={"receipt": receipt}), harness.keys.trust(), NOW
        ).invocation_number
        == 2
    )
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_receipt_payload_modification_without_resigning_is_rejected(harness: Harness) -> None:
    bundle = harness.complete()
    payload = verify_decision(bundle.receipt, harness.keys.trust().receipt, RECEIPT_KID)
    payload["invocation_number"] += 1
    changed = sign_decision(payload, harness.keys.receipt, RECEIPT_KID)
    original_parts = bundle.receipt.split(".")
    original_parts[1] = changed.split(".")[1]
    with pytest.raises(AuditError):
        audit(
            bundle.model_copy(update={"receipt": ".".join(original_parts)}),
            harness.keys.trust(),
            NOW,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("unknown", "field"),
        ("invocation_number", "1"),
        ("invocation_number", True),
        ("decided_at", str(int(NOW.timestamp()))),
        ("decision", "deny"),
        ("merchant_key_sha256", "0" * 64),
        ("policy_sha256", "0" * 64),
    ],
)
def test_correctly_signed_receipt_unknown_fields_types_and_bindings_rejected(
    harness: Harness, field: str, value: Any
) -> None:
    bundle = harness.complete()
    payload = verify_decision(bundle.receipt, harness.keys.trust().receipt, RECEIPT_KID)
    payload[field] = value
    receipt = sign_decision(payload, harness.keys.receipt, RECEIPT_KID)
    with pytest.raises(AuditError):
        audit(bundle.model_copy(update={"receipt": receipt}), harness.keys.trust(), NOW)


@pytest.mark.parametrize("offset", [-1, 301])
def test_audit_clock_is_external_and_does_not_mutate_execution(
    harness: Harness, offset: int
) -> None:
    bundle = harness.complete()
    with pytest.raises(AuditError):
        audit(bundle, harness.keys.trust(), NOW + timedelta(seconds=offset))
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (1, 1)


def test_generic_pre_handler_exception_is_sanitized(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("internal-secret-do-not-emit")

    monkeypatch.setattr(flow, "_authorize", broken)
    with pytest.raises(Exception) as error:
        harness.complete()
    assert not isinstance(error.value, Denied)
    assert type(error.value).__name__ == "TransactionAborted"
    assert str(error.value) == "TRANSACTION_ABORTED"
    assert error.value.__suppress_context__ is True
    assert harness.calls == []
    assert harness.merchant.counts() == (0, 0)


def test_database_open_error_is_sanitized_before_handler(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> None:
        raise sqlite3.OperationalError("private-path-do-not-emit")

    with monkeypatch.context() as patch:
        patch.setattr(harness.merchant, "_connection", broken)
        with pytest.raises(Exception) as error:
            harness.complete()
    assert not isinstance(error.value, Denied)
    assert type(error.value).__name__ == "TransactionAborted"
    assert str(error.value) == "TRANSACTION_ABORTED"
    assert error.value.__suppress_context__ is True
    assert harness.calls == []
    assert harness.merchant.counts() == (0, 0)


@pytest.mark.parametrize("exception_kind", ["runtime", "late_denied"])
def test_post_handler_signing_failure_rolls_back_without_denial_claim(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, exception_kind: str
) -> None:
    def broken(*args: Any, **kwargs: Any) -> None:
        if exception_kind == "late_denied":
            raise Denied("must-not-be-returned-as-denial-after-handler")
        raise RuntimeError("signing-secret-do-not-emit")

    with monkeypatch.context() as patch:
        patch.setattr(flow, "sign_decision", broken)
        with pytest.raises(Exception) as error:
            harness.complete()
    assert not isinstance(error.value, Denied)
    assert type(error.value).__name__ == "TransactionAborted"
    assert str(error.value) == "TRANSACTION_ABORTED"
    assert error.value.__suppress_context__ is True
    assert harness.calls == [(CHECKOUT, 1)]
    assert harness.merchant.counts() == (0, 0)
    with sqlite3.connect(harness.merchant.path) as connection:
        assert connection.execute("SELECT count(*) FROM retries").fetchone()[0] == 0
        checkout = json.loads(
            connection.execute("SELECT body FROM checkouts WHERE id=?", (CHECKOUT,)).fetchone()[0]
        )
    assert checkout["status"] == "ready_for_complete"
    # Retrying after the injected failure performs a new attempt. Only its local
    # effect commits: two handler entries do NOT mean two committed purchases.
    assert audit(harness.complete(), harness.keys.trust(), NOW).invocation_number == 1
    assert len(harness.calls) == 2
    assert harness.merchant.counts() == (1, 1)


def test_expiry_rechecked_after_sqlite_lock_wait(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempting_lock = Event()
    time_guard = Lock()
    current_time = NOW

    def clock() -> datetime:
        with time_guard:
            return current_time

    class ObservedConnection(sqlite3.Connection):
        def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
            if sql == "BEGIN IMMEDIATE":
                attempting_lock.set()
            return super().execute(sql, parameters)

    monkeypatch.setattr(harness.merchant, "clock", clock)
    monkeypatch.setattr(
        harness.merchant,
        "_connection",
        lambda: sqlite3.connect(harness.merchant.path, timeout=5, factory=ObservedConnection),
    )
    blocker = sqlite3.connect(harness.merchant.path)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(harness.complete)
            try:
                assert attempting_lock.wait(timeout=3)
                with time_guard:
                    current_time = NOW + timedelta(seconds=241)
            finally:
                blocker.rollback()
            with pytest.raises(Denied) as error:
                future.result(timeout=5)
    finally:
        blocker.close()
    assert error.value.reason == "GRANT_EXPIRED"
    assert harness.calls == []
    assert harness.merchant.counts() == (0, 0)


@pytest.mark.parametrize("kind", ["grant", "http_signature"])
def test_pre_handler_final_freshness_recheck(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    calls = 0
    future_time = NOW + timedelta(seconds=240 if kind == "grant" else 300)
    token = harness.grant
    if kind == "http_signature":
        token = changed_grant(harness, expires_at=int(NOW.timestamp()) + 600)

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return NOW if calls == 1 else future_time

    monkeypatch.setattr(harness.merchant, "clock", clock)
    harness.assert_denial(
        "GRANT_EXPIRED" if kind == "grant" else "AUTHENTICATION_FAILED", token=token
    )
