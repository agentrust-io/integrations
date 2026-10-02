"""A local merchant boundary and an independently rerunnable evidence auditor.

The only business effect is an SQLite row, not a payment. Authorization, the
simulated effect, and the cached signed result commit in one transaction. This
does NOT implement exactly-once execution across an external payment system.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from collections.abc import Callable
from contextlib import closing
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import BaseModel, ConfigDict, Field

from .evidence import (
    AuthorityGrant,
    EvidenceError,
    create_trace,
    sign_decision,
    sign_grant,
    verify_decision,
    verify_grant,
    verify_trace,
)
from .schema import (
    UCP_VERSION,
    SchemaValidationError,
    sample_checkout,
    sample_complete_request,
    validate_checkout,
    validate_complete_request,
)
from .wire import (
    SignedMessage,
    WireError,
    public_key_digest,
    raw_body,
    sign_request,
    sign_response,
    verify_request,
    verify_response,
)

MERCHANT = "https://merchant.example"
MERCHANT_KID = "example-merchant"
PLATFORM_KID = "example-platform"
PLATFORM_PROFILE = "https://platform.example/.well-known/ucp"
GRANT_KID = "example-user-authority"
RECEIPT_KID = "example-controller-receipt"
POLICY = {
    "id": "urn:example:ucp-one-purchase:v1",
    "ucp_version": UCP_VERSION,
    "merchant_origin": MERCHANT,
    "platform_profile": PLATFORM_PROFILE,
    "operation": "checkout.complete",
    "currency": "USD",
    "checkout_profile": "one-fictional-reservation-v1",
    "payment_profile": "empty-instruments-no-payment",
    "grant_redemption": "one-local-purchase-per-grant-id",
    "http_signature_max_age_seconds": 300,
    "idempotency": "client-and-target-scoped-raw-body-sha256",
    "idempotency_retention": "database-lifetime-no-automatic-pruning",
}


def digest(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def body_digest(message: SignedMessage) -> str:
    return hashlib.sha256(raw_body(message)).hexdigest()


def utc_now() -> datetime:
    return datetime.now(UTC)


class Denied(ValueError):
    """Stable refusal reason; never carries submitted payloads or raw exceptions."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class AuditError(ValueError):
    pass


class TransactionAborted(RuntimeError):
    """A local transaction failed; this is not an authorization denial.

    The handler may have been entered. Its SQL effects do not commit on error.
    This guarantee would not apply to external I/O performed by another handler.
    """

    reason = "TRANSACTION_ABORTED"

    def __init__(self) -> None:
        super().__init__(self.reason)


class Decision(BaseModel):
    """Example-local receipt, not a new normative UCP/TRACE schema."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    profile: Literal["example-ucp-decision-v1"]
    decision: Literal["allow"]
    decided_at: int = Field(gt=0)
    invocation_number: int = Field(gt=0)
    grant_id: str
    checkout_id: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    grant_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkout_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    merchant_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Bundle(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    grant: str = Field(max_length=8192)
    checkout: SignedMessage
    request: SignedMessage
    response: SignedMessage
    runtime_record: dict[str, Any]
    receipt: str = Field(max_length=32768)


@dataclass(frozen=True)
class Trust:
    """Public keys supplied independently, never adopted from an evidence bundle."""

    merchant: ec.EllipticCurvePublicKey
    platform: ec.EllipticCurvePublicKey
    authority: ed25519.Ed25519PublicKey
    receipt: ed25519.Ed25519PublicKey


@dataclass(frozen=True)
class Keys:
    merchant: ec.EllipticCurvePrivateKey
    platform: ec.EllipticCurvePrivateKey
    authority: ed25519.Ed25519PrivateKey
    receipt: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> Keys:
        return cls(
            ec.generate_private_key(ec.SECP256R1()),
            ec.generate_private_key(ec.SECP256R1()),
            ed25519.Ed25519PrivateKey.generate(),
            ed25519.Ed25519PrivateKey.generate(),
        )

    def trust(self) -> Trust:
        return Trust(
            self.merchant.public_key(),
            self.platform.public_key(),
            self.authority.public_key(),
            self.receipt.public_key(),
        )


def _checkout_profile(checkout: dict[str, Any], status: str) -> tuple[str, int]:
    """Schema validity does not imply this example supports every UCP extension."""
    validate_checkout(checkout)
    identifier = checkout.get("id")
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", identifier):
        raise Denied("UNSUPPORTED_CHECKOUT")
    totals = [total for total in checkout["totals"] if total["type"] == "total"]
    if len(totals) != 1 or type(totals[0]["amount"]) is not int:
        raise Denied("UNSUPPORTED_CHECKOUT")
    amount = totals[0]["amount"]
    # Explicitly small supported profile: do not silently drop signed extensions,
    # alternate totals, currency, fulfillment constraints or payment instruments.
    if amount < 0 or checkout != sample_checkout(identifier, amount, status):
        raise Denied("UNSUPPORTED_CHECKOUT")
    return identifier, amount


def _authorize(
    token: str,
    checkout_message: SignedMessage,
    request: SignedMessage,
    trust: Trust,
    now: datetime,
    *,
    check_request_profile: bool = True,
) -> tuple[AuthorityGrant, dict[str, Any], str, int]:
    """Non-mutating authentication and spending-policy evaluation."""
    try:
        grant = verify_grant(token, trust.authority, GRANT_KID)
        checkout = verify_response(checkout_message, trust.merchant, MERCHANT_KID, now)
        request_body = verify_request(request, trust.platform, PLATFORM_KID, now)
        if request.header("ucp-agent") != f'profile="{PLATFORM_PROFILE}"':
            raise Denied("PLATFORM_PROFILE")
        if check_request_profile:
            validate_complete_request(request_body)
            if request_body != sample_complete_request():
                raise Denied("UNSUPPORTED_PAYMENT_PROFILE")
        checkout_id, amount = _checkout_profile(checkout, "ready_for_complete")
        if checkout_message.status != 200:
            raise Denied("CHECKOUT_STATUS")
        # Response URL/method are transport annotations, NOT authenticated UCP
        # response components. Never use them as merchant/checkout authority.
        target = f"{MERCHANT}/checkout-sessions/{checkout_id}/complete"
        if request.method != "POST" or request.url != target:
            raise Denied("REQUEST_TARGET")
        if grant.merchant_origin != MERCHANT or (
            grant.merchant_key_sha256 != public_key_digest(trust.merchant)
        ):
            raise Denied("MERCHANT_AUTHORITY")
        if grant.platform_key_sha256 != public_key_digest(trust.platform):
            raise Denied("PLATFORM_AUTHORITY")
        if grant.currency != "USD":
            raise Denied("CURRENCY")
        if now.timestamp() >= grant.expires_at:
            raise Denied("GRANT_EXPIRED")
        if amount > grant.max_amount_minor:
            raise Denied("OVERSPEND")
        return grant, checkout, checkout_id, amount
    except (EvidenceError, WireError):
        raise Denied("AUTHENTICATION_FAILED") from None
    except SchemaValidationError:
        raise Denied("SCHEMA_INVALID") from None


def _decision(
    bundle: Bundle,
    trust: Trust,
    grant: AuthorityGrant,
    checkout_id: str,
    decided_at: int,
    invocation_number: int,
) -> Decision:
    return Decision(
        profile="example-ucp-decision-v1",
        decision="allow",
        decided_at=decided_at,
        invocation_number=invocation_number,
        grant_id=grant.grant_id,
        checkout_id=checkout_id,
        policy_sha256=digest(POLICY),
        grant_sha256=digest(grant.model_dump()),
        checkout_body_sha256=body_digest(bundle.checkout),
        request_sha256=digest(bundle.request.model_dump(mode="json")),
        request_body_sha256=body_digest(bundle.request),
        response_sha256=digest(bundle.response.model_dump(mode="json")),
        runtime_record_sha256=digest(bundle.runtime_record),
        merchant_key_sha256=public_key_digest(trust.merchant),
        platform_key_sha256=public_key_digest(trust.platform),
    )


def audit(bundle: Bundle, trust: Trust, now: datetime) -> Decision:
    """Read-only audit, separate from execution. Never spends or trusts embedded keys.

    Re-evaluation authenticates recorded statements under configured example keys;
    it is not independent proof of physical execution, payment, or settlement.
    """
    try:
        bundle = Bundle.model_validate_json(bundle.model_dump_json())
        decision = Decision.model_validate(
            verify_decision(bundle.receipt, trust.receipt, RECEIPT_KID)
        )
        # Verify freshness at the caller's current time, not a timestamp chosen by
        # the record. This online-age policy is not a historical archive verifier.
        if not 0 <= now.timestamp() - decision.decided_at <= 300:
            raise ValueError("receipt outside local freshness window")
        at_decision = datetime.fromtimestamp(decision.decided_at, UTC)
        grant, checkout, checkout_id, amount = _authorize(
            bundle.grant,
            bundle.checkout,
            bundle.request,
            trust,
            at_decision,
        )
        completed = verify_response(bundle.response, trust.merchant, MERCHANT_KID, at_decision)
        if bundle.response.status != 200:
            raise ValueError("completion not successful")
        final_id, final_amount = _checkout_profile(completed, "completed")
        if final_id != checkout_id or final_amount != amount:
            raise ValueError("completion differs from approved checkout")
        expected_completed = deepcopy(checkout)
        expected_completed["status"] = "completed"
        expected_completed["order"] = sample_checkout(checkout_id, amount, "completed")["order"]
        if completed != expected_completed:
            raise ValueError("completed checkout changed purchase terms")
        verify_trace(bundle.runtime_record, trust.receipt, at_decision, {"policy": POLICY})
        expected = _decision(
            bundle,
            trust,
            grant,
            checkout_id,
            decision.decided_at,
            decision.invocation_number,
        )
        if decision != expected:
            raise ValueError("decision does not bind supplied evidence")
        return decision
    except Exception:
        raise AuditError("purchase evidence rejected") from None


class Merchant:
    """One SQLite-backed simulated merchant. Every completion enters this boundary."""

    def __init__(self, path: Path, keys: Keys, clock: Callable[[], datetime] = utc_now):
        self.path, self.clock = path, clock
        # The harness constructs all roles in one process, not isolated services.
        # The merchant retains only its own signing keys, not the user/platform keys.
        self._merchant_key, self._receipt_key = keys.merchant, keys.receipt
        self.trust = keys.trust()
        with closing(self._connection()) as connection, connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS checkouts (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS spends (
                    number INTEGER PRIMARY KEY AUTOINCREMENT,
                    grant_id TEXT NOT NULL UNIQUE, checkout_id TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS effects (
                    number INTEGER PRIMARY KEY, checkout_id TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS retries (
                    client TEXT NOT NULL, target TEXT NOT NULL, token TEXT NOT NULL,
                    body_digest TEXT NOT NULL, result TEXT NOT NULL,
                    PRIMARY KEY(client, target, token)
                );
            """)

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def seed_checkout(self, checkout: dict[str, Any]) -> None:
        """Fixture setup, not an untrusted network route. No replacement on conflict."""
        identifier, _ = _checkout_profile(checkout, "ready_for_complete")
        with closing(self._connection()) as connection, connection:
            connection.execute(
                "INSERT INTO checkouts VALUES (?, ?)", (identifier, json.dumps(checkout))
            )

    def quote(self, identifier: str) -> SignedMessage:
        with closing(self._connection()) as connection:
            row = connection.execute(
                "SELECT body FROM checkouts WHERE id=?", (identifier,)
            ).fetchone()
        if row is None:
            raise Denied("CHECKOUT_UNKNOWN")
        now = self.clock()
        request = sign_request(
            "GET",
            f"{MERCHANT}/checkout-sessions/{identifier}",
            {},
            self._merchant_key,
            MERCHANT_KID,
            None,
            now,
        )
        # This internal GET supplies response transport annotations only. The
        # completion POST below is the actual authenticated platform request.
        return sign_response(
            request, 200, json.loads(row[0]), self._merchant_key, MERCHANT_KID, now
        )

    def counts(self) -> tuple[int, int]:
        with closing(self._connection()) as connection:
            return (
                connection.execute("SELECT count(*) FROM spends").fetchone()[0],
                connection.execute("SELECT count(*) FROM effects").fetchone()[0],
            )

    def _complete_checkout(
        self,
        connection: sqlite3.Connection,
        checkout: dict[str, Any],
        invocation: int,
    ) -> dict[str, Any]:
        """The entire simulated business effect. NEVER performs external I/O."""
        identifier, amount = _checkout_profile(checkout, "ready_for_complete")
        completed = sample_checkout(identifier, amount, "completed")
        connection.execute("INSERT INTO effects VALUES (?, ?)", (invocation, identifier))
        connection.execute(
            "UPDATE checkouts SET body=? WHERE id=?", (json.dumps(completed), identifier)
        )
        return completed

    def complete(self, token: str, checkout: SignedMessage, request: SignedMessage) -> Bundle:
        # INV-1: the only exposed completion path verifies authority before the
        # private handler. Tests assert both DB counters and actual handler calls.
        connection = None
        handler_started = False
        try:
            connection = self._connection()
            connection.execute("BEGIN IMMEDIATE")
            # INV-2: lock waits cannot leave us authorizing with a pre-lock clock.
            now = self.clock()
            grant, terms, identifier, _ = _authorize(
                token, checkout, request, self.trust, now, check_request_profile=False
            )
            client = public_key_digest(self.trust.platform)
            retry_key = request.header("idempotency-key")
            cached = connection.execute(
                "SELECT body_digest, result FROM retries WHERE client=? AND target=? AND token=?",
                (client, request.url, retry_key),
            ).fetchone()
            # INV-3: RFC 9530 RAW body matching, not semantic JSON equivalence.
            # Identical scoped retries return the original signed result.
            if cached is not None:
                if cached[0] != body_digest(request):
                    raise Denied("IDEMPOTENCY_CONFLICT")
                result = Bundle.model_validate_json(cached[1])
                connection.rollback()
                return result
            # Authenticate before examining a cached response, but compare raw
            # retry bodies before interpreting a changed body's payment profile.
            # For a new operation, validate its released schema and local profile.
            _authorize(token, checkout, request, self.trust, now)
            if connection.execute(
                "SELECT 1 FROM spends WHERE grant_id=?", (grant.grant_id,)
            ).fetchone():
                raise Denied("GRANT_SPENT")
            current = connection.execute(
                "SELECT body FROM checkouts WHERE id=?", (identifier,)
            ).fetchone()
            if current is None:
                raise Denied("CHECKOUT_UNKNOWN")
            # INV-4: approval of an old, correctly signed checkout is not approval
            # of the merchant's current state. Compare under the same write lock.
            if digest(json.loads(current[0])) != digest(terms):
                raise Denied("STALE_CHECKOUT")
            # Recheck ALL time-bound inputs immediately before the spend/effect,
            # not just the grant. A slow preflight must not extend HTTP freshness.
            now = self.clock()
            _authorize(token, checkout, request, self.trust, now)
            cursor = connection.execute(
                "INSERT INTO spends(grant_id, checkout_id) VALUES (?, ?)",
                (grant.grant_id, identifier),
            )
            invocation = int(cursor.lastrowid or 0)
            handler_started = True
            completed = self._complete_checkout(connection, terms, invocation)
            response = sign_response(request, 200, completed, self._merchant_key, MERCHANT_KID, now)
            record = create_trace({"policy": POLICY}, self._receipt_key, now)
            draft = Bundle(
                grant=token,
                checkout=checkout,
                request=request,
                response=response,
                runtime_record=record,
                receipt="",
            )
            decision = _decision(
                draft, self.trust, grant, identifier, int(now.timestamp()), invocation
            )
            result = draft.model_copy(
                update={
                    "receipt": sign_decision(decision.model_dump(), self._receipt_key, RECEIPT_KID),
                }
            )
            audit(result, self.trust, now)
            connection.execute(
                "INSERT INTO retries VALUES (?, ?, ?, ?, ?)",
                (
                    client,
                    request.url,
                    retry_key,
                    body_digest(request),
                    result.model_dump_json(),
                ),
            )
            # INV-5: spend, local effect and cached receipt commit together. On a
            # signing/audit/storage error ALL local rows roll back. This is only
            # possible because there is no external merchant/payment side effect.
            connection.commit()
            return result
        except Denied:
            if connection is not None:
                connection.rollback()
            if handler_started:
                raise TransactionAborted() from None
            raise
        except Exception:
            if connection is not None:
                connection.rollback()
            raise TransactionAborted() from None
        finally:
            if connection is not None:
                connection.close()


def make_grant(
    keys: Keys, now: datetime, *, grant_id: str | None = None, limit: int = 20000
) -> str:
    grant = AuthorityGrant(
        grant_id=grant_id or secrets.token_hex(16),
        merchant_origin=MERCHANT,
        merchant_key_sha256=public_key_digest(keys.merchant.public_key()),
        platform_key_sha256=public_key_digest(keys.platform.public_key()),
        currency="USD",
        max_amount_minor=limit,
        operation="checkout.complete",
        expires_at=int(now.timestamp()) + 240,
    )
    return sign_grant(grant, keys.authority, GRANT_KID)


def completion_request(
    keys: Keys, now: datetime, identifier: str, token: str | None = None
) -> SignedMessage:
    return sign_request(
        "POST",
        f"{MERCHANT}/checkout-sessions/{identifier}/complete",
        sample_complete_request(),
        keys.platform,
        PLATFORM_KID,
        token or secrets.token_hex(16),
        now,
        ucp_agent=PLATFORM_PROFILE,
    )
