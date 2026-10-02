"""Real released-library signing/verification, without crypto test doubles."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import rfc8785
from agentrust_trace import jwk_thumbprint, key_to_jwk, sign_record, validate_json, verify_record
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from joserfc import jws
from joserfc.jwk import OKPKey
from pydantic import ValidationError

from ucp_commerce.evidence import (
    DECISION_TYPE,
    GRANT_ALGORITHM,
    GRANT_TYPE,
    MAX_SAFE_INTEGER,
    MAX_UNIX_TIME,
    AuthorityGrant,
    EvidenceError,
    create_trace,
    sign_decision,
    sign_grant,
    verify_decision,
    verify_grant,
    verify_trace,
)


@pytest.fixture
def grant() -> AuthorityGrant:
    return AuthorityGrant(
        grant_id="grant-01",
        merchant_origin="http://127.0.0.1:8123",
        merchant_key_sha256="a" * 64,
        platform_key_sha256="b" * 64,
        currency="USD",
        max_amount_minor=20_000,
        operation="checkout.complete",
        expires_at=1_800_000_000,
    )


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def signed_bytes(payload: bytes, key: Ed25519PrivateKey, **headers: str) -> str:
    protected = {"alg": GRANT_ALGORITHM, "kid": "authority-1", "typ": GRANT_TYPE}
    protected.update(headers)
    return jws.serialize_compact(
        protected, payload, OKPKey.import_key(key), algorithms=[GRANT_ALGORITHM]
    )


def test_grant_round_trip_is_canonical_and_protected(grant, signing_key):
    token = sign_grant(grant, signing_key, "authority-1")
    public_key = signing_key.public_key()
    assert verify_grant(token, public_key, "authority-1") == grant
    decoded = jws.deserialize_compact(
        token, OKPKey.import_key(public_key), algorithms=[GRANT_ALGORITHM]
    )
    assert decoded.protected == {
        "alg": GRANT_ALGORITHM,
        "kid": "authority-1",
        "typ": GRANT_TYPE,
    }
    assert decoded.payload == rfc8785.dumps(grant.model_dump())


def test_grant_requires_configured_key(grant, signing_key):
    token = sign_grant(grant, signing_key, "authority-1")
    other_key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(token, other_key, "authority-1")


@pytest.mark.parametrize("header,value", [("kid", "other"), ("typ", "other"), ("cty", "json")])
def test_grant_refuses_wrong_or_additional_protected_header(grant, signing_key, header, value):
    token = signed_bytes(rfc8785.dumps(grant.model_dump()), signing_key, **{header: value})
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(token, signing_key.public_key(), "authority-1")


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_amount_minor", "20000"),
        ("max_amount_minor", True),
        ("max_amount_minor", 0.5),
        ("max_amount_minor", 0),
        ("max_amount_minor", -1),
        ("expires_at", "1800000000"),
        ("expires_at", True),
        ("expires_at", 0.5),
        ("expires_at", 0),
        ("expires_at", MAX_UNIX_TIME + 1),
        ("merchant_key_sha256", "a" * 63),
        ("merchant_key_sha256", "A" * 64),
        ("platform_key_sha256", "not-a-digest"),
        ("operation", "checkout.cancel"),
        ("currency", "usd"),
        ("grant_id", ""),
        ("merchant_origin", "https://merchant.example/path"),
        ("merchant_origin", "https://user@merchant.example"),
        ("merchant_origin", "https://merchant.example?redirect=other"),
        ("merchant_origin", "https://merchant.example#fragment"),
        ("merchant_origin", "https://merchant.example:99999"),
        ("merchant_origin", "https://merchant.example\n"),
        ("merchant_origin", "file://merchant.example"),
    ],
)
def test_correctly_signed_invalid_claim_is_refused(grant, signing_key, field, value):
    payload = grant.model_dump()
    payload[field] = value
    token = signed_bytes(rfc8785.dumps(payload), signing_key)
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(token, signing_key.public_key(), "authority-1")


def test_amount_must_fit_canonical_integer_domain(grant):
    payload = grant.model_dump()
    payload["max_amount_minor"] = MAX_SAFE_INTEGER + 1
    with pytest.raises(ValidationError):
        AuthorityGrant.model_validate(payload)


@pytest.mark.parametrize("mutation", ["unknown", "missing", "duplicate", "not_canonical", "array"])
def test_grant_rejects_ambiguous_or_open_schema_payloads(grant, signing_key, mutation):
    payload = grant.model_dump()
    if mutation == "unknown":
        payload["extra"] = "not a grant field"
        raw = rfc8785.dumps(payload)
    elif mutation == "missing":
        del payload["expires_at"]
        raw = rfc8785.dumps(payload)
    elif mutation == "duplicate":
        raw = b'{"grant_id":"earlier",' + rfc8785.dumps(payload)[1:]
    elif mutation == "array":
        raw = rfc8785.dumps([payload])
    else:
        raw = json.dumps(payload, indent=2).encode()
    token = signed_bytes(raw, signing_key)
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(token, signing_key.public_key(), "authority-1")


def test_grant_payload_substitution_fails_signature(grant, signing_key):
    token = sign_grant(grant, signing_key, "authority-1")
    substituted = grant.model_copy(update={"max_amount_minor": 50_000})
    other_token = sign_grant(substituted, signing_key, "authority-1")
    header, _, signature = token.split(".")
    _, changed_payload, _ = other_token.split(".")
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(
            f"{header}.{changed_payload}.{signature}", signing_key.public_key(), "authority-1"
        )


@pytest.mark.parametrize("token", ["", "not-jws", "x" * 8193, 123])
def test_invalid_token_is_a_generic_refusal(signing_key, token):
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(token, signing_key.public_key(), "authority-1")


def test_signing_revalidates_model_copy_bypass(grant, signing_key):
    invalid = grant.model_copy(update={"expires_at": "not-an-integer"})
    with pytest.raises(ValidationError):
        sign_grant(invalid, signing_key, "authority-1")


def test_cryptographic_grant_verification_does_not_decide_expiry(grant, signing_key):
    # Controller/auditor tests own the real clock-and-business authorization gate.
    old_grant = grant.model_copy(update={"expires_at": 1})
    token = sign_grant(old_grant, signing_key, "authority-1")
    assert verify_grant(token, signing_key.public_key(), "authority-1").expires_at == 1


def test_grant_rejects_private_key_as_verification_trust(grant, signing_key):
    token = sign_grant(grant, signing_key, "authority-1")
    with pytest.raises(EvidenceError, match="trusted Ed25519 public key"):
        verify_grant(token, signing_key, "authority-1")


@pytest.mark.parametrize("kid", ["", "k" * 129, 123])
def test_grant_requires_exact_configured_key_identifier(grant, signing_key, kid):
    with pytest.raises(EvidenceError, match="configured grant key identifier"):
        sign_grant(grant, signing_key, kid)


@pytest.fixture
def evaluation_time() -> datetime:
    return datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def transcript() -> dict:
    return {
        "policy": {"currency": "USD", "operation": "checkout.complete"},
        "request": {"operation": "checkout.complete"},
        "response": {"status": "completed"},
    }


def test_trace_uses_released_schema_signature_and_explicit_local_revocation(
    transcript, signing_key, evaluation_time
):
    record = create_trace(transcript, signing_key, evaluation_time)
    validate_json(record)
    result = verify_record(
        record,
        signing_key.public_key(),
        revocation=frozenset(),
        now=int(evaluation_time.timestamp()),
    )
    assert result.revocation.outcome == "verified"
    assert result.revocation.evidence == {"source": "store"}
    verify_trace(record, signing_key.public_key(), evaluation_time, transcript)
    assert record["runtime"]["platform"] == "software-only"
    assert record["appraisal"]["status"] == "none"
    assert record["policy"]["enforcement_mode"] == "enforce"
    assert record["build_provenance"]["slsa_level"] == 0
    assert "transparency" not in record
    assert "tool_transcript" not in record
    assert "references" not in record
    assert "d" not in record["cnf"]["jwk"]


def test_trace_refuses_wrong_external_trust(transcript, signing_key, evaluation_time):
    record = create_trace(transcript, signing_key, evaluation_time)
    other_key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(record, other_key, evaluation_time, transcript)


def test_trace_refuses_modified_policy(transcript, signing_key, evaluation_time):
    record = create_trace(transcript, signing_key, evaluation_time)
    modified = {**transcript, "policy": {"currency": "EUR"}}
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(record, signing_key.public_key(), evaluation_time, modified)


def test_trace_refuses_modified_signed_record(transcript, signing_key, evaluation_time):
    record = create_trace(transcript, signing_key, evaluation_time)
    record["iat"] += 1
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(
            record, signing_key.public_key(), evaluation_time + timedelta(seconds=1), transcript
        )


@pytest.mark.parametrize("offset", [-1, 301])
def test_trace_time_bounds_are_injected(transcript, signing_key, evaluation_time, offset):
    record = create_trace(transcript, signing_key, evaluation_time)
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(
            record,
            signing_key.public_key(),
            evaluation_time + timedelta(seconds=offset),
            transcript,
        )


def test_trace_refuses_revoked_local_key(transcript, signing_key, evaluation_time):
    record = create_trace(transcript, signing_key, evaluation_time)
    revoked = frozenset({jwk_thumbprint(key_to_jwk(signing_key))})
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(
            record,
            signing_key.public_key(),
            evaluation_time,
            transcript,
            revoked_key_ids=revoked,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime", {"platform": "tpm2", "measurement": "sha256:" + "a" * 64}),
        ("appraisal", {"status": "affirming", "verifier": "urn:example:appraiser"}),
        ("origin", {"kind": "log-import", "producer": "other"}),
        ("model", {"provider": "claimed-provider", "model_id": "claimed-model"}),
        ("subject", "did:example:other-controller"),
        ("policy", {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"}),
        ("tool_transcript", {"hash": "sha256:" + "a" * 64}),
        ("build_provenance", {"slsa_level": 3, "digest": "sha256:" + "a" * 64}),
        ("iat", "1788782400"),
        ("iat", True),
        ("unknown", "not in the released schema"),
    ],
)
def test_correctly_signed_trace_must_keep_local_assurance_ceiling(
    transcript, signing_key, evaluation_time, field, value
):
    record = create_trace(transcript, signing_key, evaluation_time)
    record[field] = value
    resigned = sign_record(record, signing_key)
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(resigned, signing_key.public_key(), evaluation_time, transcript)


def test_trace_refuses_naive_evaluation_time(transcript, signing_key, evaluation_time):
    with pytest.raises(EvidenceError, match="aware datetime"):
        create_trace(transcript, signing_key, evaluation_time.replace(tzinfo=None))


def test_trace_signature_is_not_purchase_authorization(transcript, signing_key, evaluation_time):
    # This helper authenticates the controller's observation only. The main
    # controller/auditor must reject missing grants, receipts, and business links.
    arbitrary_observation = {
        "policy": transcript["policy"],
        "claim": "a signature cannot make this purchase authorized",
    }
    record = create_trace(arbitrary_observation, signing_key, evaluation_time)
    verify_trace(record, signing_key.public_key(), evaluation_time, arbitrary_observation)


def test_nonpolicy_http_data_needs_the_outer_decision_binding(
    transcript, signing_key, evaluation_time
):
    record = create_trace(transcript, signing_key, evaluation_time)
    changed_http_data = {**transcript, "response": {"status": "changed"}}
    # TRACE does not pretend UCP HTTP is MCP/A2A. Auditor tests exercise the outer
    # signed decision's business hashes plus runtime_record_sha256 instead.
    verify_trace(record, signing_key.public_key(), evaluation_time, changed_http_data)


def test_decision_jws_authenticates_exact_values_without_coercing_them(signing_key):
    payload = {"decision": "allow", "value": "123", "flag": "false"}
    token = sign_decision(payload, signing_key, "decision-key")
    assert verify_decision(token, signing_key.public_key(), "decision-key") == payload
    # Signature verification returns exact types. The separate Decision model
    # rejects wrong types/unknown claims before the business auditor uses them.


def test_decision_cannot_be_used_as_a_grant(grant, signing_key):
    token = sign_decision(grant.model_dump(), signing_key, "authority-1")
    with pytest.raises(EvidenceError, match="^invalid authority grant$"):
        verify_grant(token, signing_key.public_key(), "authority-1")


def test_grant_cannot_be_used_as_a_decision(grant, signing_key):
    token = sign_grant(grant, signing_key, "authority-1")
    with pytest.raises(EvidenceError, match="^invalid decision receipt$"):
        verify_decision(token, signing_key.public_key(), "authority-1")


def test_decision_requires_external_trust(signing_key):
    token = sign_decision({"decision": "allow"}, signing_key, "decision-key")
    with pytest.raises(EvidenceError, match="^invalid decision receipt$"):
        verify_decision(token, Ed25519PrivateKey.generate().public_key(), "decision-key")


@pytest.mark.parametrize("raw", [b"[]", b'{"x": 1}', b'{"x":1,"x":2}'])
def test_decision_rejects_noncanonical_or_nonobject_payload(signing_key, raw):
    token = signed_bytes(raw, signing_key, typ=DECISION_TYPE)
    with pytest.raises(EvidenceError, match="^invalid decision receipt$"):
        verify_decision(token, signing_key.public_key(), "authority-1")


@pytest.mark.parametrize("token", ["", "x" * 65_537, None])
def test_decision_refuses_malformed_token(signing_key, token):
    with pytest.raises(EvidenceError, match="^invalid decision receipt$"):
        verify_decision(token, signing_key.public_key(), "decision-key")


def test_signers_and_verifiers_require_their_respective_key_types(grant, signing_key):
    with pytest.raises(EvidenceError, match="Ed25519 private key"):
        sign_grant(grant, signing_key.public_key(), "authority-1")
    with pytest.raises(EvidenceError, match="Ed25519 private key"):
        sign_decision({}, signing_key.public_key(), "decision-key")
    with pytest.raises(EvidenceError, match="Ed25519 public key"):
        verify_decision("", signing_key, "decision-key")


@pytest.mark.parametrize("policy", [None, {}, [], "policy"])
def test_trace_requires_nonempty_policy_object(signing_key, evaluation_time, policy):
    with pytest.raises(EvidenceError, match="local application policy"):
        create_trace({"policy": policy}, signing_key, evaluation_time)


def test_trace_refuses_invalid_local_parameters(transcript, signing_key, evaluation_time):
    with pytest.raises(EvidenceError, match="Ed25519 private key"):
        create_trace(transcript, signing_key.public_key(), evaluation_time)
    with pytest.raises(EvidenceError, match="outside the example profile"):
        create_trace(transcript, signing_key, datetime(2020, 1, 1, tzinfo=UTC))
    record = create_trace(transcript, signing_key, evaluation_time)
    with pytest.raises(EvidenceError, match="trusted Ed25519 public key"):
        verify_trace(record, signing_key, evaluation_time, transcript)
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace([], signing_key.public_key(), evaluation_time, transcript)
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(record, signing_key.public_key(), evaluation_time, {})
    with pytest.raises(EvidenceError, match="^invalid TRACE observation record$"):
        verify_trace(
            record,
            signing_key.public_key(),
            evaluation_time,
            transcript,
            revoked_key_ids=frozenset({123}),
        )
