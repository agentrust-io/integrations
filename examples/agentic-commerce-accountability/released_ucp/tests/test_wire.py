"""Offline defensive regressions using real RFC 9421 / ES256 operations."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
    algorithms,
    http_sfv,
)
from pydantic import ValidationError

from ucp_commerce.wire import (
    MAX_BODY_BYTES,
    SignedMessage,
    WireError,
    public_key_digest,
    raw_body,
    sign_request,
    sign_response,
    verify_request,
    verify_response,
)

NOW = datetime(2026, 9, 7, 12, tzinfo=UTC)
URL = "https://merchant.example/checkouts/chk_example/complete"
KID = "platform-example"
IDEMPOTENCY = "f3ef412de1be1e4f7e36e6d6031696cd"
BODY = {"payment": {"instruments": []}}


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def request(key: ec.EllipticCurvePrivateKey, **kwargs: object) -> SignedMessage:
    options = dict(
        method="POST",
        url=URL,
        body=BODY,
        private_key=key,
        kid=KID,
        idempotency_key=IDEMPOTENCY,
        now=NOW,
    )
    options.update(kwargs)
    return sign_request(**options)


def replace_header(message: SignedMessage, name: str, value: str) -> SignedMessage:
    headers = message.header_map()
    headers[name] = value
    return message.model_copy(update={"headers": tuple(headers.items())})


def resign(
    message: SignedMessage,
    key: ec.EllipticCurvePrivateKey,
    *,
    covered: tuple[str, ...] | None = None,
    body: bytes | None = None,
    created: datetime = NOW,
    expires: datetime | None = NOW + timedelta(minutes=5),
    include_alg: bool = False,
) -> SignedMessage:
    """Produce independently configured signatures with the released library.

    This is test construction, not a mock of the production verifier or signer.
    """

    class Resolver(HTTPSignatureKeyResolver):
        def resolve_private_key(self, key_id: str) -> ec.EllipticCurvePrivateKey:
            assert key_id == KID
            return key

    headers = message.header_map()
    for name in ("signature", "signature-input"):
        headers.pop(name, None)
    payload = raw_body(message) if body is None else body
    headers["content-digest"] = (
        "sha-256=:" + base64.b64encode(hashlib.sha256(payload).digest()).decode() + ":"
    )
    transport = SimpleNamespace(method=message.method, url=message.url, headers=headers)
    if message.status is not None:
        transport.status_code = message.status
        transport.request = SimpleNamespace(method=message.method)
    if covered is None:
        covered = (
            "@method",
            "@authority",
            "@path",
            "content-type",
            "content-digest",
            "idempotency-key",
        )
        if message.status is not None:
            covered = ("@status", "content-type", "content-digest")
    HTTPMessageSigner(
        signature_algorithm=algorithms.ECDSA_P256_SHA256, key_resolver=Resolver()
    ).sign(
        transport,
        key_id=KID,
        created=created,
        expires=expires,
        include_alg=include_alg,
        covered_component_ids=covered,
    )
    return SignedMessage(
        **message.model_dump(exclude={"headers", "body_b64"}),
        headers=tuple((name.lower(), value) for name, value in transport.headers.items()),
        body_b64=base64.b64encode(payload).decode(),
    )


def test_request_round_trip_uses_raw_r_s_and_no_alg(key: ec.EllipticCurvePrivateKey) -> None:
    message = request(key)
    assert verify_request(message, key.public_key(), KID, NOW) == BODY
    assert raw_body(message) == b'{"payment":{"instruments":[]}}'
    assert ";alg=" not in message.header("signature-input")
    signature = http_sfv.Dictionary()
    signature.parse(message.header("signature").encode())
    assert len(signature["pyhms"].value) == 64
    assert SignedMessage.model_validate_json(message.model_dump_json()) == message


def test_response_round_trip_binds_status_and_raw_body(key: ec.EllipticCurvePrivateKey) -> None:
    message = sign_response(
        request(key), 200, {"id": "chk_example", "status": "completed"}, key, KID, NOW
    )
    assert verify_response(message, key.public_key(), KID, NOW)["id"] == "chk_example"
    with pytest.raises(WireError):
        verify_response(message.model_copy(update={"status": 201}), key.public_key(), KID, NOW)
    with pytest.raises(WireError):
        verify_request(message, key.public_key(), KID, NOW)
    with pytest.raises(WireError):
        verify_response(request(key), key.public_key(), KID, NOW)


def test_response_does_not_authenticate_request_metadata(key: ec.EllipticCurvePrivateKey) -> None:
    message = sign_response(request(key), 200, {"id": "chk_example"}, key, KID, NOW)
    moved = message.model_copy(update={"url": "https://other.example/other", "method": "DELETE"})
    # This is deliberately NOT a denial assertion. Default UCP response signatures
    # do not bind URL/method: the business/audit layer must bind checkout IDs.
    assert verify_response(moved, key.public_key(), KID, NOW) == {"id": "chk_example"}


@pytest.mark.parametrize(
    "update",
    [
        {"method": "DELETE"},
        {"url": "https://other.example/checkouts/chk_example/complete"},
        {"url": "https://merchant.example/checkouts/different/complete"},
        {"url": URL + "?currency=GBP"},
    ],
)
def test_request_target_substitutions_are_denied(
    key: ec.EllipticCurvePrivateKey, update: dict
) -> None:
    with pytest.raises(WireError):
        verify_request(request(key).model_copy(update=update), key.public_key(), KID, NOW)


def test_query_and_profile_header_are_covered(key: ec.EllipticCurvePrivateKey) -> None:
    message = request(
        key, url=URL + "?view=full", ucp_agent="https://platform.example/.well-known/ucp"
    )
    assert verify_request(message, key.public_key(), KID, NOW) == BODY
    with pytest.raises(WireError):
        verify_request(
            message.model_copy(update={"url": URL + "?view=brief"}), key.public_key(), KID, NOW
        )
    changed = replace_header(
        message, "ucp-agent", 'profile="https://other.example/.well-known/ucp"'
    )
    with pytest.raises(WireError):
        verify_request(changed, key.public_key(), KID, NOW)


@pytest.mark.parametrize(
    "missing",
    ["@method", "@authority", "@path", "content-type", "content-digest", "idempotency-key"],
)
def test_valid_signature_with_insufficient_request_coverage_is_denied(
    key: ec.EllipticCurvePrivateKey, missing: str
) -> None:
    components = (
        "@method",
        "@authority",
        "@path",
        "content-type",
        "content-digest",
        "idempotency-key",
    )
    message = resign(
        request(key), key, covered=tuple(item for item in components if item != missing)
    )
    with pytest.raises(WireError):
        verify_request(message, key.public_key(), KID, NOW)


@pytest.mark.parametrize("missing", ["@status", "content-type", "content-digest"])
def test_valid_signature_with_insufficient_response_coverage_is_denied(
    key: ec.EllipticCurvePrivateKey, missing: str
) -> None:
    response = sign_response(request(key), 200, {"id": "chk_example"}, key, KID, NOW)
    message = resign(
        response,
        key,
        covered=tuple(
            item for item in ("@status", "content-type", "content-digest") if item != missing
        ),
    )
    with pytest.raises(WireError):
        verify_response(message, key.public_key(), KID, NOW)


@pytest.mark.parametrize(
    "kwargs", [{"url": URL + "?view=full"}, {"ucp_agent": "https://platform.example/profile"}]
)
def test_conditional_query_and_profile_coverage_required(
    key: ec.EllipticCurvePrivateKey, kwargs: dict
) -> None:
    message = resign(request(key, **kwargs), key)
    with pytest.raises(WireError):
        verify_request(message, key.public_key(), KID, NOW)


@pytest.mark.parametrize(
    "profile",
    [
        "profile=unquoted",
        'profile="http://platform.example/profile"',
        'missing="https://platform.example/profile"',
        'profile="https://platform.example/profile";unexpected',
    ],
)
def test_signed_malformed_profile_header_is_denied(
    key: ec.EllipticCurvePrivateKey, profile: str
) -> None:
    message = replace_header(request(key), "ucp-agent", profile)
    signed = resign(
        message,
        key,
        covered=(
            "@method",
            "@authority",
            "@path",
            "content-type",
            "content-digest",
            "idempotency-key",
            "ucp-agent",
        ),
    )
    with pytest.raises(WireError):
        verify_request(signed, key.public_key(), KID, NOW)


def test_digest_checks_raw_bytes_not_equivalent_json(key: ec.EllipticCurvePrivateKey) -> None:
    message = request(key)
    changed = message.model_copy(
        update={"body_b64": base64.b64encode(json.dumps(BODY).encode()).decode()}
    )
    assert json.loads(raw_body(changed)) == BODY
    with pytest.raises(WireError):
        verify_request(changed, key.public_key(), KID, NOW)
    # Freshly signing those same bytes makes them valid; canonical JSON is NOT a
    # wire requirement. Durable JCS records are a separate layer.
    assert (
        verify_request(resign(message, key, body=raw_body(changed)), key.public_key(), KID, NOW)
        == BODY
    )


def test_key_id_does_not_select_an_untrusted_key(key: ec.EllipticCurvePrivateKey) -> None:
    message = request(key)
    with pytest.raises(WireError):
        verify_request(message, ec.generate_private_key(ec.SECP256R1()).public_key(), KID, NOW)
    with pytest.raises(WireError):
        verify_request(message, key.public_key(), "other-trusted-key-id", NOW)
    assert (
        public_key_digest(key.public_key())
        == hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
    )


@pytest.mark.parametrize("delta", [-0.01, 300, 301])
def test_strict_local_freshness_no_wall_clock_dependency(
    key: ec.EllipticCurvePrivateKey, delta: float
) -> None:
    with pytest.raises(WireError):
        verify_request(request(key), key.public_key(), KID, NOW + timedelta(seconds=delta))
    assert (
        verify_request(request(key), key.public_key(), KID, NOW + timedelta(seconds=299.9)) == BODY
    )


@pytest.mark.parametrize(
    "options",
    [
        {"expires": None},
        {"expires": NOW},
        {"expires": NOW + timedelta(seconds=301)},
        {"include_alg": True},
        {"created": NOW + timedelta(seconds=1)},
    ],
)
def test_correctly_signed_invalid_local_time_or_algorithm_parameters_denied(
    key: ec.EllipticCurvePrivateKey, options: dict
) -> None:
    with pytest.raises(WireError):
        verify_request(resign(request(key), key, **options), key.public_key(), KID, NOW)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"nested":1,"nested":2}}',
        b"[]",
        b"null",
        b'{"number":NaN}',
        b'{"number":Infinity}',
        b'{"number":1e999}',
        b"\xff",
        b"{",
    ],
)
def test_authenticated_invalid_or_ambiguous_json_denied(
    key: ec.EllipticCurvePrivateKey, payload: bytes
) -> None:
    with pytest.raises(WireError, match="^HTTP message verification failed$"):
        verify_request(resign(request(key), key, body=payload), key.public_key(), KID, NOW)


@pytest.mark.parametrize(
    "update",
    [
        {"status": "200"},
        {"status": True},
        {"method": "post"},
        {"body_b64": "%%%"},
        {"url": "http://merchant.example/path"},
        {"url": "https://user:secret@merchant.example/path"},
        {"url": "https://merchant.example/path#fragment"},
        {"url": "https://merchant.example"},
        {"url": "https://merchant.example/path%GG"},
        {"url": "https://merchant.example/path\r\n"},
    ],
)
def test_copied_models_revalidated_and_invalid_snapshot_denied(
    key: ec.EllipticCurvePrivateKey, update: dict
) -> None:
    with pytest.raises(WireError):
        verify_request(request(key).model_copy(update=update), key.public_key(), KID, NOW)


def test_headers_deeply_immutable_and_duplicates_unknowns_controls_denied(
    key: ec.EllipticCurvePrivateKey,
) -> None:
    message = request(key)
    with pytest.raises(ValidationError):
        message.method = "DELETE"
    with pytest.raises(TypeError):
        message.headers[0] = ("content-type", "text/plain")
    copied = message.header_map()
    copied["content-type"] = "text/plain"
    assert message.header("content-type") == "application/json"
    for header in (
        ("content-type", "application/json"),
        ("x-unknown", "value"),
        ("UCP-Agent", "value"),
        ("ucp-agent", "value\nsecret"),
    ):
        with pytest.raises(WireError):
            verify_request(
                message.model_copy(update={"headers": (*message.headers, header)}),
                key.public_key(),
                KID,
                NOW,
            )
    data = message.model_dump()
    data["unknown"] = "not permitted"
    with pytest.raises(ValidationError):
        SignedMessage.model_validate(data)


def test_limits_idempotency_content_type_and_naive_clock(key: ec.EllipticCurvePrivateKey) -> None:
    for idem in (None, "short"):
        with pytest.raises(WireError):
            request(key, idempotency_key=idem)
    with pytest.raises(ValueError):
        request(key, body={"oversize": "x" * MAX_BODY_BYTES})
    with pytest.raises(WireError):
        request(key, now=NOW.replace(tzinfo=None))
    message = request(key)
    with pytest.raises(WireError):
        verify_request(message, key.public_key(), KID, NOW.replace(tzinfo=None))
    with pytest.raises(WireError):
        verify_request(
            replace_header(message, "content-type", "text/plain"), key.public_key(), KID, NOW
        )
    headers = tuple((name, value) for name, value in message.headers if name != "idempotency-key")
    with pytest.raises(WireError):
        verify_request(message.model_copy(update={"headers": headers}), key.public_key(), KID, NOW)


def test_wrong_curve_and_key_type_are_rejected(key: ec.EllipticCurvePrivateKey) -> None:
    for other in (ec.generate_private_key(ec.SECP384R1()), ed25519.Ed25519PrivateKey.generate()):
        with pytest.raises(WireError):
            request(other)
        with pytest.raises(WireError):
            verify_request(request(key), other.public_key(), KID, NOW)


def test_no_payload_or_key_material_in_verification_errors(key: ec.EllipticCurvePrivateKey) -> None:
    message = request(key, body={"private": "do-not-disclose"})
    changed = replace_header(message, "signature-input", "do-not-disclose-invalid-header")
    with pytest.raises(WireError) as error:
        verify_request(changed, key.public_key(), KID, NOW)
    assert str(error.value) == "HTTP message verification failed"
    assert error.value.__suppress_context__ is True


def test_get_and_empty_query_profile_and_invalid_json_signing(
    key: ec.EllipticCurvePrivateKey,
) -> None:
    message = request(key, method="GET", idempotency_key=None, url=URL + "?")
    assert verify_request(message, key.public_key(), KID, NOW) == BODY
    with pytest.raises(ValueError):
        request(key, body={"not_json": object()})
    with pytest.raises(ValueError):
        request(key, body={"not_json": float("nan")})
    with pytest.raises(WireError):
        sign_response(sign_response(request(key), 200, {}, key, KID, NOW), 200, {}, key, KID, NOW)
