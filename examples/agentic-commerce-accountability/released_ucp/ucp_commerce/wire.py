"""Offline UCP 2026-08-25 REST signatures, not a network/key-discovery client.

RFC 9421 signature construction and ES256 verification belong to the released
http-message-signatures library. This layer checks RFC 9530 raw-body digests and
the components the application actually needs. It deliberately supports one
externally configured P-256 key, one signature, JSON object bodies, and HTTPS.
The required five-minute validity window is LOCAL POLICY, not a UCP requirement.

A standard UCP response authenticates status and body, NOT its enclosing method
or URL. Consumers must independently bind its checkout/order identifiers to the
expected request. Neither a signature nor this clock check redeems an entitlement
or supplies durable idempotency; that belongs to the business boundary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Self
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
    http_sfv,
)
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from http_message_signatures.structures import CaseInsensitiveDict
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, model_validator

MAX_BODY_BYTES = 65_536
MAX_SIGNATURE_AGE = timedelta(minutes=5)
_MAX_ENCODED_BODY = 4 * ((MAX_BODY_BYTES + 2) // 3)
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HEADERS = frozenset(
    {
        "content-type",
        "content-digest",
        "idempotency-key",
        "ucp-agent",
        "signature-input",
        "signature",
    }
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9._~-]{1,128}\Z")
_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])


class WireError(ValueError):
    """A bounded wire-profile failure; contains no underlying payload/key data."""


def _check_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        not url.isascii()
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
        or "\\" in url
        or re.search(r"[^A-Za-z0-9:/?\[\]@!$&'()*+,;=%._~-]", url)
        or re.search(r"%(?![A-Fa-f0-9]{2})", url)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "#" in url
        or not parsed.path.startswith("/")
        or parsed.port == 0
    ):
        raise ValueError("unsupported HTTPS target")


class SignedMessage(BaseModel):
    """Immutable transport snapshot; the snapshot itself is not a signed envelope.

    Headers are immutable name/value pairs, serialized as JSON arrays. Use
    ``header_map()`` for a detached dictionary. No unknown headers are permitted
    by this small profile; in particular it does not implement WBA discovery.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    method: str = Field(min_length=1, max_length=8)
    url: str = Field(min_length=1, max_length=2048)
    status: int | None
    headers: tuple[tuple[str, str], ...] = Field(min_length=1, max_length=8)
    body_b64: str = Field(min_length=1, max_length=_MAX_ENCODED_BODY)

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.method not in _METHODS:
            raise ValueError("unsupported HTTP method")
        _check_url(self.url)
        if self.status is not None and not 200 <= self.status <= 599:
            raise ValueError("unsupported HTTP status")
        names: set[str] = set()
        for name, value in self.headers:
            if name not in _HEADERS or name in names:
                raise ValueError("unknown, duplicate, or non-lowercase header")
            if not 1 <= len(value) <= 4096 or not value.isascii():
                raise ValueError("invalid header value")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError("invalid header value")
            names.add(name)
        try:
            decoded = base64.b64decode(self.body_b64, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("invalid body encoding") from None
        if len(decoded) > MAX_BODY_BYTES or base64.b64encode(decoded).decode() != self.body_b64:
            raise ValueError("invalid body size or encoding")
        return self

    def header(self, name: str) -> str | None:
        return dict(self.headers).get(name.lower())

    def header_map(self) -> dict[str, str]:
        return dict(self.headers)


def _snapshot(message: SignedMessage) -> SignedMessage:
    # model_copy/model_construct bypass Pydantic validation. Trust no such object
    # merely because its Python type is SignedMessage.
    if not isinstance(message, SignedMessage):
        raise WireError("invalid message")
    return SignedMessage.model_validate(message.model_dump(warnings=False))


def raw_body(message: SignedMessage) -> bytes:
    """Return bounded raw bytes, without implying signature authentication."""
    try:
        return base64.b64decode(_snapshot(message).body_b64, validate=True)
    except (ValueError, TypeError):
        raise WireError("invalid message") from None


def _timestamp(now: datetime) -> float:
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise WireError("timezone-aware evaluation time required")
    return now.timestamp()


def _check_kid(kid: str) -> None:
    if not isinstance(kid, str) or _IDENTIFIER.fullmatch(kid) is None:
        raise WireError("invalid configured key identifier")


def _check_public_key(key: ec.EllipticCurvePublicKey) -> None:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise WireError("configured key must be P-256")


def public_key_digest(key: ec.EllipticCurvePublicKey) -> str:
    """SHA-256 of DER SubjectPublicKeyInfo, not a JWK thumbprint."""
    _check_public_key(key)
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


class _PinnedKey(HTTPSignatureKeyResolver):
    def __init__(
        self,
        kid: str,
        public: ec.EllipticCurvePublicKey,
        private: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        _check_kid(kid)
        _check_public_key(public)
        self.kid, self.public, self.private = kid, public, private

    def resolve_public_key(self, key_id: str) -> ec.EllipticCurvePublicKey:
        if key_id != self.kid:
            raise WireError("untrusted signing key")
        return self.public

    def resolve_private_key(self, key_id: str) -> ec.EllipticCurvePrivateKey:
        if key_id != self.kid or self.private is None:
            raise WireError("signing key unavailable")
        return self.private


class _AtTimeVerifier(HTTPMessageVerifier):
    """Override only the library's time-policy hook, not signature verification."""

    def __init__(self, *, key_resolver: _PinnedKey, now: datetime) -> None:
        super().__init__(
            signature_algorithm=algorithms.ECDSA_P256_SHA256, key_resolver=key_resolver
        )
        self.evaluation_time = _timestamp(now)

    def validate_created_and_expires(self, sig_input: Any, max_age: Any = None) -> None:
        params = sig_input.params
        # UCP derives the algorithm from the key; its wire form omits `alg`.
        # This local profile does not claim WBA/multiple-signature support.
        if set(params) != {"created", "expires", "keyid"}:
            raise WireError("unsupported signature parameters")
        created, expires = params["created"], params["expires"]
        if type(created) is not int or type(expires) is not int:
            raise WireError("invalid signature validity bounds")
        if not (
            0 <= created <= self.evaluation_time < expires
            and 0 < expires - created <= MAX_SIGNATURE_AGE.total_seconds()
        ):
            raise WireError("signature outside validity window")


def _digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _transport(message: SignedMessage) -> SimpleNamespace:
    transport = SimpleNamespace(
        url=message.url, method=message.method, headers=CaseInsensitiveDict(message.header_map())
    )
    if message.status is not None:
        transport.status_code = message.status
        transport.request = SimpleNamespace(method=message.method)
    return transport


def _required_components(message: SignedMessage) -> tuple[str, ...]:
    if message.status is not None:
        return ("@status", "content-digest", "content-type")
    components = ["@method", "@authority", "@path"]
    if "?" in message.url:
        components.append("@query")
    if message.header("ucp-agent") is not None:
        components.append("ucp-agent")
    if message.header("idempotency-key") is not None:
        components.append("idempotency-key")
    return (*components, "content-digest", "content-type")


def _check_profile_header(value: str) -> None:
    profile = http_sfv.Dictionary()
    profile.parse(value.encode("ascii"))
    if set(profile) != {"profile"}:
        raise WireError("unsupported UCP-Agent profile declaration")
    item = profile["profile"]
    if type(item.value) is not str or item.params:
        raise WireError("invalid UCP-Agent profile declaration")
    _check_url(item.value)


def _sign(
    method: str,
    url: str,
    status: int | None,
    body: dict[str, JsonValue],
    private_key: ec.EllipticCurvePrivateKey,
    kid: str,
    headers: dict[str, str],
    now: datetime,
) -> SignedMessage:
    _timestamp(now)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise WireError("configured signing key must be P-256")
    resolver = _PinnedKey(kid, private_key.public_key(), private_key)
    # Deliberately no checkout-schema validation here: the consumer enforces its
    # released schema, and tests must be able to sign schema-invalid JSON too.
    data = _JSON_OBJECT.validate_python(body, strict=True)
    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    headers.update({"content-type": "application/json", "content-digest": _digest(encoded)})
    message = SignedMessage(
        method=method,
        url=url,
        status=status,
        body_b64=base64.b64encode(encoded).decode(),
        headers=tuple(headers.items()),
    )
    transport = _transport(message)
    HTTPMessageSigner(signature_algorithm=algorithms.ECDSA_P256_SHA256, key_resolver=resolver).sign(
        transport,
        key_id=kid,
        created=now,
        expires=now + MAX_SIGNATURE_AGE,
        include_alg=False,
        covered_component_ids=_required_components(message),
    )
    return SignedMessage(
        **message.model_dump(exclude={"headers"}),
        headers=tuple((name.lower(), value) for name, value in transport.headers.items()),
    )


def sign_request(
    method: str,
    url: str,
    body: dict[str, JsonValue],
    private_key: ec.EllipticCurvePrivateKey,
    kid: str,
    idempotency_key: str | None,
    now: datetime,
    *,
    ucp_agent: str | None = None,
) -> SignedMessage:
    """Sign an offline REST request. UCP-Agent, when provided, is a profile URL."""
    headers: dict[str, str] = {}
    if method in _MUTATING_METHODS and idempotency_key is None:
        raise WireError("state-changing REST request requires idempotency key")
    if idempotency_key is not None:
        # Generation/uniqueness/entropy are caller responsibilities. Shape alone
        # cannot establish 128 random bits; the example uses secrets.token_hex.
        if re.fullmatch(r"[A-Za-z0-9_-]{22,128}", idempotency_key) is None:
            raise WireError("invalid idempotency key")
        headers["idempotency-key"] = idempotency_key
    if ucp_agent is not None:
        _check_url(ucp_agent)
        headers["ucp-agent"] = str(http_sfv.Dictionary({"profile": ucp_agent}))
    return _sign(method, url, None, body, private_key, kid, headers, now)


def sign_response(
    request: SignedMessage,
    status: int,
    body: dict[str, JsonValue],
    private_key: ec.EllipticCurvePrivateKey,
    kid: str,
    now: datetime,
) -> SignedMessage:
    """Sign status/body; copying request metadata does NOT authenticate that metadata."""
    request = _snapshot(request)
    if request.status is not None:
        raise WireError("expected request")
    return _sign(request.method, request.url, status, body, private_key, kid, {}, now)


def _no_duplicate_properties(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise WireError("duplicate JSON property")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise WireError("non-JSON numeric constant")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise WireError("non-finite JSON number")
    return result


def _verify(
    message: SignedMessage,
    key: ec.EllipticCurvePublicKey,
    kid: str,
    now: datetime,
    *,
    response: bool,
) -> dict[str, JsonValue]:
    try:
        message = _snapshot(message)
        if (message.status is not None) != response:
            raise WireError("wrong message direction")
        if message.header("content-type") != "application/json":
            raise WireError("unsupported content type")
        profile = message.header("ucp-agent")
        if profile is not None:
            _check_profile_header(profile)
        if not response and message.method in _MUTATING_METHODS:
            idem = message.header("idempotency-key")
            if idem is None or re.fullmatch(r"[A-Za-z0-9_-]{22,128}", idem) is None:
                raise WireError("missing or invalid idempotency key")
        result = _AtTimeVerifier(key_resolver=_PinnedKey(kid, key), now=now).verify(
            _transport(message)
        )
        if len(result) != 1:
            raise WireError("expected one signature")
        required = {'"' + item + '"' for item in _required_components(message)}
        if not required.issubset(result[0].covered_components):
            raise WireError("insufficient signed component coverage")
        body = raw_body(message)
        # The maintained HTTP-signature library DOES NOT validate body digests.
        # Compare raw bytes before parsing JSON; never reserialize for verification.
        if not hmac.compare_digest(message.header("content-digest") or "", _digest(body)):
            raise WireError("body digest mismatch")
        decoded = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_no_duplicate_properties,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        return _JSON_OBJECT.validate_python(decoded, strict=True)
    except (ValueError, TypeError, KeyError, RecursionError, HTTPMessageSignaturesException):
        # Never return parser/crypto exceptions, payloads, or configured key material.
        raise WireError("HTTP message verification failed") from None


def verify_request(
    message: SignedMessage, key: ec.EllipticCurvePublicKey, kid: str, now: datetime
) -> dict[str, JsonValue]:
    """Authenticate covered request values against the configured key, not a supplied key."""
    return _verify(message, key, kid, now, response=False)


def verify_response(
    message: SignedMessage, key: ec.EllipticCurvePublicKey, kid: str, now: datetime
) -> dict[str, JsonValue]:
    """Authenticate status/body only; independently check expected checkout identifiers."""
    return _verify(message, key, kid, now, response=True)
