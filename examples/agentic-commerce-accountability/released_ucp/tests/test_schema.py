"""Released schema and SDK checks, deliberately independent of authorization."""

import copy
import hashlib
import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from ucp_commerce.schema import (
    SCHEMA_DIRECTORY,
    SchemaValidationError,
    sample_checkout,
    sample_complete_request,
    validate_checkout,
    validate_complete_request,
)


@pytest.mark.parametrize("status", ["ready_for_complete", "completed"])
def test_checkout_passes_released_schema_and_sdk_without_mutation(status: str) -> None:
    checkout = sample_checkout(status=status)
    original = copy.deepcopy(checkout)
    assert validate_checkout(checkout) is None
    assert checkout == original


def test_complete_request_passes_released_schema_and_sdk_without_payment_data() -> None:
    request = sample_complete_request()
    assert request == {"payment": {"instruments": []}}
    assert validate_complete_request(request) is None


@pytest.mark.parametrize(
    "field", ["ucp", "id", "line_items", "status", "currency", "totals", "links"]
)
def test_checkout_rejects_missing_released_required_field(field: str) -> None:
    checkout = sample_checkout()
    del checkout[field]
    with pytest.raises(SchemaValidationError, match="invalid UCP checkout response"):
        validate_checkout(checkout)


def test_completion_requires_payment_not_the_response_shape() -> None:
    with pytest.raises(SchemaValidationError, match="invalid UCP completion request"):
        validate_complete_request({})
    with pytest.raises(SchemaValidationError):
        validate_complete_request(sample_checkout())


@pytest.mark.parametrize("amount", ["12500", True, -1, 1.5])
def test_checkout_rejects_invalid_amount_before_sdk_coercion(amount: Any) -> None:
    checkout = sample_checkout()
    checkout["line_items"][0]["item"]["price"] = amount
    with pytest.raises(SchemaValidationError):
        validate_checkout(checkout)


def test_checkout_requires_exactly_one_total_and_subtotal() -> None:
    checkout = sample_checkout()
    checkout["totals"].append({"type": "total", "amount": 12500})
    with pytest.raises(SchemaValidationError):
        validate_checkout(checkout)
    checkout = sample_checkout()
    checkout["totals"] = [{"type": "total", "amount": 12500}]
    with pytest.raises(SchemaValidationError):
        validate_checkout(checkout)


def test_checkout_rejects_unknown_status_and_invalid_link_uri() -> None:
    checkout = sample_checkout(status="fictional_status")
    with pytest.raises(SchemaValidationError):
        validate_checkout(checkout)
    checkout = sample_checkout()
    checkout["links"][0]["url"] = "not a URI"
    with pytest.raises(SchemaValidationError):
        validate_checkout(checkout)


def test_validation_errors_do_not_echo_payload() -> None:
    request = {"payment": "private-customer-material-not-for-errors"}
    with pytest.raises(SchemaValidationError) as caught:
        validate_complete_request(request)
    assert str(caught.value) == "invalid UCP completion request"
    assert caught.value.__suppress_context__ is True


def test_schema_acceptance_is_not_authorization_or_extension_negotiation() -> None:
    checkout = sample_checkout(amount_minor=99999999)
    checkout["example_unknown_member"] = "ignored by the released open schema"
    assert validate_checkout(checkout) is None


def _references(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(item) for key, item in value.items() if key == "$ref"] + [
            ref for item in value.values() for ref in _references(item)
        ]
    if isinstance(value, list):
        return [ref for item in value for ref in _references(item)]
    return []


def test_vendored_schemas_are_valid_offline_and_match_provenance() -> None:
    provenance = json.loads((SCHEMA_DIRECTORY / "provenance.json").read_text())
    assert provenance["ucp_source"]["commit"] == "cd78fb38e819de77d9b527d110476eccb876f1bd"
    assert provenance["resolver"]["version"] == "1.4.1"
    for filename, expected_hash in provenance["artifact_sha256"].items():
        raw = (SCHEMA_DIRECTORY / filename).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_hash
        if filename.endswith(".json"):
            schema = json.loads(raw)
            Draft202012Validator.check_schema(schema)
            assert all(ref.startswith("#") for ref in _references(schema))
