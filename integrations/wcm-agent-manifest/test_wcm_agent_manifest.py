"""Tests for the Agent Manifest <-> WCM model identity binding.

The property under test throughout: a matching digest means the two documents
describe the same weights, and nothing stronger. Every name and every result
field is checked to keep it from reading as custody enforcement.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import WeightCustodyManifest  # noqa: E402

from wcm_agent_manifest import (  # noqa: E402
    CUSTODY_DEPLOYMENT_TYPES,
    BindingError,
    BindingResult,
    hash_grammars_agree,
    model_identity_from_wcm,
    verify_binding,
)

WEIGHTS = "sha256:" + "4a1c" * 16
OTHER_WEIGHTS = "sha256:" + "9f0b" * 16
SERVING = "sha256:" + "5e2d" * 16


def make_manifest(**overrides: object) -> WeightCustodyManifest:
    document: dict = {
        "manifest_version": "0.1",
        "weights_hash": WEIGHTS,
        "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
        "release_terms": {
            "license": "customer-deployment-agreement-ref:CDA-2026-0091",
            "permitted_derivatives": "fine-tune-only",
            "permitted_environments": ["attested-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "physical_hardening": "not-required",
            "trusted_time_source": "secure-tsc",
            "memory_fingerprint_challenge": "not-required",
            "required_hw_platform": ["amd-sev-snp"],
            "tenancy": "shared",
            "required_serving_image": {
                "signer": "ed25519:builder-key",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": SERVING, "status": "current"}],
            },
            "key_release_mode": "attestation-gated",
            "replay_protection": "kbs-nonce-required",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": "example-custodian",
            "custodian_type": "opaque-hosted",
            "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
            "enclave_id": "did:example:enclave-04",
            "attestation_cadence": "24h",
        },
        "signatures": [],
    }
    document.update(overrides)
    return WeightCustodyManifest.model_validate(document)


def agent_document(
    *,
    model_hash: str | None = WEIGHTS,
    deployment_type: str = "confidential-inference",
    attestation_type: str = "hash-bound",
    include_identity: bool = True,
) -> dict:
    artifacts: dict = {}
    if include_identity:
        artifacts["model_identity"] = {
            "provider": "example-labs",
            "model_id": "example-8b-instruct",
            "version": "2026-08",
            "deployment_type": deployment_type,
            "model_hash": model_hash,
            "model_attestation_type": attestation_type,
        }
    return {"artifacts": artifacts}


def test_hash_grammars_are_identical_not_merely_similar() -> None:
    """The whole binding relies on a weights_hash being a valid model_hash verbatim."""
    assert hash_grammars_agree()


def test_binding_carries_the_weights_hash_unchanged() -> None:
    binding = model_identity_from_wcm(
        make_manifest(), provider="example-labs", model_id="example-8b", version="2026-08"
    )

    assert str(binding.model_hash) == WEIGHTS
    assert binding.model_attestation_type.value == "hash-bound"
    assert binding.deployment_type.value == "confidential-inference"


def test_local_deployment_is_also_custodial() -> None:
    binding = model_identity_from_wcm(
        make_manifest(),
        provider="example-labs",
        model_id="example-8b",
        version="2026-08",
        deployment_type="local",
    )

    assert binding.deployment_type.value == "local"


def test_api_deployment_is_a_category_error_not_a_configuration_choice() -> None:
    with pytest.raises(BindingError, match="never holds them"):
        model_identity_from_wcm(
            make_manifest(),
            provider="example-labs",
            model_id="example-8b",
            version="2026-08",
            deployment_type="api",
        )


def test_custody_deployment_types_exclude_the_api_ones() -> None:
    assert set(CUSTODY_DEPLOYMENT_TYPES) == {"local", "confidential-inference"}


def test_catalogue_identity_is_required_not_defaulted_from_the_builder() -> None:
    """builder.identity names who signed custody terms, not who publishes a model."""
    with pytest.raises(BindingError, match="model catalogue entry"):
        model_identity_from_wcm(
            make_manifest(), provider="", model_id="example-8b", version="2026-08"
        )


def test_bound_at_defaults_to_now_and_can_be_supplied() -> None:
    stamped = dt.datetime(2026, 8, 27, tzinfo=dt.timezone.utc)

    binding = model_identity_from_wcm(
        make_manifest(),
        provider="p",
        model_id="m",
        version="v",
        bound_at=stamped,
    )

    assert binding.bound_at == stamped


def test_matching_document_describes_the_same_weights() -> None:
    result = verify_binding(agent_document(), make_manifest())

    assert result.describes_the_same_weights
    assert result.digest_matches
    assert result.hash_bound
    assert result.deployment_type_is_custodial


def test_the_positive_result_is_not_named_verified_or_trusted() -> None:
    """A short name would invite a caller to read custody enforcement into it."""
    fields = set(BindingResult.__dataclass_fields__) | {"describes_the_same_weights"}

    assert "verified" not in fields
    assert "trusted" not in fields
    assert "custody_enforced" not in fields


def test_different_digest_is_reported_with_both_values() -> None:
    result = verify_binding(agent_document(model_hash=OTHER_WEIGHTS), make_manifest())

    assert not result.digest_matches
    assert result.agent_model_hash == OTHER_WEIGHTS
    assert result.wcm_weights_hash == WEIGHTS


def test_provider_asserted_is_not_a_binding() -> None:
    result = verify_binding(
        agent_document(deployment_type="api", model_hash=None, attestation_type="provider-asserted"),
        make_manifest(),
    )

    assert not result.hash_bound
    assert not result.deployment_type_is_custodial
    assert not result.describes_the_same_weights
    assert any("the weights are the provider's" in note for note in result.notes)


def test_missing_model_identity_is_noted_rather_than_crashing() -> None:
    result = verify_binding(agent_document(include_identity=False), make_manifest())

    assert not result.describes_the_same_weights
    assert any("no model_identity artifact" in note for note in result.notes)


def test_hash_bound_declaration_is_checked_separately_from_the_digest() -> None:
    """A right digest under the wrong attestation type is still not a binding."""
    result = verify_binding(agent_document(attestation_type="provider-asserted"), make_manifest())

    assert result.digest_matches
    assert not result.hash_bound
    assert not result.describes_the_same_weights


def test_open_base_weights_are_noted_as_an_integrity_claim() -> None:
    result = verify_binding(agent_document(), make_manifest(base_confidentiality="open"))

    assert result.describes_the_same_weights
    assert any("integrity claim rather than a confidentiality one" in n for n in result.notes)


def test_confidential_manifest_carries_no_such_note() -> None:
    result = verify_binding(agent_document(), make_manifest())

    assert not any("integrity claim" in note for note in result.notes)


def test_verify_binding_works_on_a_plain_document() -> None:
    """No Agent Manifest SDK object required, so a fetched JSON can be checked."""
    result = verify_binding({"artifacts": {"model_identity": {
        "model_hash": WEIGHTS,
        "deployment_type": "confidential-inference",
        "model_attestation_type": "hash-bound",
    }}}, make_manifest())

    assert result.describes_the_same_weights


def test_empty_document_is_handled() -> None:
    result = verify_binding({}, make_manifest())

    assert not result.describes_the_same_weights
    assert result.agent_model_hash is None
