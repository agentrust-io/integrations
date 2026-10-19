"""The examples open a sealed release locally and never request a clear key."""
from dataclasses import replace

import pytest

from wcm import (
    KeyBrokerService,
    SoftwareProvider,
    WeightCustodyManifest,
    generate_transport_keypair,
    manifest_identity,
)
from wcm._seal import SealError

from _mock_attestation import waive_mock_verification
from _sealed_release import start_custody
from closed_model_e2e import build_manifest, sha256


@pytest.fixture
def released():
    serving = sha256(b"serving")
    manifest = WeightCustodyManifest.model_validate(
        waive_mock_verification(build_manifest(sha256(b"weights"), serving, "example"))
    )
    private, public = generate_transport_keypair()
    kbs = KeyBrokerService(
        {manifest.weights_hash: b"example-key"},
        trusted_manifest_identities=[manifest_identity(manifest)],
        require_channel_binding=True,
    )
    evidence = SoftwareProvider().produce(
        kbs.issue_challenge(), serving_image_measurement=serving,
        gpu_measurement="nvidia-rim:golden", transport_public_key=public,
    )
    return manifest, kbs.verify_and_release(manifest, evidence), private


def test_matching_enclave_key_opens_a_sealed_only_release(released):
    manifest, decision, private = released
    assert decision.released and decision.key is None and decision.sealed_key is not None
    session = start_custody(manifest, decision, private)
    assert session.use_key() == b"example-key"
    assert decision.key is None  # the wire decision was not mutated


def test_another_transport_key_cannot_start_custody(released):
    manifest, decision, _ = released
    other_private, _ = generate_transport_keypair()
    with pytest.raises(SealError):
        start_custody(manifest, decision, other_private)


@pytest.mark.parametrize("change", [
    {"released": False},
    {"sealed_key": None},
    {"key": b"unexpected-clear-key"},
])
def test_non_sealed_only_decisions_are_refused(released, change):
    manifest, decision, private = released
    with pytest.raises(ValueError, match="sealed-only"):
        start_custody(manifest, replace(decision, **change), private)
