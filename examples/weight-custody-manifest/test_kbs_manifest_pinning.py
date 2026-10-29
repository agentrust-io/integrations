"""Regression test for the KBS manifest-pinning bug fixed in this PR.

``real_lora_custody.py`` needs torch, PEFT and a model download, so it is
excluded from ``run_demos.py`` (see ``REQUIRES_NETWORK``) and its own unit
tests in ``test_real_lora_custody.py`` only cover the encryption/decryption
helpers, not the ``KeyBrokerService`` / ``trusted_manifest_identities`` path.
That means the exact bug this PR fixes - a ``KeyBrokerService`` built without
``trusted_manifest_identities=[manifest_identity(manifest)]`` - could come
back and the normal offline test run (demos + pytest) would still pass.

This test exercises that path directly, using the same manifest-building and
release helpers as ``revocation_kill_switch.py`` (pure, offline, no network
or heavy ML dependencies), so it runs under plain ``pytest`` in CI and would
fail if the pin is ever dropped from a KBS that is supposed to have it.
"""
from __future__ import annotations

from wcm import KeyBrokerService, manifest_identity

from revocation_kill_switch import LIVE_KEY_ID, NOW, _release, build_manifest, sha256

WEIGHTS_HASH = sha256(b"the model weights")
SERVING = sha256(b"measured serving stack")
KEY = b"the-weight-decryption-key"


def _manifest():
    return build_manifest(WEIGHTS_HASH, SERVING)


def test_pinned_manifest_is_released() -> None:
    """A KBS pinned to the manifest's identity releases the key."""
    manifest = _manifest()
    kbs = KeyBrokerService(
        {WEIGHTS_HASH: KEY},
        now=lambda: NOW,
        trusted_manifest_identities=[manifest_identity(manifest)],
    )
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is True
    assert all(c.passed for c in decision.checks if c.name == "manifest_authorized")


def test_unpinned_manifest_is_refused_on_manifest_authorized() -> None:
    """Without the pin, release is refused on manifest_authorized specifically.

    This is the exact bug this PR fixes: a KBS built without
    ``trusted_manifest_identities`` never releases, regardless of how valid
    the attestation evidence is.
    """
    manifest = _manifest()
    kbs = KeyBrokerService({WEIGHTS_HASH: KEY}, now=lambda: NOW)
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is False
    failure_names = {c.name for c in decision.failures}
    assert "manifest_authorized" in failure_names


def test_revocation_is_isolated_when_manifest_is_pinned() -> None:
    """Pinned + revoked key -> refused on attestation_revocation alone.

    Guards the regression the original assertion in
    ``revocation_kill_switch.py`` missed: checks are independent, not
    short-circuited, so a release can be correctly refused "for a reason"
    even when the manifest pin itself is broken. Isolating revocation means
    manifest_authorized must also have PASSED, not merely that some failure
    with the right name exists.
    """
    manifest = _manifest()
    kbs = KeyBrokerService(
        {WEIGHTS_HASH: KEY},
        now=lambda: NOW,
        revoked_attestation_keys={LIVE_KEY_ID},
        trusted_manifest_identities=[manifest_identity(manifest)],
    )
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is False
    failure_names = {c.name for c in decision.failures}
    assert "attestation_revocation" in failure_names
    assert "manifest_authorized" not in failure_names


def test_revocation_without_pin_also_fails_manifest_authorized() -> None:
    """The precise regression: dropping the pin on a revoked KBS.

    Before this PR, a KBS built without the pin that also had a revoked
    attestation key still produced an ``attestation_revocation`` failure
    (checks run independently), which is exactly why a test that only checks
    for that one failure name cannot tell a correctly isolated revocation
    apart from a broken manifest pin. Both failures must be present here.
    """
    manifest = _manifest()
    kbs = KeyBrokerService(
        {WEIGHTS_HASH: KEY},
        now=lambda: NOW,
        revoked_attestation_keys={LIVE_KEY_ID},
    )
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is False
    failure_names = {c.name for c in decision.failures}
    assert "attestation_revocation" in failure_names
    assert "manifest_authorized" in failure_names
