"""Regression test for KBS manifest pinning: a release must require a pin.

A ``KeyBrokerService`` that isn't given ``trusted_manifest_identities`` never
releases a key, no matter how valid the attestation evidence is - a caller
could otherwise present an attacker-authored manifest that reuses a weights
hash the broker already holds and be released against terms nobody agreed.
So every KBS a demo or a real release path builds needs that pin, and losing
it silently is the regression this file exists to catch.

``real_lora_custody.py``'s full launch path needs torch, PEFT and a model
download, so the whole script is excluded from ``run_demos.py`` (see
``REQUIRES_NETWORK``), and its own unit tests in ``test_real_lora_custody.py``
only cover the encryption/decryption helpers - not the ``KeyBrokerService`` /
``trusted_manifest_identities`` path. That path is factored out as
``real_lora_custody.build_kbs``, which has no heavy dependency of its own, so
this test imports and calls it directly: if the manifest pin is ever dropped
from that function, these tests fail the same run that broke it, instead of
only failing on the one launch command nothing in CI exercises.

To additionally guard the revocation-isolation invariant (see
``revocation_kill_switch.py``), this file also covers the manifest-pinning
behavior of a plain ``KeyBrokerService`` directly, independent of which demo
constructs it.
"""
from __future__ import annotations

from wcm import CheckResult, KeyBrokerService, ReleaseDecision, manifest_identity

import real_lora_custody
from revocation_kill_switch import LIVE_KEY_ID, NOW, _release, build_manifest, sha256

WEIGHTS_HASH = sha256(b"the model weights")
SERVING = sha256(b"measured serving stack")
KEY = b"the-weight-decryption-key"


def _manifest():
    return build_manifest(WEIGHTS_HASH, SERVING)


def _check(decision: ReleaseDecision, name: str) -> CheckResult:
    """The single check named ``name``, asserting it actually ran.

    A release decision is a list of named checks; looking one up by name and
    requiring exactly one match is what makes an assertion about it
    meaningful. Both ``"x" not in failure_names`` and
    ``all(c.passed for c in checks if c.name == "x")`` pass vacuously if a
    check by that name never ran at all - renamed, removed, or never added -
    which is exactly the kind of regression a security test like this one
    needs to catch rather than silently pass through.
    """
    matches = [c for c in decision.checks if c.name == name]
    assert len(matches) == 1, (
        f"expected exactly one {name!r} check to run, found {len(matches)}: "
        f"{[c.name for c in decision.checks]}"
    )
    return matches[0]


# -- real_lora_custody.build_kbs: the production KBS construction ----------
#
# This test calls the production helper directly, not a KBS rebuilt here. If
# the trusted_manifest_identities pin is ever dropped from build_kbs, this
# test fails: build_kbs would return an unpinned broker, and the release it
# attempts would be refused on manifest_authorized instead of succeeding.


def test_lora_kbs_with_pinned_manifest_is_released() -> None:
    manifest = _manifest()
    kbs = real_lora_custody.build_kbs(manifest, KEY)
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is True
    assert _check(decision, "manifest_authorized").passed is True


# -- KeyBrokerService manifest-pinning behavior, independent of any demo ----


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
    assert _check(decision, "manifest_authorized").passed is True


def test_unpinned_manifest_is_refused_on_manifest_authorized() -> None:
    """Without the pin, release is refused on manifest_authorized specifically.

    A KBS built without ``trusted_manifest_identities`` never releases,
    regardless of how valid the attestation evidence is.
    """
    manifest = _manifest()
    kbs = KeyBrokerService({WEIGHTS_HASH: KEY}, now=lambda: NOW)
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is False
    assert _check(decision, "manifest_authorized").passed is False


def test_revocation_is_isolated_when_manifest_is_pinned() -> None:
    """Pinned + revoked key -> refused on attestation_revocation alone.

    Checks are independent, not short-circuited, so a release can be
    correctly refused "for a reason" even when the manifest pin itself is
    broken. Isolating revocation requires manifest_authorized to have
    positively PASSED - not merely that no failure with that name was seen,
    which would also be true if the check never ran at all.
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
    assert _check(decision, "attestation_revocation").passed is False
    assert _check(decision, "manifest_authorized").passed is True


def test_revocation_without_pin_also_fails_manifest_authorized() -> None:
    """Dropping the pin on a revoked KBS fails both checks, not just one.

    A KBS built without the pin that also has a revoked attestation key
    still produces an ``attestation_revocation`` failure (checks run
    independently), which is exactly why a test that only checks for that
    one failure name cannot tell a correctly isolated revocation apart from
    a broken manifest pin. Both checks must fail here.
    """
    manifest = _manifest()
    kbs = KeyBrokerService(
        {WEIGHTS_HASH: KEY},
        now=lambda: NOW,
        revoked_attestation_keys={LIVE_KEY_ID},
    )
    decision = _release(kbs, manifest, SERVING)
    assert decision.released is False
    assert _check(decision, "attestation_revocation").passed is False
    assert _check(decision, "manifest_authorized").passed is False
