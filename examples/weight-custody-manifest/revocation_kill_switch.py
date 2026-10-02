"""The kill switch: revocation blocks new releases, wipe-on-lapse stops the current one.

    python revocation_kill_switch.py

Real WCM code, no hardware. A recall (a safety issue, a license breach, a
compromised key) has to actually stop a model that is already serving. WCM does
that from two sides at once:

  - the KBS refuses any NEW release once the attestation key / manifest is
    revoked (checked live per release);
  - the enclave already holding a key zeroizes it at the next cadence lapse
    unless it re-attests, and re-attestation now fails because of the revocation.

So the worst case is one cadence window, even against a host that swallows every
push notification.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from wcm import (
    Ed25519Signer,
    EnclaveSession,
    generate_ed25519,
    KeyBrokerService,
    KeyWipedError,
    manifest_identity,
    SoftwareProvider,
    WeightCustodyManifest,
)

from _mock_attestation import waive_mock_verification

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
LIVE_KEY_ID = "vcek:live-0001"


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(weights_hash: str, serving: str):
    doc = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": "lab", "signing_key": "ed25519:lab"},
        "release_terms": {
            "license": "deployment-agreement",
            "permitted_derivatives": "none",
            "permitted_environments": ["attested-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp"],
            "required_serving_image": {
                "signer": "ed25519:lab",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
            # Revocation is checked live on every release.
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": "customer",
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"kbs image"), "signer": "ed25519:lab"},
            "enclave_id": "did:example:enclave",
            "attestation_cadence": "30m",
        },
    }
    b, c = generate_ed25519(), generate_ed25519()
    m = WeightCustodyManifest.model_validate(waive_mock_verification(doc))
    return m.with_signatures([
        Ed25519Signer(b).sign(m.unsigned_dict(), role="builder", signer="lab"),
        Ed25519Signer(c).sign(m.unsigned_dict(), role="custodian", signer="customer"),
    ])


def _release(kbs, manifest, serving):
    ch = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        ch, serving_image_measurement=serving, gpu_measurement="nvidia-rim:golden",
        attestation_key_id=LIVE_KEY_ID,
    )
    return kbs.verify_and_release(manifest, ev)


def main() -> int:
    serving = sha256(b"measured serving stack")
    weights_hash = sha256(b"the model weights")
    manifest = build_manifest(weights_hash, serving)
    key = b"the-weight-decryption-key"

    rule("Step 1 - The model is attested, released, and serving")
    kbs = KeyBrokerService(
        {weights_hash: key},
        now=lambda: NOW,
        # weight-custody-manifest 0.27.0 refuses to release unless the manifest's
        # identity is pinned out of band. Without it, a caller could present an
        # attacker-authored policy that reused a weights hash the broker already
        # held and be released against terms nobody agreed.
        trusted_manifest_identities=[manifest_identity(manifest)],
    )
    decision = _release(kbs, manifest, serving)
    print("released              :", decision.released)
    session = EnclaveSession.from_release(manifest, decision, now=lambda: NOW)
    session.use_key(now=NOW)
    print("serving under a", "30m", "cadence")

    rule("Step 2 - A recall revokes the attestation key. New releases are refused.")
    # The revocation authority marks the key revoked; the KBS enforces it live.
    revoked_kbs = KeyBrokerService(
        {weights_hash: key}, now=lambda: NOW, revoked_attestation_keys={LIVE_KEY_ID}
    )
    denied = _release(revoked_kbs, manifest, serving)
    print("new release after recall:", denied.released, " (refused)")
    reason = next((c.detail for c in denied.failures if c.name == "attestation_revocation"), None)
    print("why                     :", reason)

    rule("Step 3 - The enclave already serving zeroizes at the next cadence lapse")
    later = NOW + timedelta(minutes=31)  # past the 30m window, and re-attestation now fails
    try:
        session.use_key(now=later)
        print("still serving         : True   (should not happen)")
    except KeyWipedError:
        print("cadence lapsed        : key ZEROIZED (re-attestation would be refused anyway)")
        print("state                 :", session.state.value)

    print()
    print("Two sides of one kill switch: revocation stops the next release, wipe-on-lapse")
    print("stops the running one. Anchoring the revocation in the transparency log")
    print("(see transparency_log.py) makes it non-repudiable.")
    return 0 if (decision.released and not denied.released and session.is_wiped) else 1


if __name__ == "__main__":
    raise SystemExit(main())
