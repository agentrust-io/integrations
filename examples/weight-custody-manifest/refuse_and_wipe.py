"""The 30-second demo: the key refuses to release, and wipe-on-lapse zeroizes it.

Two moments, real WCM code with a software (mock) attestation provider (no
hardware):

  1. REFUSE - the KBS will not release the weight-decryption key into an enclave
     running an unapproved serving stack. A silently modified fork gets nothing,
     so the weights it holds stay encrypted.
  2. WIPE   - once released, the key lives only for the attestation cadence. Miss
     the re-attestation and the enclave zeroizes it. The key is gone, not
     suspended, which bounds worst-case exposure to a single cadence window even
     if every revocation signal is blocked.

    pip install weight-custody-manifest
    python refuse_and_wipe.py
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


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def banner(text: str) -> None:
    print(f"\n{'=' * 64}\n{text}\n{'=' * 64}")


def build_manifest(weights_hash: str, serving: str, org: str) -> dict:
    return {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": org, "signing_key": "ed25519:demo"},
        "release_terms": {
            "license": "Frontier-Model-License",
            "permitted_derivatives": "fine-tune-only",
            "derivatives": "fine-tune-only",
            "permitted_environments": ["enterprise-governed-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:golden"},
            "required_serving_image": {
                "signer": "ed25519:demo",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": org,
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"reference-kbs-image"), "signer": "ed25519:demo"},
            "enclave_id": "did:example:enclave-01",
            "attestation_cadence": "1h",
        },
        "base_confidentiality": "gated-open",
        "deployment_model": "builder-to-customer",
    }


def main() -> None:
    org = "frontier-labs"
    builder, custodian = generate_ed25519(), generate_ed25519()

    weights_hash = sha256(b"<the certified model weights>")
    approved = sha256(b"vllm-0.6.3 + policy-bundle-v2 (the builder-signed serving stack)")

    doc = build_manifest(weights_hash, approved, org)
    manifest = WeightCustodyManifest.model_validate(waive_mock_verification(doc))
    manifest = manifest.with_signatures([
        Ed25519Signer(builder).sign(manifest.unsigned_dict(), role="builder", signer=org),
        Ed25519Signer(custodian).sign(manifest.unsigned_dict(), role="custodian", signer=org),
    ])

    kbs = KeyBrokerService(
        {weights_hash: b"the-weight-decryption-key"},
        # weight-custody-manifest 0.27.0 refuses to release unless the manifest's
        # identity is pinned out of band. Without it, a caller could present an
        # attacker-authored policy that reused a weights hash the broker already
        # held and be released against terms nobody agreed.
        trusted_manifest_identities=[manifest_identity(manifest)],
    )

    # -- Moment 1: REFUSE ------------------------------------------------------
    banner("1. A tampered enclave asks for the key. It gets nothing.")
    tampered = sha256(b"vllm-0.6.3 + a BACKDOORED policy bundle")
    challenge = kbs.issue_challenge()
    bad_evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=tampered,  # not what the builder signed
        gpu_measurement="nvidia-rim:golden",
    )
    decision = kbs.verify_and_release(manifest, bad_evidence)
    print("serving stack     : UNAPPROVED (a modified fork)")
    print("key released      :", decision.released)
    print("why               :", next(c.detail for c in decision.failures))
    print("-> the weights it holds stay encrypted. The fork cannot decrypt them.")

    # -- The approved enclave gets the key -------------------------------------
    banner("2. The approved enclave attests. The key releases.")
    challenge = kbs.issue_challenge()
    good_evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=approved,
        gpu_measurement="nvidia-rim:golden",
    )
    decision = kbs.verify_and_release(manifest, good_evidence)
    print("serving stack     : builder-signed and attested")
    print("key released      :", decision.released)

    # -- Moment 2: WIPE-ON-LAPSE -----------------------------------------------
    banner("3. Miss the re-attestation. The enclave zeroizes the key.")
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    session = EnclaveSession.from_release(manifest, decision, now=lambda: t0)
    print("cadence           :", doc["custody"]["attestation_cadence"],
          " time_floor:", session.time_floor.value)
    session.use_key(now=t0)
    print("served a request  : key present")
    later = t0 + timedelta(hours=1, minutes=1)  # past the 1h window, no re-attest
    try:
        session.use_key(now=later)
        print("served a request  : key present")  # not reached
    except KeyWipedError:
        print("re-attest missed  : key ZEROIZED")
        print("state             :", session.state.value, "(gone, not suspended)")
    print("-> worst-case exposure is one cadence window, even if revocation is blocked.")

    banner("Refuse. Release only on proof. Wipe on lapse.")


if __name__ == "__main__":
    main()
