"""End-to-end custody for a CLOSED-weight (frontier) model, where secrecy IS the job.

    python closed_model_e2e.py

Real WCM code with a software (mock) attestation provider, so it runs anywhere
with no hardware.

Closed vs open, the one distinction that drives everything
---------------------------------------------------------
This is the counterpart to `open_model_e2e.py`. For a CLOSED frontier model the
base weights are a secret the builder is deploying into someone else's
infrastructure, so the whole point of attestation-gated release is secrecy: the
decryption key must reach only a builder-approved, measured serving stack, and
nothing else. (For an OPEN-weight model the base is already public, so the same
machinery instead does integrity, license, and derivative custody. See
`open_model_e2e.py`.)

`base_confidentiality` is set to "confidential" and stated on the manifest, so a
verifier can see that this manifest really is protecting secrecy, not theater.
"""
from __future__ import annotations

import hashlib

from wcm import (
    Ed25519Signer,
    EnclaveSession,
    generate_ed25519,
    KeyBrokerService,
    manifest_identity,
    SoftwareProvider,
    VerificationContext,
    verify_manifest,
    WeightCustodyManifest,
)

from _mock_attestation import waive_mock_verification


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(weights_hash: str, serving: str, org: str) -> dict:
    return {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": org, "signing_key": "ed25519:builder"},
        "release_terms": {
            "license": "Frontier-Model-Deployment-Agreement (no redistribution)",
            "permitted_derivatives": "none",
            "derivatives": "none",
            "permitted_environments": ["customer-attested-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:golden"},
            "required_serving_image": {
                "signer": "ed25519:builder",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": "customer-platform-team",
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"builder-signed KBS image"), "signer": "ed25519:builder"},
            "enclave_id": "did:example:customer-enclave-01",
            "attestation_cadence": "30m",
        },
        # The distinction this whole demo turns on: the base weights ARE secret.
        "base_confidentiality": "confidential",
        "deployment_model": "builder-to-customer",
    }


def main() -> int:
    builder, custodian = generate_ed25519(), generate_ed25519()
    weights_hash = sha256(b"<the secret frontier model weights>")
    serving = sha256(b"vllm-0.6.3 + builder policy bundle (the approved serving stack)")

    rule("Step 0 - Certify: the manifest binds the secret weights + serving stack")
    doc = build_manifest(weights_hash, serving, "frontier-lab")
    manifest = WeightCustodyManifest.model_validate(waive_mock_verification(doc))
    manifest = manifest.with_signatures([
        Ed25519Signer(builder).sign(manifest.unsigned_dict(), role="builder", signer="frontier-lab"),
        Ed25519Signer(custodian).sign(manifest.unsigned_dict(), role="custodian", signer="customer-platform-team"),
    ])
    print("base_confidentiality :", manifest.base_confidentiality.value, " (secrecy is the job)")
    print("deployment_model     :", manifest.deployment_model.value)
    print("signed jointly by builder + custodian")

    rule("Step 1 - Verify the manifest (both required roles signed)")
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    result = verify_manifest(manifest, ctx)
    print("manifest valid       :", result.ok)
    for note in result.notes:
        print("  note:", note)
    if not result.ok:
        return 1

    rule("Step 2 - Attestation gate: the decryption key releases only into the approved enclave")
    kbs = KeyBrokerService(
        {weights_hash: b"the-secret-weight-decryption-key"},
        # weight-custody-manifest 0.27.0 refuses to release unless the manifest's
        # identity is pinned out of band. Without it, a caller could present an
        # attacker-authored policy that reused a weights hash the broker already
        # held and be released against terms nobody agreed.
        trusted_manifest_identities=[manifest_identity(manifest)],
    )
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=serving, gpu_measurement="nvidia-rim:golden"
    )
    decision = kbs.verify_and_release(manifest, evidence)
    print("key released         :", decision.released)
    print("the key decrypts the secret weights ONLY under the builder-signed, measured")
    print("serving stack. A different or tampered stack gets nothing (see refuse_and_wipe.py).")

    rule("Step 3 - Wipe-on-lapse custody (bounded exposure of the secret)")
    session = EnclaveSession.from_release(manifest, decision)
    session.use_key()
    print("serving under a", doc["custody"]["attestation_cadence"], "cadence, time_floor =", session.time_floor.value)
    print("miss the re-attestation and the key is zeroized, so worst-case exposure of")
    print("the secret is one cadence window even if a revocation signal is blocked.")

    rule("The honest ceiling for a secret")
    print("secrecy holds against software and remote adversaries. It does NOT hold against")
    print("an operator who physically owns the hardware: TEE.fail / BadRAM extract keys")
    print("from live memory (open question 8.8). Against that party WCM is accountability-")
    print("grade (cost, detection, containment, mandatory physical hardening), not")
    print("cryptographic custody. A frontier builder self-selects its counterparties on")
    print("exactly this line.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
