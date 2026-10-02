"""Demo 7: Closed-weight custody - when secrecy IS the job.

Usage:
    python demo-07-closed-weight/run.py       # from repo root
    python run.py                              # from the demo-07 directory

The counterpart to demo 6. Demo 6 ran an OPEN-weight model, where the base
weights are public so the machinery does integrity, license, and derivative
custody. Here the model is CLOSED (a frontier lab shipping weights into a
customer's or sovereign's own enclave), so the base weights ARE the secret and
the whole job is to keep the decryption key off the operator. Same protocol,
software (mock) attestation, no hardware.
"""
from __future__ import annotations

import hashlib
import sys

from wcm import (
    manifest_identity,
    Ed25519Signer,
    KeyBrokerService,
    SoftwareProvider,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    verify_manifest,
)

sys.stdout.reconfigure(line_buffering=True)


def rule(title: str) -> None:
    print(f"\n{'-' * 66}\n{title}\n{'-' * 66}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(*, weights_hash: str, serving: str, builder_id: str, custodian_id: str) -> dict:
    return {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": builder_id, "signing_key": "ed25519:demo"},
        "release_terms": {
            "license": "Frontier-Model-License (confidential, field-of-use bound)",
            "permitted_derivatives": "none",
            "derivatives": "none",
            "permitted_environments": ["sovereign-governed-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:demo-golden"},
            "required_serving_image": {
                "signer": "ed25519:demo",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": custodian_id,
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"reference-kbs-image"), "signer": "ed25519:demo"},
            "enclave_id": "did:example:sovereign-enclave-01",
            "attestation_cadence": "1h",
        },
        "base_confidentiality": "confidential",
        "deployment_model": "builder-to-customer",
    }


def sign(manifest: WeightCustodyManifest, keypair, role: str, signer: str) -> dict:
    return Ed25519Signer(keypair).sign(manifest.unsigned_dict(), role=role, signer=signer)


def _evidence(kbs: KeyBrokerService, serving: str):
    challenge = kbs.issue_challenge()
    return SoftwareProvider().produce(
        challenge, serving_image_measurement=serving, gpu_measurement="nvidia-rim:demo-golden"
    )


def main() -> None:
    print("Closed-weight custody: the weights are the secret. Keep the key off the operator.")
    print("Real WCM code with a software (mock) attestation provider, no hardware.")

    builder = generate_ed25519()     # the frontier lab
    custodian = generate_ed25519()   # the deploying customer / sovereign

    weights_hash = sha256(b"<the confidential frontier model weights>")
    serving = sha256(b"trusted-serving-stack + no-raw-weight-export-path")

    rule("1. The lab ships CLOSED weights and signs the release policy")
    doc = build_manifest(
        weights_hash=weights_hash, serving=serving,
        builder_id="frontier-labs", custodian_id="sovereign-customer",
    )
    manifest = WeightCustodyManifest.model_validate(doc)
    manifest = manifest.with_signatures([
        sign(manifest, builder, "builder", "frontier-labs"),
        sign(manifest, custodian, "custodian", "sovereign-customer"),
    ])
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    result = verify_manifest(manifest, ctx)
    print("base_confidentiality:", manifest.base_confidentiality.value, "(the weights are secret)")
    print("manifest signature  :", result.ok, "(jointly signed lab + customer)")

    rule("2. The key releases ONLY into the attested, lab-signed enclave")
    # The KBS pins the exact manifest identity it will release for. Without
    # this the gate refuses, and correctly: a caller-supplied manifest is not
    # its own trust root, so an unpinned one could name any weights it liked.
    kbs = KeyBrokerService(
        {weights_hash: b"the-model-decryption-key"},
        trusted_manifest_identities=[manifest_identity(manifest)],
    )
    released = kbs.verify_and_release(manifest, _evidence(kbs, serving)).released
    print("approved enclave    : key released =", released)
    print("-> the weights decrypt only inside the measured stack, never on the host.")

    rule("3. An unapproved serving stack gets nothing")
    tampered_serving = sha256(b"a modified serving stack with a raw-weight export path")
    denied = kbs.verify_and_release(manifest, _evidence(kbs, tampered_serving))
    print("unapproved enclave  : key released =", denied.released)
    print("why                 :", next(c.detail for c in denied.failures))
    print("-> a stack that could exfiltrate plaintext weights never receives the key.")

    rule("Closed vs open: same protocol, different job")
    print("closed model (here): the base weights ARE the secret; the job is secrecy.")
    print("open model (demo 6): the base is public; the same steps do integrity,")
    print("                     license, and derivative custody instead.")
    print("honest scope       : cost, detection, and mandatory physical hardening")
    print("                     against a hardware owner who can lift keys (TEE.fail),")
    print("                     not silicon-proof custody. That is why the sovereign")
    print("                     profile adds a threshold split (demo 9).")


if __name__ == "__main__":
    main()
