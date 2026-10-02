"""Demo 9: Sovereign self-custody - no single party holds the key.

Usage:
    python demo-09-sovereign-threshold/run.py  # from repo root
    python run.py                               # from the demo-09 directory

For a sovereign deployment the honest limit from demos 6 to 8 bites hardest: a
hardware owner who can forge one attestation could release a key. The answer is
to never let one release be enough. The model key is split 2-of-3 across
independent parties, each releasing its share only against its own valid
attestation, so a quorum of independent attestations is required and one forged
quote is below threshold. Software (mock) attestation, no hardware.
"""
from __future__ import annotations

import hashlib
import sys

from wcm import (
    manifest_identity,
    Ed25519Signer,
    KeyBrokerService,
    Share,
    SoftwareProvider,
    WeightCustodyManifest,
    combine_shares,
    generate_ed25519,
    split_secret,
)

sys.stdout.reconfigure(line_buffering=True)


def rule(title: str) -> None:
    print(f"\n{'-' * 66}\n{title}\n{'-' * 66}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pack(share: Share) -> bytes:
    """Serialize a share so an independent KBS can hold and release it."""
    return bytes([share.x]) + share.y


def unpack(blob: bytes) -> Share:
    return Share(x=blob[0], y=blob[1:])


SERVING = sha256(b"sovereign-serving-stack")


def build_manifest(weights_hash: str) -> dict:
    return {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": "frontier-labs", "signing_key": "ed25519:demo"},
        "release_terms": {
            "license": "Frontier-Model-License",
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
                "accepted_measurements": [{"measurement": SERVING, "status": "current"}],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "quorum",
        },
        "custody": {
            "custodian": "sovereign-customer",
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"reference-kbs-image"), "signer": "ed25519:demo"},
            "enclave_id": "did:example:sovereign-enclave-01",
            "attestation_cadence": "1h",
        },
        "base_confidentiality": "confidential",
        "deployment_model": "builder-to-customer",
    }


def attested_share(kbs: KeyBrokerService, manifest: WeightCustodyManifest) -> Share:
    """Release one share from an independent shareholder's KBS against attestation."""
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=SERVING, gpu_measurement="nvidia-rim:demo-golden"
    )
    decision = kbs.verify_and_release(manifest, evidence)
    return unpack(decision.key)


def main() -> None:
    print("Sovereign self-custody: split the key so no single release is ever enough.")
    print("Real WCM code with a software (mock) attestation provider, no hardware.")

    builder, custodian = generate_ed25519(), generate_ed25519()
    model_key = b"the-sovereign-model-decryption-k"  # 32 bytes

    rule("1. Split the model key 2-of-3 across independent parties")
    shares = split_secret(model_key, threshold=2, shares=3)
    holders = ["frontier-labs", "sovereign-authority", "sovereign-customer"]
    for name, s in zip(holders, shares):
        print(f"  share {s.x} -> {name}")
    print("policy: any 2 of the 3 reconstruct; no 1 can.")

    rule("2. No single party can reconstruct the key")
    one = combine_shares([shares[0]])
    print("one share reconstructs the key:", one == model_key)
    print("-> a lone shareholder, or a single forged attestation, gets nothing usable.")

    rule("3. Each shareholder releases its share only against attestation")
    doc = build_manifest(sha256(b"<the sovereign model weights>"))
    manifest = WeightCustodyManifest.model_validate(doc)
    manifest = manifest.with_signatures([
        Ed25519Signer(builder).sign(manifest.unsigned_dict(), role="builder", signer="frontier-labs"),
        Ed25519Signer(custodian).sign(manifest.unsigned_dict(), role="custodian", signer="sovereign-customer"),
    ])
    # Each shareholder runs its own KBS holding only its share.
    # The KBS pins the exact manifest identity it will release for. Without
    # this the gate refuses, and correctly: a caller-supplied manifest is not
    # its own trust root, so an unpinned one could name any weights it liked.
    kbs_by_holder = [
        KeyBrokerService(
            {manifest.weights_hash: pack(s)},
            trusted_manifest_identities=[manifest_identity(manifest)],
        )
        for s in shares
    ]
    # A quorum of two independent parties each attest and release their share.
    quorum = [attested_share(kbs_by_holder[0], manifest), attested_share(kbs_by_holder[2], manifest)]
    print("attested releases  :", len(quorum), "of 3 shareholders (a quorum)")

    rule("4. The quorum reconstructs; a single forged root does not")
    recovered = combine_shares(quorum)
    print("quorum reconstructs the key :", recovered == model_key)
    print("-> to forge the key an attacker must forge attestation to a QUORUM of")
    print("   independent sovereign-run roots, not one. That is why threshold is a")
    print("   prerequisite for sovereign self-custody, not optional hardening.")


if __name__ == "__main__":
    main()
