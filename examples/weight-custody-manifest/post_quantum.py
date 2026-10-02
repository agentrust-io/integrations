"""Post-quantum manifest signing: ML-DSA-65 and an Ed25519 + ML-DSA-65 hybrid.

    python post_quantum.py

Real WCM code, no hardware. A weight-custody manifest is a long-lived artifact:
a signature that is safe today must still be safe when a model it governs is
still deployed years out. WCM supports FIPS 204 ML-DSA-65 (post-quantum) and a
hybrid that requires BOTH a classical Ed25519 signature and an ML-DSA-65 one, so
it stays valid unless an attacker breaks both. This signs and verifies a manifest
under each profile.
"""
from __future__ import annotations

import hashlib

from wcm import (
    HybridSigner,
    MlDsa65Signer,
    VerificationContext,
    WeightCustodyManifest,
    generate_hybrid,
    generate_ml_dsa65,
    verify_manifest,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def manifest_doc() -> dict:
    serving = sha256(b"measured serving stack")
    return {
        "manifest_version": "0.1",
        "weights_hash": sha256(b"the model weights"),
        "builder": {"identity": "frontier-lab", "signing_key": "pq:builder"},
        "release_terms": {
            "license": "deployment-agreement",
            "permitted_derivatives": "fine-tune-only",
            "permitted_environments": ["attested-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp"],
            "required_serving_image": {
                "signer": "pq:builder",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
        },
        "custody": {
            "custodian": "customer-platform",
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"kbs image"), "signer": "pq:builder"},
            "enclave_id": "did:example:enclave",
            "attestation_cadence": "1h",
        },
    }


def main() -> int:
    rule("Profile 1 - ML-DSA-65 (FIPS 204, post-quantum)")
    b_key, c_key = generate_ml_dsa65(), generate_ml_dsa65()
    m = WeightCustodyManifest.model_validate(manifest_doc())
    m = m.with_signatures([
        MlDsa65Signer(b_key).sign(m.unsigned_dict(), role="builder", signer="frontier-lab"),
        MlDsa65Signer(c_key).sign(m.unsigned_dict(), role="custodian", signer="customer-platform"),
    ])
    ctx = VerificationContext()
    ctx.add_ml_dsa65_key(b_key.public_bytes)
    ctx.add_ml_dsa65_key(c_key.public_bytes)
    result = verify_manifest(m, ctx)
    print("algorithm         :", ", ".join(sorted({s.algorithm.value for s in m.signatures})))
    print("manifest verifies :", result.ok)

    rule("Profile 2 - Ed25519 + ML-DSA-65 hybrid (valid only if BOTH hold)")
    b_hy, c_hy = generate_hybrid(), generate_hybrid()
    m2 = WeightCustodyManifest.model_validate(manifest_doc())
    m2 = m2.with_signatures([
        HybridSigner(b_hy).sign(m2.unsigned_dict(), role="builder", signer="frontier-lab"),
        HybridSigner(c_hy).sign(m2.unsigned_dict(), role="custodian", signer="customer-platform"),
    ])
    ctx2 = VerificationContext()
    ctx2.add_hybrid_key(b_hy.ed25519.public_bytes, b_hy.ml_dsa65.public_bytes)
    ctx2.add_hybrid_key(c_hy.ed25519.public_bytes, c_hy.ml_dsa65.public_bytes)
    result2 = verify_manifest(m2, ctx2)
    print("algorithm         :", ", ".join(sorted({s.algorithm.value for s in m2.signatures})))
    print("manifest verifies :", result2.ok)

    rule("Why both are offered")
    print("ML-DSA-65 removes the quantum risk to the manifest signature outright.")
    print("The hybrid is the conservative migration path: it keeps the classical")
    print("guarantee AND adds the PQ one, so it stays valid unless an attacker breaks")
    print("both schemes. Same manifest, same verifier, selectable per deployment.")
    return 0 if (result.ok and result2.ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
