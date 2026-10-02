"""Provenance interop: WCM custody on top of an OpenSSF model-signing signature.

    pip install "weight-custody-manifest[model-signing]"
    python provenance_model_signing.py

Real WCM code, no hardware. OpenSSF model-signing (Sigstore) answers "who signed
this artifact and does it still match?"; WCM answers "release the key only into an
attested enclave, wipe it on lapse, and carry the lineage." They compose: a WCM
manifest carries a signed `provenance.model_signing` reference, and
`verify_provenance` cryptographically verifies that model-signing signature and
binds it to the manifest. WCM is the custody-and-release layer ON TOP of the
signing layer, not a competitor to it.

This signs a model file with model-signing (using a local EC key, so no Sigstore
account or network is needed), records the model-signing digest in a WCM
manifest, and verifies the whole chain.
"""
from __future__ import annotations

import hashlib
import pathlib
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from model_signing import signing

from wcm import (
    Ed25519Signer,
    WeightCustodyManifest,
    generate_ed25519,
    model_signing_digest,
    verify_provenance,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(weights_hash: str, signed_digest: str) -> WeightCustodyManifest:
    serving = sha256(b"measured serving stack")
    doc = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": "frontier-lab", "signing_key": "ed25519:lab"},
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
                "signer": "ed25519:lab",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
        },
        "custody": {
            "custodian": "customer",
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"kbs image"), "signer": "ed25519:lab"},
            "enclave_id": "did:example:enclave",
            "attestation_cadence": "1h",
        },
        # The provenance reference, under the joint signature.
        "provenance": {
            "model_signing": {
                "method": "openssf-model-signing",
                "signed_digest": signed_digest,
                "transparency": "sigstore-rekor",
                "signer": "release-engineering@frontier-lab",
            }
        },
    }
    b, c = generate_ed25519(), generate_ed25519()
    m = WeightCustodyManifest.model_validate(doc)
    return m.with_signatures([
        Ed25519Signer(b).sign(m.unsigned_dict(), role="builder", signer="frontier-lab"),
        Ed25519Signer(c).sign(m.unsigned_dict(), role="custodian", signer="customer"),
    ])


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        model_path = d / "model.safetensors"
        model_path.write_bytes(b"<the open-weight checkpoint bytes>")
        sig_path = d / "model.sig"
        priv_path = d / "signer.key"
        pub_path = d / "signer.pub"

        rule("Step 1 - Sign the model with OpenSSF model-signing (local EC key)")
        key = ec.generate_private_key(ec.SECP256R1())
        priv_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        pub_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        signing.Config().use_elliptic_key_signer(private_key=priv_path).sign(model_path, sig_path)
        digest = model_signing_digest(model_path)
        print("model-signing signature written:", sig_path.name)
        print("model-signing digest           :", digest[:26], "...")

        rule("Step 2 - Record it in a WCM manifest and verify the whole chain")
        manifest = build_manifest(sha256(model_path.read_bytes()), digest)
        result = verify_provenance(manifest, model_path, sig_path, public_key=pub_path)
        print("provenance verified            :", result.verified,
              "" if result.verified else f"({result.reason})")

        rule("Step 3 - A manifest that claims the wrong digest fails the binding")
        wrong = build_manifest(sha256(model_path.read_bytes()), sha256(b"a different artifact"))
        bad = verify_provenance(wrong, model_path, sig_path, public_key=pub_path)
        print("provenance verified            :", bad.verified, f"({bad.reason})")

        print()
        print("So the WCM manifest cannot claim a model-signing provenance it does not")
        print("actually match: verify_provenance checks the signature AND the digest.")
        return 0 if (result.verified and not bad.verified) else 1


if __name__ == "__main__":
    raise SystemExit(main())
