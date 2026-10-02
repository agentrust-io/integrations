"""Demo 8: Derivative lineage - the fine-tune is the real IP.

Usage:
    python demo-08-derivative-lineage/run.py   # from repo root
    python run.py                               # from the demo-08 directory

When a customer fine-tunes a model inside the enclave on its own private data,
the result is novel IP that never existed publicly. WCM gives that derivative its
own signed manifest with a `derived_from` pointer and a `rights_holder` split, so
its whole chain of custody resolves back to the base, and the base's rules travel
down the chain. Software (mock) attestation, no hardware.
"""
from __future__ import annotations

import hashlib
import sys

from wcm import (
    Ed25519Signer,
    WeightCustodyManifest,
    generate_ed25519,
    is_root,
    verify_lineage,
)

sys.stdout.reconfigure(line_buffering=True)


def rule(title: str) -> None:
    print(f"\n{'-' * 66}\n{title}\n{'-' * 66}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(
    *,
    weights_hash: str,
    org: str,
    derivatives: str,
    derived_from: str | None = None,
    rights_holder: dict | None = None,
) -> dict:
    m: dict = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": org, "signing_key": "ed25519:demo"},
        "release_terms": {
            "license": "Frontier-Model-License",
            "permitted_derivatives": "fine-tune-only",
            "derivatives": derivatives,
            "permitted_environments": ["enterprise-governed-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:demo-golden"},
            "required_serving_image": {
                "signer": "ed25519:demo",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": sha256(b"serving"), "status": "current"}],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": org,
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"reference-kbs-image"), "signer": "ed25519:demo"},
            "enclave_id": "did:example:enterprise-enclave-01",
            "attestation_cadence": "1h",
        },
        "base_confidentiality": "gated-open",
        "deployment_model": "builder-to-customer",
    }
    if derived_from is not None:
        m["derived_from"] = derived_from
    if rights_holder is not None:
        m["rights_holder"] = rights_holder
    return m


def sign_manifest(doc: dict, keys: list) -> WeightCustodyManifest:
    m = WeightCustodyManifest.model_validate(doc)
    return m.with_signatures([
        Ed25519Signer(k).sign(m.unsigned_dict(), role=r, signer=s) for k, r, s in keys
    ])


def main() -> None:
    print("Derivative lineage: the fine-tune is the asset. Prove where it came from.")
    print("Real WCM code with a software (mock) attestation provider, no hardware.")

    builder, custodian = generate_ed25519(), generate_ed25519()
    keys = [(builder, "builder", "acme-governance"), (custodian, "custodian", "acme-governance")]

    rule("1. The base model, signed")
    base = sign_manifest(
        build_manifest(weights_hash=sha256(b"<public base checkpoint>"), org="acme-governance",
                       derivatives="fine-tune-only"),
        keys,
    )
    print("base weights_hash  :", base.weights_hash)
    print("permits            : fine-tune-only (derivatives allowed, one level)")

    rule("2. Fine-tune on private data: the derivative gets its own manifest")
    deriv = sign_manifest(
        build_manifest(
            weights_hash=sha256(b"<base>+<acme proprietary fine-tune on private data>"),
            org="acme-governance", derivatives="none",
            derived_from=base.weights_hash,
            rights_holder={"base": "meta", "derivative": "acme"},
        ),
        keys,
    )
    print("derivative hash    :", deriv.weights_hash)
    print("derived_from       :", deriv.derived_from)
    print("rights_holder      :", {"base": deriv.rights_holder.base, "derivative": deriv.rights_holder.derivative})
    print("permits            : none (acme does not permit derivatives OF its derivative)")

    rule("3. Lineage resolves the derivative back to the base")
    manifests = {base.weights_hash: base, deriv.weights_hash: deriv}
    lineage = verify_lineage(manifests, deriv.weights_hash)
    print("lineage ok         :", lineage.ok)
    print("chain (leaf->root) :", " -> ".join(h.split(":")[1][:12] + "..." for h in lineage.chain))
    print("depth              :", lineage.depth, " base is a root:", is_root(base))
    print("-> this fine-tune never existed publicly. The chain is its custody record.")

    rule("4. The base's rules travel down the chain")
    # Someone tries to fork the derivative, but the derivative permits no derivatives.
    rogue = sign_manifest(
        build_manifest(weights_hash=sha256(b"<a fork of acme's derivative>"), org="rogue",
                       derivatives="none", derived_from=deriv.weights_hash),
        keys,
    )
    manifests[rogue.weights_hash] = rogue
    bad = verify_lineage(manifests, rogue.weights_hash)
    print("fork of derivative : lineage ok =", bad.ok)
    print("violation          :", bad.violations[0] if bad.violations else "(none)")
    print("-> monotone rights: a child may narrow the parent's terms, never widen them.")


if __name__ == "__main__":
    main()
