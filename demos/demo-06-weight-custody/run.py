"""Demo 6: Weight custody - prove the model is the one the builder shipped.

Usage:
    python demo-06-weight-custody/run.py      # from repo root
    python run.py                              # from the demo-06 directory

A pure in-process Weight Custody Manifest flow with a software (mock)
attestation provider, so it runs anywhere with no hardware. It shows the four
things a manifest gives you over a bare checkpoint download: provenance, an
attestation gate, tamper refusal, and derivative lineage. Possession is not
provenance.
"""
from __future__ import annotations

import hashlib
import sys

from wcm import (
    ReleasePolicy,
    manifest_identity,
    EnclaveSession,
    Ed25519Signer,
    KeyBrokerService,
    SoftwareProvider,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    is_root,
    verify_lineage,
    verify_manifest,
)

sys.stdout.reconfigure(line_buffering=True)

#: From the release after 0.28.4, a manifest requires cryptographic evidence
#: verification unless it says otherwise, and GPU confidential-compute mode is
#: met only by a verified GPU report. This demo runs on mock attestation, which
#: nothing can verify, so its manifests waive both explicitly. On 0.28.4 the
#: field does not exist and the waivers are left out.
_REQUIRES_VERIFICATION = "require_evidence_verification" in ReleasePolicy.model_fields


def waive_mock_verification(doc: dict) -> dict:
    if _REQUIRES_VERIFICATION:
        policy = doc["release_policy"]
        policy["require_evidence_verification"] = False
        gpu = policy.get("required_gpu_measurement")
        if gpu is not None:
            gpu["require_cc_mode"] = False
    return doc


def rule(title: str) -> None:
    print(f"\n{'-' * 66}\n{title}\n{'-' * 66}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(
    *,
    weights_hash: str,
    license_text: str,
    serving_measurement: str,
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
            "license": license_text,
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
                "accepted_measurements": [
                    {"measurement": serving_measurement, "status": "current"}
                ],
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


def sign(manifest: WeightCustodyManifest, keypair, role: str, signer: str) -> dict:
    return Ed25519Signer(keypair).sign(manifest.unsigned_dict(), role=role, signer=signer)


def _release(kbs: KeyBrokerService, manifest: WeightCustodyManifest, serving: str):
    """Issue a fresh single-use challenge, produce evidence, run the gate."""
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=serving,
        gpu_measurement="nvidia-rim:demo-golden",
    )
    return kbs.verify_and_release(manifest, evidence)


def main() -> None:
    print("Weight Custody Manifest: possession is not provenance.")
    print("Real WCM code with a software (mock) attestation provider, no hardware.")

    builder = generate_ed25519()     # the model builder
    custodian = generate_ed25519()   # the deploying customer / governance function

    # The builder ships a checkpoint and a serving stack it certifies.
    checkpoint = b"<the certified model checkpoint the builder shipped>"
    base_hash = sha256(checkpoint)
    serving = sha256(b"vllm-0.6.3 + policy-bundle-v2 (the certified serving stack)")
    cadence = "1h"

    rule("1. The builder signs a manifest binding the exact weight hash")
    base_doc = build_manifest(
        weights_hash=base_hash,
        license_text="Frontier-Model-License (usage + field-of-use)",
        serving_measurement=serving,
        org="frontier-labs",
        derivatives="fine-tune-only",
    )
    base = WeightCustodyManifest.model_validate(waive_mock_verification(base_doc))
    base = base.with_signatures([
        sign(base, builder, "builder", "frontier-labs"),
        sign(base, custodian, "custodian", "enterprise-governance"),
    ])
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    print("weights_hash bound :", base_hash)
    print("manifest signature :", verify_manifest(base, ctx).ok, "(jointly signed builder + custodian)")

    rule("2. Attestation gate: the key releases only into the certified stack")
    # The KBS pins the exact manifest identity it will release for. Without
    # this the gate refuses, and correctly: a caller-supplied manifest is not
    # its own trust root, so an unpinned one could name any weights it liked.
    kbs = KeyBrokerService(
        {base.weights_hash: b"the-model-decryption-key"},
        trusted_manifest_identities=[manifest_identity(base)],
    )
    print("gate released key  :", _release(kbs, base, serving).released)
    print("enforced: genuine attestation nonce, approved platform, and a serving")
    print("image measurement matching what the builder signed.")

    rule("3. A tampered checkpoint fails before it ever loads")
    tampered = checkpoint.replace(b"certified", b"backdoored")
    matches = sha256(tampered) == base.weights_hash
    print("certified hash     :", base.weights_hash)
    print("downloaded hash    :", sha256(tampered))
    print("matches manifest   :", matches, "-> load proceeds" if matches else "-> REFUSE to load")
    print("no human reads 2.8T parameters; the hash does the reading.")

    rule("4. The fine-tune is the real IP: lineage back to the signed base")
    derivative = checkpoint + b"<+ proprietary fine-tune on private data>"
    deriv_hash = sha256(derivative)
    deriv_doc = build_manifest(
        weights_hash=deriv_hash,
        license_text="Frontier-Model-License + enterprise-proprietary-derivative",
        serving_measurement=serving,
        org="enterprise-governance",
        derivatives="none",
        derived_from=base.weights_hash,
        rights_holder={"base": "frontier-labs", "derivative": "enterprise"},
    )
    deriv = WeightCustodyManifest.model_validate(waive_mock_verification(deriv_doc))
    deriv = deriv.with_signatures([
        sign(deriv, builder, "builder", "enterprise-governance"),
        sign(deriv, custodian, "custodian", "enterprise-governance"),
    ])
    lineage = verify_lineage({base.weights_hash: base, deriv.weights_hash: deriv}, deriv.weights_hash)
    print("derivative         :", deriv_hash)
    print("lineage verified   :", lineage.ok, " depth", lineage.depth, " root is a base:", is_root(base))

    rule("What this is, and is not")
    session = EnclaveSession.from_release(base, _release(kbs, base, serving))
    session.use_key()
    print("custody active     : key held under a", cadence, "cadence, wiped on lapse",
          "(time_floor " + session.time_floor.value + ")")
    print("honest scope       : accountability-grade against an operator who physically")
    print("                     owns the silicon (see TEE.fail), not silicon-proof")
    print("                     custody. It IS the provenance the download never gave you.")


if __name__ == "__main__":
    main()
