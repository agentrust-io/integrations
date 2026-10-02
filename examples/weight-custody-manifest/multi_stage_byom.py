"""Multi-stage BYOM: sequential re-custody down a derivative chain (SPEC 3.8).

    python multi_stage_byom.py

Real WCM code, no hardware. A base model is fine-tuned, then that derivative is
fine-tuned again, each stage getting its own signed manifest that chains to its
parent by `derived_from`. `verify_lineage` enforces the three properties that
make a multi-stage pipeline safe:

  - monotone rights: a derivative may NARROW but never WIDEN the rights it
    inherits (the `derivatives` policy and `permitted_environments`);
  - upstream-logged gating: release is allowed only if every manifest up the
    chain is present in the transparency log;
  - revocation cascade: revoking any manifest invalidates everything downstream.
"""
from __future__ import annotations

import hashlib

from wcm import (
    Ed25519Signer,
    WeightCustodyManifest,
    generate_ed25519,
    is_root,
    verify_lineage,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(
    *,
    weights_hash: str,
    org: str,
    derivatives: str,
    environments: list[str],
    derived_from: str | None = None,
    rights_holder: dict | None = None,
) -> dict:
    serving = sha256(b"measured serving stack")
    doc: dict = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": org, "signing_key": "ed25519:gov"},
        "release_terms": {
            "license": "enterprise-governance",
            "permitted_derivatives": derivatives,
            "derivatives": derivatives,
            "permitted_environments": environments,
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp"],
            "required_serving_image": {
                "signer": "ed25519:gov",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
        },
        "custody": {
            "custodian": org,
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"kbs image"), "signer": "ed25519:gov"},
            "enclave_id": "did:example:gov-enclave",
            "attestation_cadence": "1h",
        },
        "base_confidentiality": "gated-open",
        "deployment_model": "byom-symmetric",
    }
    if derived_from is not None:
        doc["derived_from"] = derived_from
    if rights_holder is not None:
        doc["rights_holder"] = rights_holder
    return doc


def sign(doc: dict, keys) -> WeightCustodyManifest:
    m = WeightCustodyManifest.model_validate(doc)
    return m.with_signatures([
        Ed25519Signer(keys[0]).sign(m.unsigned_dict(), role="builder", signer=doc["builder"]["identity"]),
        Ed25519Signer(keys[1]).sign(m.unsigned_dict(), role="custodian", signer=doc["custody"]["custodian"]),
    ])


def show(label: str, result) -> None:
    chain = " -> ".join(h.split(":")[1][:10] + "..." for h in result.chain) if result.chain else "(none)"
    print(f"{label:<34} ok={result.ok}  depth={result.depth}  chain={chain}")
    for err in getattr(result, "errors", []) or []:
        print("   reason:", err)


def main() -> int:
    keys = (generate_ed25519(), generate_ed25519())

    rule("Build a 3-stage chain: base -> fine-tune -> fine-tune-of-fine-tune")
    base_h = sha256(b"public base checkpoint")
    d1_h = sha256(b"base + proprietary fine-tune A")
    d2_h = sha256(b"derivative-1 + fine-tune B")

    # Rights narrow at every stage: unrestricted -> fine-tune-only -> none, and
    # the permitted environments shrink. That is the monotone direction.
    base = sign(build_manifest(
        weights_hash=base_h, org="acme-gov", derivatives="unrestricted",
        environments=["enclave-a", "enclave-b"]), keys)
    d1 = sign(build_manifest(
        weights_hash=d1_h, org="acme-gov", derivatives="fine-tune-only",
        environments=["enclave-a"], derived_from=base_h,
        rights_holder={"base": "meta", "derivative": "acme"}), keys)
    d2 = sign(build_manifest(
        weights_hash=d2_h, org="acme-gov", derivatives="none",
        environments=["enclave-a"], derived_from=d1_h,
        rights_holder={"base": "acme", "derivative": "acme"}), keys)
    manifests = {base_h: base, d1_h: d1, d2_h: d2}
    print("root is a base manifest:", is_root(base), " leaf derived_from:", d2.derived_from[:19], "...")

    rule("1. Monotone rights: the narrowing chain verifies")
    show("leaf d2 (rights narrow):", verify_lineage(manifests, d2_h))

    rule("2. A derivative that WIDENS its parent's rights is rejected")
    # d1 allows only fine-tune-only; a child that re-opens to unrestricted widens.
    bad_h = sha256(b"derivative that illegally re-widens")
    bad = sign(build_manifest(
        weights_hash=bad_h, org="acme-gov", derivatives="unrestricted",  # widened!
        environments=["enclave-a"], derived_from=d1_h,
        rights_holder={"base": "acme", "derivative": "rogue"}), keys)
    show("widened child:", verify_lineage({**manifests, bad_h: bad}, bad_h))

    rule("3. Upstream-logged gating: release only if every ancestor is logged")
    show("all three logged:", verify_lineage(manifests, d2_h, logged=[base_h, d1_h, d2_h]))
    show("d1 missing from log:", verify_lineage(manifests, d2_h, logged=[base_h, d2_h]))

    rule("4. Revocation cascades down the chain")
    show("revoke the base:", verify_lineage(manifests, d2_h, revoked=[base_h]))
    print("revoking the base invalidates the leaf two stages down: one pull kills the")
    print("whole lineage, which is what sequential re-custody has to guarantee.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
