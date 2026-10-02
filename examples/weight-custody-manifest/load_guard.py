"""Gate your model load: verify the weights before you load them.

A drop-in load guard. Before a checkpoint is loaded, prove two things: the
manifest that certifies it is jointly signed (builder + custodian), and the
bytes on disk hash to exactly what that manifest binds. A tampered or swapped
fork is refused BEFORE it ever reaches your loader.

This is the integrity and provenance gate (Layer 1): "is this the checkpoint the
builder shipped." Honest scope: it catches tampering and swaps against software
and remote adversaries; it is accountability-grade, not silicon-proof, against an
operator who physically owns the hardware.

    pip install weight-custody-manifest
    python load_guard.py                    # offline demo: certified loads, tampered refused
    python load_guard.py --load --model model.safetensors   # gate + actually load a real file
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import tempfile

from wcm import (
    Ed25519Signer,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    verify_manifest,
)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def banner(text: str) -> None:
    print(f"\n{'=' * 64}\n{text}\n{'=' * 64}")


def build_manifest(weights_hash: str, org: str) -> dict:
    serving = sha256_bytes(b"vllm + policy-bundle (the builder-signed serving stack)")
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
            "kbs_image": {"measurement": sha256_bytes(b"reference-kbs-image"), "signer": "ed25519:demo"},
            "enclave_id": "did:example:enclave-01",
            "attestation_cadence": "1h",
        },
        "base_confidentiality": "gated-open",
        "deployment_model": "builder-to-customer",
    }


class RefusedToLoad(Exception):
    """The checkpoint failed verification and must not be loaded."""


def guarded_load(model_path, manifest, ctx, *, do_load: bool = False) -> str:
    """Verify the manifest and the bytes on disk BEFORE loading; refuse on any mismatch.

    The whole point: both checks run before a single byte reaches your loader.
    Returns the verified digest, or raises RefusedToLoad.
    """
    model_path = pathlib.Path(model_path)

    # 1. The manifest itself must be jointly signed and valid.
    if not verify_manifest(manifest, ctx).ok:
        raise RefusedToLoad("manifest signature invalid (not the certified manifest)")

    # 2. The bytes on disk must hash to exactly what the manifest binds.
    digest = sha256_file(model_path)
    if digest != manifest.weights_hash:
        raise RefusedToLoad(
            "weights hash mismatch\n"
            f"    manifest binds : {manifest.weights_hash}\n"
            f"    file on disk   : {digest}"
        )

    # Only now is it safe to load.
    if do_load:
        _real_load(model_path)
    return digest


def _real_load(model_path: pathlib.Path) -> None:
    """Actually load the verified file (run-local; needs the infer extras)."""
    from safetensors import safe_open  # lazy: pip install -r requirements-infer.txt

    with safe_open(str(model_path), framework="pt") as f:
        keys = list(f.keys())
    print(f"loaded {len(keys)} tensors from {model_path.name} (verified first)")


def _signed_manifest(weights_hash: str, org: str = "frontier-labs"):
    """Return (manifest, verification_context) for a jointly-signed manifest."""
    builder, custodian = generate_ed25519(), generate_ed25519()
    manifest = WeightCustodyManifest.model_validate(build_manifest(weights_hash, org))
    manifest = manifest.with_signatures([
        Ed25519Signer(builder).sign(manifest.unsigned_dict(), role="builder", signer=org),
        Ed25519Signer(custodian).sign(manifest.unsigned_dict(), role="custodian", signer=org),
    ])
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    return manifest, ctx


def demo() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        weights = b"<the certified model weights the builder shipped>"
        certified = tmp / "model.certified.bin"
        certified.write_bytes(weights)

        # The builder signs a manifest binding this exact checkpoint.
        manifest, ctx = _signed_manifest(sha256_bytes(weights))

        banner("1. The certified checkpoint. Verified, then loaded.")
        digest = guarded_load(certified, manifest, ctx)
        print("manifest signature :", "valid (builder + custodian)")
        print("weights hash       :", digest[:23], "... matches the manifest")
        print("-> load proceeds")

        banner("2. A tampered fork. Refused before it loads.")
        b = bytearray(weights)
        b[0] ^= 0x01  # flip a single byte
        tampered = tmp / "model.tampered.bin"
        tampered.write_bytes(bytes(b))
        try:
            guarded_load(tampered, manifest, ctx)
            print("-> load proceeds")  # not reached
        except RefusedToLoad as exc:
            print("REFUSED:", exc)
            print("-> the loader never sees the bytes. One flipped byte is enough.")

    banner("Verify the weights before you load them.")
    print("Integrity gate only (Layer 1). Honest scope: this catches tampering and swaps")
    print("against software and remote adversaries. It is accountability-grade, not")
    print("silicon-proof, against an operator who physically owns the hardware.")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Gate a model load on a signed Weight Custody Manifest."
    )
    ap.add_argument("--model", help="path to a real checkpoint to gate (run-local)")
    ap.add_argument(
        "--load", action="store_true",
        help="actually load the file after verifying (needs --model and the infer extras)",
    )
    args = ap.parse_args()

    if not args.model:
        demo()
        return

    # Real run: a builder signs a manifest over this file, then the guard runs
    # before the load. Swap in a manifest you received from the builder instead.
    path = pathlib.Path(args.model)
    manifest, ctx = _signed_manifest(sha256_file(path))
    banner(f"Gating {path.name}")
    guarded_load(path, manifest, ctx, do_load=args.load)
    print("verified" + (" and loaded" if args.load else " (pass --load to load it)"))


if __name__ == "__main__":
    main()
