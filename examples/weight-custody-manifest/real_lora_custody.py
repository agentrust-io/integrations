"""Train, encrypt, verify, and locally load a real LoRA derivative.

The public base model is not treated as secret.  The saved PEFT adapter is the
private derivative: its complete file inventory is hashed, packed with stable
metadata, encrypted with AES-256-GCM, and only unpacked after authenticated
decryption and an exact inventory check.

Heavy dependencies and a model download are needed only for the launch run::

    pip install -r requirements-lora.txt
    python real_lora_custody.py --output validation/lora --infer
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import secrets
import shutil
import tarfile
import tempfile
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from model_signing import signing as model_signing

from wcm import (
    Ed25519Signer,
    KeyBrokerService,
    SoftwareProvider,
    VerificationContext,
    WeightCustodyManifest,
    artifact_files,
    generate_ed25519,
    generate_transport_keypair,
    model_signing_digest,
    open_sealed,
    verify_manifest,
    verify_provenance,
)

from _mock_attestation import waive_mock_verification

from real_open_model import build_manifest, resolve_artifact, sha256_artifact

FORMAT = "wcm-encrypted-derivative/v1"


def sign_artifact(root: pathlib.Path, output: pathlib.Path) -> tuple[str, pathlib.Path, pathlib.Path]:
    """Create a detached OpenSSF signature, retaining no private signing key."""
    signature_path = output / "adapter.model-signing.sig"
    public_key_path = output / "adapter.model-signing.pub.pem"
    key = ec.generate_private_key(ec.SECP256R1())
    public_key_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    with tempfile.TemporaryDirectory(prefix="wcm-model-signing-") as temp:
        private_key_path = pathlib.Path(temp) / "signer.key"
        private_key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        model_signing.Config().use_elliptic_key_signer(
            private_key=private_key_path
        ).sign(root, signature_path)
    return model_signing_digest(root), signature_path, public_key_path


def _relative_files(root: pathlib.Path) -> Iterable[tuple[pathlib.Path, str]]:
    for path in artifact_files(root, follow_symlinks=True):
        yield path, path.relative_to(root).as_posix()


def pack_artifact(root: pathlib.Path) -> bytes:
    """Create stable tar bytes for a directory without timestamps or owners."""
    if not root.is_dir():
        raise ValueError("the LoRA artifact must be a directory")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for path, relative in _relative_files(root):
            info = tarfile.TarInfo(relative)
            info.size = path.stat().st_size
            info.mode = 0o644
            info.mtime = info.uid = info.gid = 0
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    return output.getvalue()


def encrypt_artifact(root: pathlib.Path, key: bytes) -> dict:
    if len(key) != 32:
        raise ValueError("the derivative data-encryption key must be 32 bytes")
    digest = sha256_artifact(root)
    nonce = secrets.token_bytes(12)
    aad = json.dumps(
        {"format": FORMAT, "artifact_digest": digest},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    ciphertext = AESGCM(key).encrypt(nonce, pack_artifact(root), aad)
    return {
        "format": FORMAT,
        "artifact_digest": digest,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }


def encrypt_and_remove_staging(root: pathlib.Path, key: bytes) -> dict:
    """Encrypt a staging artifact and remove its plaintext on every exit path."""
    try:
        return encrypt_artifact(root, key)
    finally:
        if root.exists():
            shutil.rmtree(root)


def decrypt_artifact(envelope: dict, key: bytes, destination: pathlib.Path) -> str:
    """Authenticate, safely unpack, then verify the exact derivative inventory."""
    if envelope.get("format") != FORMAT:
        raise ValueError("unsupported encrypted derivative format")
    digest = envelope.get("artifact_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("encrypted derivative is missing its artifact digest")
    aad = json.dumps(
        {"format": FORMAT, "artifact_digest": digest},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(envelope["nonce_b64"], validate=True),
        base64.b64decode(envelope["ciphertext_b64"], validate=True),
        aad,
    )
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents or not member.isfile():
                raise ValueError("encrypted derivative contains an unsafe archive member")
        archive.extractall(destination, filter="data")
    observed = sha256_artifact(destination)
    if observed != digest:
        raise ValueError(f"decrypted derivative digest mismatch: {observed} != {digest}")
    return observed


def train_lora(base_path: pathlib.Path, output: pathlib.Path, *, steps: int) -> None:
    """Perform a small, deterministic, genuine gradient update and save PEFT files."""
    try:
        import torch
        from peft import LoraConfig, TaskType, get_peft_model
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise SystemExit("install requirements-lora.txt to train the derivative") from exc

    torch.manual_seed(20260812)
    os.environ["HF_HUB_OFFLINE"] = "1"
    tokenizer = AutoTokenizer.from_pretrained(base_path, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(base_path, local_files_only=True)
    config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=4,
        lora_alpha=8,
        lora_dropout=0.0,
        target_modules=["q_proj", "v_proj"],
    )
    model = get_peft_model(model, config)
    model.train()
    batch = tokenizer(
        "WCM releases a private model derivative only after fresh attestation.",
        return_tensors="pt",
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-4)
    for _ in range(steps):
        optimizer.zero_grad()
        loss = model(**batch, labels=batch["input_ids"]).loss
        loss.backward()
        optimizer.step()
    output.mkdir(parents=True, exist_ok=False)
    model.save_pretrained(output, safe_serialization=True)


def run_inference(base_path: pathlib.Path, adapter_path: pathlib.Path) -> str:
    try:
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise SystemExit("install requirements-lora.txt to run inference") from exc
    os.environ["HF_HUB_OFFLINE"] = "1"
    tokenizer = AutoTokenizer.from_pretrained(base_path, local_files_only=True)
    base = AutoModelForCausalLM.from_pretrained(base_path, local_files_only=True)
    model = PeftModel.from_pretrained(base, adapter_path, local_files_only=True)
    inputs = tokenizer("Confidential model custody", return_tensors="pt")
    output = model.generate(**inputs, max_new_tokens=12, do_sample=False)
    return tokenizer.decode(output[0], skip_special_tokens=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="HuggingFaceTB/SmolLM2-135M-Instruct")
    parser.add_argument("--revision", default="main")
    parser.add_argument("--local")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--steps", type=int, default=1)
    parser.add_argument("--infer", action="store_true")
    args = parser.parse_args()
    if args.steps < 1:
        parser.error("--steps must be positive")

    base_path, model_id = resolve_artifact(args)
    if not base_path.is_dir():
        parser.error("LoRA training requires a complete base-model directory")
    base_digest = sha256_artifact(base_path)
    adapter_path = args.output / "adapter-plaintext"
    train_lora(base_path, adapter_path, steps=args.steps)

    provenance_digest, provenance_signature, provenance_public_key = sign_artifact(
        adapter_path, args.output
    )

    key = AESGCM.generate_key(bit_length=256)
    envelope = encrypt_and_remove_staging(adapter_path, key)
    envelope_path = args.output / "adapter.encrypted.json"
    envelope_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    # Bind the real derivative digest and lineage into a jointly signed WCM
    # manifest, then release its DEK only as ciphertext sealed to the workload's
    # ephemeral transport key. This local tier deliberately uses software
    # evidence; the identical manifest/KBS path is fed hardware evidence later.
    builder, custodian = generate_ed25519(), generate_ed25519()
    serving = "sha256:" + hashlib.sha256(b"wcm-local-lora-serving-stack-v1").hexdigest()
    manifest_doc = build_manifest(
        weights_hash=envelope["artifact_digest"],
        license_text="Apache-2.0 + OPAQUE-private-derivative",
        serving=serving,
        builder_id="opaque-wcm-builder",
        custodian_id="opaque-wcm-custodian",
        derivatives="none",
        derived_from=base_digest,
        rights_holder={"base": model_id, "derivative": "OPAQUE"},
    )
    manifest_doc["provenance"] = {
        "model_signing": {
            "method": "openssf-model-signing",
            "signed_digest": provenance_digest,
            "transparency": "local-key; publication pending",
            "signer": "opaque-wcm-builder",
        }
    }
    manifest = WeightCustodyManifest.model_validate(waive_mock_verification(manifest_doc))
    manifest = manifest.with_signatures([
        Ed25519Signer(builder).sign(
            manifest.unsigned_dict(), role="builder", signer="opaque-wcm-builder"
        ),
        Ed25519Signer(custodian).sign(
            manifest.unsigned_dict(), role="custodian", signer="opaque-wcm-custodian"
        ),
    ])
    context = VerificationContext()
    context.add_key(builder.public_bytes)
    context.add_key(custodian.public_bytes)
    if not verify_manifest(manifest, context).ok:
        raise RuntimeError("joint derivative-manifest verification failed")

    transport_private, transport_public = generate_transport_keypair()
    kbs = KeyBrokerService(
        {manifest.weights_hash: key}, require_channel_binding=True
    )
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=serving,
        gpu_measurement="nvidia-rim:demo-golden",
        transport_public_key=transport_public,
    )
    release = kbs.verify_and_release(manifest, evidence)
    if not release.released or release.key is not None or release.sealed_key is None:
        raise RuntimeError("KBS did not return a transport-sealed derivative key")
    released_key = open_sealed(release.sealed_key, transport_private)

    manifest_path = args.output / "derivative.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json", exclude_none=True), indent=2),
        encoding="utf-8",
    )
    verification_keys_path = args.output / "manifest-verification-keys.json"
    verification_keys_path.write_text(json.dumps({
        "builder_ed25519_public_b64": base64.b64encode(builder.public_bytes).decode(),
        "custodian_ed25519_public_b64": base64.b64encode(custodian.public_bytes).decode(),
    }, indent=2), encoding="utf-8")
    print("base model       :", model_id)
    print("base digest      :", base_digest)
    print("derivative digest:", envelope["artifact_digest"])
    print("encrypted artifact:", envelope_path)
    print("signed manifest  :", manifest_path)
    print("verification keys:", verification_keys_path)
    print("OpenSSF signature:", provenance_signature)
    print("OpenSSF public key:", provenance_public_key)
    print("KBS release      : sealed to ephemeral transport key (software evidence tier)")

    with tempfile.TemporaryDirectory(prefix="wcm-lora-") as temp:
        verified = pathlib.Path(temp) / "verified-adapter"
        decrypt_artifact(envelope, released_key, verified)
        provenance = verify_provenance(
            manifest,
            verified,
            provenance_signature,
            public_key=provenance_public_key,
        )
        if not provenance.verified:
            raise RuntimeError(f"OpenSSF provenance verification failed: {provenance.reason}")
        print("OpenSSF provenance: verified against decrypted exact artifact")
        print("verified local derivative before load:", verified)
        if args.infer:
            print("model output:", repr(run_inference(base_path, verified)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
