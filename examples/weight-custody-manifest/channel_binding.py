"""Channel binding: sealing the released key to the attested enclave (CVE-2026-33697).

    python channel_binding.py

Real WCM code, no hardware. Nonce binding stops a REPLAYED quote, but not a
RELAYED one: a network adversary terminating the enclave's channel could forward
a live valid quote and divert the released key onto its own channel. WCM closes
that gap (SPEC 3.2 channel binding): the enclave folds a transport public key
into the quote's REPORT_DATA under the nonce, and the KBS seals the released key
to that transport key instead of returning it in the clear. This shows both
teeth: a relay that just forwards the release gets ciphertext it cannot open, and
a relay that substitutes its own transport key fails quote verification outright.

The attestation quote here is signed by a synthetic PKI (real cryptography, not a
real vendor chain) so the verification is genuine end to end.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wcm import (
    CompositeEvidence,
    CpuQuote,
    Ed25519Signer,
    generate_ed25519,
    generate_transport_keypair,
    JsonQuoteParser,
    KeyBrokerService,
    manifest_identity,
    open_sealed,
    QuoteVerifier,
    SealError,
    TrustStore,
    WeightCustodyManifest,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _pki():
    """A self-signed root CA and a leaf attestation-key cert it signs."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    def cert(subject, subj_key, issuer, issuer_key, ca):
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(subj_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=365))
        )
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        return b.sign(issuer_key, hashes.SHA256())

    root = cert("wcm-demo-root", root_key, "wcm-demo-root", root_key, True)
    leaf = cert("attestation-key", leaf_key, "wcm-demo-root", root_key, False)
    return root, leaf, leaf_key


def _quote(leaf, leaf_key, nonce_hex: str, transport_pub_hex: str) -> str:
    """A quote whose REPORT_DATA binds sha256(nonce || transport_public_key)."""
    digest = hashlib.sha256(bytes.fromhex(nonce_hex) + bytes.fromhex(transport_pub_hex)).digest()
    report_body = digest + bytes(32) + b"measurement-and-tcb"
    signature = leaf_key.sign(report_body, ec.ECDSA(hashes.SHA256()))
    doc = {
        "report_b64": base64.b64encode(report_body).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "intermediates_pem": [],
        "report_data_offset": 0,
    }
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _manifest():
    serving = sha256(b"measured serving stack")
    doc = {
        "manifest_version": "0.1",
        "weights_hash": sha256(b"the model weights"),
        "builder": {"identity": "lab", "signing_key": "ed25519:lab"},
        "release_terms": {
            "license": "deployment-agreement",
            "permitted_derivatives": "none",
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
    }
    b, c = generate_ed25519(), generate_ed25519()
    m = WeightCustodyManifest.model_validate(doc)
    return m.with_signatures([
        Ed25519Signer(b).sign(m.unsigned_dict(), role="builder", signer="lab"),
        Ed25519Signer(c).sign(m.unsigned_dict(), role="custodian", signer="customer"),
    ]), serving


def _evidence(manifest, serving, nonce, quote_b64, transport_pub_hex):
    return CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=serving,
            nonce_echo=nonce,
            attestation_key_id="vcek:demo",
            quote_b64=quote_b64,
            transport_public_key=transport_pub_hex,
        )
    )


def main() -> int:
    root, leaf, leaf_key = _pki()
    manifest, serving = _manifest()
    KEY = b"the-weight-decryption-key-32bytes"

    trust = TrustStore()
    trust.add_root(root)
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY},
        now=lambda: NOW,
        cpu_quote_verifier=QuoteVerifier(JsonQuoteParser(), trust),
        require_channel_binding=True,
        # weight-custody-manifest 0.27.0 refuses to release unless the manifest's
        # identity is pinned out of band. Without it, a caller could present an
        # attacker-authored policy that reused a weights hash the broker already
        # held and be released against terms nobody agreed.
        trusted_manifest_identities=[manifest_identity(manifest)],
    )

    enclave_priv, enclave_pub = generate_transport_keypair()
    attacker_priv, attacker_pub = generate_transport_keypair()

    rule("Step 1 - Legit enclave: the key releases, SEALED to its transport key")
    ch = kbs.issue_challenge()
    quote = _quote(leaf, leaf_key, ch.nonce, enclave_pub)  # bound to the enclave key
    decision = kbs.verify_and_release(manifest, _evidence(manifest, serving, ch.nonce, quote, enclave_pub))
    print("released              :", decision.released)
    print("raw key on the wire   :", decision.key, " (never; sealed only)")
    opened = open_sealed(decision.sealed_key, enclave_priv)
    print("enclave opens the seal:", opened == KEY)

    rule("Step 2 - A relay forwards the sealed release: it gets only ciphertext")
    try:
        open_sealed(decision.sealed_key, attacker_priv)
        print("attacker opened it    : True   (should not happen)")
    except SealError:
        print("attacker opens the seal: FAILS (SealError) - it is not the bound enclave")

    rule("Step 3 - A relay substitutes its own transport key: quote verification fails")
    ch2 = kbs.issue_challenge()
    quote2 = _quote(leaf, leaf_key, ch2.nonce, enclave_pub)  # still bound to the enclave key
    # ...but the relay claims the attacker key so the seal would land on its channel.
    relayed = kbs.verify_and_release(
        manifest, _evidence(manifest, serving, ch2.nonce, quote2, attacker_pub)
    )
    print("released              :", relayed.released, " (denied)")
    reason = next((c.detail for c in relayed.failures if c.name == "cpu_quote_verified"), None)
    print("why                   :", reason)
    print()
    print("Either way the relay is defeated: forward the seal and it is unopenable;")
    print("swap the transport key and REPORT_DATA no longer matches, so nothing releases.")
    return 0 if (decision.released and not relayed.released) else 1


if __name__ == "__main__":
    raise SystemExit(main())
