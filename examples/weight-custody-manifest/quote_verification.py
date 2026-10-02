"""Quote verification: the KBS-side trust decision, and where real vendors plug in.

    python quote_verification.py

Real WCM code, no hardware. Getting structured evidence to the gate is not the
trust decision. The trust decision is cryptographic: does the attestation quote
carry a valid hardware signature, does that key chain to a root the verifier
trusts, and is the quote bound to THIS challenge nonce? This drives
`QuoteVerifier` through the happy path and every failure mode against a synthetic
PKI (real cryptography), then points at the real vendor parsers that produce the
same `ParsedQuote` from genuine binary quotes.
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
    JsonQuoteParser,
    QuoteVerifier,
    SnpQuoteParser,
    TrustStore,
    build_gpu_verifier,
    verify_tdx_quote,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
NONCE = "ab" * 32


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def _pki():
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

    root = cert("vendor-root", root_key, "vendor-root", root_key, True)
    leaf = cert("attestation-key", leaf_key, "vendor-root", root_key, False)
    return root, leaf, leaf_key


def _quote(leaf, leaf_key, nonce_hex: str) -> str:
    report_body = hashlib.sha256(bytes.fromhex(nonce_hex)).digest() + bytes(32) + b"measurement"
    signature = leaf_key.sign(report_body, ec.ECDSA(hashes.SHA256()))
    doc = {
        "report_b64": base64.b64encode(report_body).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "intermediates_pem": [],
        "report_data_offset": 0,
    }
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _verifier(root) -> QuoteVerifier:
    ts = TrustStore()
    ts.add_root(root)
    return QuoteVerifier(JsonQuoteParser(), ts)


def main() -> int:
    root, leaf, leaf_key = _pki()
    quote = _quote(leaf, leaf_key, NONCE)
    v = _verifier(root)

    rule("Happy path - chain, signature, and nonce binding all check")
    r = v.verify(quote, expected_nonce=NONCE, now=NOW)
    print("verified:", r.verified, " leaf:", r.leaf_subject)

    rule("Untrusted root - the quote does not chain to a root we trust")
    other_root, _, _ = _pki()
    r = _verifier(other_root).verify(quote, expected_nonce=NONCE, now=NOW)
    print("verified:", r.verified, " reason:", r.reason)

    rule("Tampered report - the signature no longer verifies")
    doc = json.loads(base64.b64decode(quote))
    body = bytearray(base64.b64decode(doc["report_b64"]))
    body[-1] ^= 0xFF
    doc["report_b64"] = base64.b64encode(bytes(body)).decode()
    tampered = base64.b64encode(json.dumps(doc).encode()).decode()
    r = v.verify(tampered, expected_nonce=NONCE, now=NOW)
    print("verified:", r.verified, " reason:", r.reason)

    rule("Nonce mismatch - a replayed quote is not bound to this challenge")
    r = v.verify(quote, expected_nonce="cd" * 32, now=NOW)
    print("verified:", r.verified, " reason:", r.reason)

    rule("Where the real vendors plug in")
    print("The machinery above is vendor-agnostic. A real deployment swaps the")
    print("JsonQuoteParser + synthetic root for a vendor parser + the vendor's real root:")
    print(f"  AMD SEV-SNP : {SnpQuoteParser.__name__} (VCEK -> ASK -> ARK), validated on live Azure")
    print(f"  Intel TDX   : {verify_tdx_quote.__name__} (DCAP v4 -> Intel SGX Root CA), validated on GCP")
    print(f"  NVIDIA H100 : {build_gpu_verifier.__name__} (GPU report -> NVIDIA device root)")
    print("None of this closes the key-extraction hole (open question 8.8): a")
    print("physically-extracted key produces a genuinely valid signature. It raises")
    print("the bar to a real hardware signature; it does not beat a hardware owner.")
    return 0 if r is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
