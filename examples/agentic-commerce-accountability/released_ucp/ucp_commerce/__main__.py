"""Offline demonstration and independently selected public-key audit entry point."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import BaseModel, ConfigDict, Field

from .flow import (
    Bundle,
    Denied,
    Keys,
    Merchant,
    Trust,
    audit,
    completion_request,
    make_grant,
    utc_now,
)
from .schema import UCP_VERSION, sample_checkout


class PublicTrust(BaseModel):
    """Explicit local trust configuration, NOT keys discovered from a bundle."""

    model_config = ConfigDict(strict=True, extra="forbid")
    merchant: str = Field(max_length=2048)
    platform: str = Field(max_length=2048)
    authority: str = Field(max_length=2048)
    receipt: str = Field(max_length=2048)

    @classmethod
    def from_trust(cls, trust: Trust) -> PublicTrust:
        def pem(key: ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey) -> str:
            return key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")

        return cls(
            merchant=pem(trust.merchant),
            platform=pem(trust.platform),
            authority=pem(trust.authority),
            receipt=pem(trust.receipt),
        )

    def trust(self) -> Trust:
        merchant = serialization.load_pem_public_key(self.merchant.encode("ascii"))
        platform = serialization.load_pem_public_key(self.platform.encode("ascii"))
        authority = serialization.load_pem_public_key(self.authority.encode("ascii"))
        receipt = serialization.load_pem_public_key(self.receipt.encode("ascii"))
        if not (
            isinstance(merchant, ec.EllipticCurvePublicKey)
            and isinstance(merchant.curve, ec.SECP256R1)
            and isinstance(platform, ec.EllipticCurvePublicKey)
            and isinstance(platform.curve, ec.SECP256R1)
            and isinstance(authority, ed25519.Ed25519PublicKey)
            and isinstance(receipt, ed25519.Ed25519PublicKey)
        ):
            raise ValueError("unsupported configured public keys")
        configured = Trust(merchant, platform, authority, receipt)
        # cryptography's parser can ignore trailing PEM blocks. Require exactly
        # the canonical public SPKI document, with no appended key or other data.
        if self != PublicTrust.from_trust(configured):
            raise ValueError("configured fields must contain one canonical public key")
        return configured


def _read(path: Path, limit: int) -> str:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds example size limit")
    return data.decode("utf-8")


def _demo(output: Path | None) -> dict:
    # Private keys exist only in memory; the temporary local DB is never exported.
    keys = Keys.generate()
    now = utc_now()
    with tempfile.TemporaryDirectory(prefix="released-ucp-") as temporary:
        merchant = Merchant(Path(temporary) / "merchant.sqlite", keys)
        merchant.seed_checkout(sample_checkout())
        quote = merchant.quote("checkout-001")
        grant = make_grant(keys, now)
        request = completion_request(keys, now, "checkout-001")
        bundle = merchant.complete(grant, quote, request)
        decision = audit(bundle, keys.trust(), utc_now())
        retry = merchant.complete(grant, quote, request)
        try:
            merchant.complete(grant, quote, completion_request(keys, utc_now(), "checkout-001"))
        except Denied as refusal:
            replay = refusal.reason
        else:
            raise RuntimeError("one-purchase invariant failed")
        spends, effects = merchant.counts()
        if replay != "GRANT_SPENT" or (spends, effects) != (1, 1) or retry != bundle:
            raise RuntimeError("retry invariant failed")
        if output is not None:
            # Deliberately do not overwrite a previous evidence/trust selection.
            output.mkdir(mode=0o700, parents=True, exist_ok=False)
            (output / "bundle.json").write_text(bundle.model_dump_json(indent=2) + "\n")
            (output / "public-trust.json").write_text(
                PublicTrust.from_trust(keys.trust()).model_dump_json(indent=2) + "\n"
            )
        return {
            "ucp_release": UCP_VERSION,
            "decision": decision.decision,
            "amount_minor": 12500,
            "currency": "USD",
            "invocation_number": decision.invocation_number,
            "spends": spends,
            "effects": effects,
            "identical_retry_cached": retry == bundle,
            "fresh_token_replay": replay,
            "trace": [
                "released JSON Schemas and SDK models validate both UCP bodies",
                "configured keys verify ES256 HTTP signatures and raw-body digests",
                "user authority permits this merchant/platform, USD cap and operation",
                "current checkout matches the authenticated quoted terms",
                "one SQL spend, simulated effect and signed result commit together",
                "read-only audit rechecks grant, messages, software TRACE and decision",
            ],
            "assurance": (
                "Local simulated purchase only: no payment, hardware attestation, "
                "exact-price user consent, or independent proof of execution."
            ),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="new directory for public demonstration evidence"
    )
    commands = parser.add_subparsers(dest="command")
    verifier = commands.add_parser(
        "audit", help="read-only audit within the local 300-second window"
    )
    verifier.add_argument("bundle", type=Path)
    verifier.add_argument(
        "--trust", type=Path, required=True, help="independently selected public keys"
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "audit":
            if arguments.output is not None:
                raise ValueError("audit does not export evidence")
            trust = PublicTrust.model_validate_json(_read(arguments.trust, 16_384)).trust()
            bundle = Bundle.model_validate_json(_read(arguments.bundle, 1_048_576))
            result = audit(bundle, trust, utc_now()).model_dump()
        else:
            result = _demo(arguments.output)
        print(json.dumps(result, indent=2))
        return 0
    except Exception:
        # No raw submitted artifacts, filesystem paths or cryptographic errors.
        print(json.dumps({"error": "example operation failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
