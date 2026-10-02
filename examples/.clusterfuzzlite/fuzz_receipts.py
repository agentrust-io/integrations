#!/usr/bin/python3
"""Fuzz the embodied-action receipt verifier.

verify_text() reads a fixture an auditor was handed: a TRACE reference, an
action and a chain of controller-signed receipts. Every byte is attacker-chosen
until the Ed25519 check on each receipt passes.

The property is the documented contract: it always returns a verdict, with
"valid" or "invalid" as the result, and never raises. Before this target
existed a wrong shape escaped as KeyError, TypeError, AttributeError or
binascii.Error, and a signature with stray characters in its base64 still
verified. The seed corpus is the committed fixtures, so mutations start from a
chain that already verifies.
"""
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "embodied-action-receipts"))

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from verify_receipts import TrustedSigner, b64url_decode, verify_text

# The public test key from embodied-action-receipts/trusted-keys.json, inlined
# because PyInstaller bundles code, not the data files beside it.
_TRUSTED = {
    "robot-cell-7-controller": TrustedSigner(
        issuer="spiffe://factory.example/controller/robot-cell-7",
        public_key=Ed25519PublicKey.from_public_bytes(
            b64url_decode("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
        ),
    )
}


def TestOneInput(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    result = verify_text(text, _TRUSTED)
    assert isinstance(result, dict), result
    assert result.get("result") in {"valid", "invalid"}, result
    assert isinstance(result.get("receipt_state"), str), result


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
