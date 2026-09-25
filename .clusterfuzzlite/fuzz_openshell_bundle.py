#!/usr/bin/python3
"""Fuzz verify_bundle(), the OpenShell evidence-bundle verifier.

A bundle is a manifest, a detached signature and two files, all supplied by the
party presenting the evidence. The verifier promises that anything malformed,
unauthenticated, substituted or corrupted raises BundleError and never yields a
coverage verdict.

Random bytes alone never get past the Ed25519 check, so in most modes this
target signs the manifest with its own pinned key. That is the case that
matters: a producer holding a trusted key can still emit a malformed manifest or
event file, and the verifier has to reject it inside its own error type.

Properties:
  * Only BundleError escapes.
  * A result is one of the three declared coverage values, and
    "verified_complete_over_range" is only returned for a manifest that says
    complete, carries sequence bounds, and has one event per signed sequence.
  * Nothing verifies under a key that is not pinned.
"""
import base64
import hashlib
import json
import sys

import atheris

with atheris.instrument_imports():
    from agentrust_trace_adapters.openshell_bundle import BundleError, verify_bundle
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
_OTHER = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
_TRUSTED = {"gw": _KEY.public_key()}
_COVERAGE = {"verified_complete_over_range", "provable_gap", "not_established"}


def _sign(key, raw: bytes) -> bytes:
    return json.dumps({
        "algorithm": "Ed25519",
        "key_id": "gw",
        "signature": base64.b64encode(key.sign(raw)).decode(),
    }).encode()


def _structured(fdp) -> tuple[bytes, dict]:
    """A manifest whose shape is right and whose values are fuzzed."""
    events = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))
    files = {"effective-policy.yaml": b"network: deny\n", "events.ocsf.jsonl": events}
    first = fdp.ConsumeIntInRange(0, 20)
    complete = fdp.ConsumeBool()
    manifest = {
        "format": "agentrust.openshell-evidence-candidate.v1",
        "sandbox_id": "sbx",
        "openshell_version": "v",
        "policy_revision": "r",
        "capture_start": 0,
        "capture_end": 1000,
        "complete": complete,
        "incomplete_reason": None if complete else "stopped",
        "event_count": fdp.ConsumeIntInRange(0, 20),
        "sequence": (
            {"epoch": "e", "first": first, "last": first + fdp.ConsumeIntInRange(0, 20)}
            if fdp.ConsumeBool() else None
        ),
        "files": {n: "sha256:" + hashlib.sha256(b).hexdigest() for n, b in files.items()},
    }
    return json.dumps(manifest).encode(), files


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 3)
    if mode == 0:
        # Every byte raw, signature included.
        manifest = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048))
        signature = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512))
        files = {
            "effective-policy.yaml": fdp.ConsumeBytes(64),
            "events.ocsf.jsonl": fdp.ConsumeBytes(fdp.remaining_bytes()),
        }
    elif mode == 1:
        # Raw manifest bytes, validly signed by the pinned key.
        manifest = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))
        signature = _sign(_KEY, manifest)
        files = {
            "effective-policy.yaml": b"p",
            "events.ocsf.jsonl": fdp.ConsumeBytes(fdp.remaining_bytes()),
        }
    elif mode == 2:
        # Well-formed manifest and matching digests over a fuzzed event file.
        manifest, files = _structured(fdp)
        signature = _sign(_KEY, manifest)
    else:
        # The same, signed by a key that is not pinned: must never verify.
        manifest, files = _structured(fdp)
        signature = _sign(_OTHER, manifest)

    try:
        result = verify_bundle(
            manifest,
            signature,
            files,
            trusted_keys=_TRUSTED,
            expected_sandbox_id="sbx",
            expected_capture_start=0,
            expected_capture_end=1000,
        )
    except BundleError:
        return

    assert mode != 3, "bundle verified under an unpinned key"
    assert result.coverage in _COVERAGE
    if result.coverage == "verified_complete_over_range":
        parsed = json.loads(manifest)
        assert parsed["complete"] is True
        bounds = parsed["sequence"]
        assert bounds is not None
        assert result.event_count == bounds["last"] - bounds["first"] + 1


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
