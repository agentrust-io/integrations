"""Runnable synthetic bundle; prints verification, never writes private keys."""

import base64
import hashlib
import json
from dataclasses import asdict

from agentrust_trace_adapters.openshell_bundle import verify_bundle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    key = Ed25519PrivateKey.generate()
    event = {
        "time": 150,
        "metadata": {
            "uid": "synthetic-sandbox",
            "sequence": 7,
            "product": {"version": "synthetic"},
        },
    }
    files = {
        "effective-policy.yaml": b"network: deny\n",
        "events.ocsf.jsonl": json.dumps(event).encode() + b"\n",
    }
    manifest = {
        "format": "agentrust.openshell-evidence-candidate.v1",
        "sandbox_id": "synthetic-sandbox",
        "openshell_version": "synthetic",
        "policy_revision": "synthetic-policy",
        "capture_start": 100,
        "capture_end": 200,
        "complete": True,
        "incomplete_reason": None,
        "event_count": 1,
        "sequence": {"epoch": "synthetic-boot", "first": 7, "last": 7},
        "files": {
            name: "sha256:" + hashlib.sha256(raw).hexdigest()
            for name, raw in files.items()
        },
    }
    raw = json.dumps(manifest, indent=2).encode()
    signature = json.dumps(
        {
            "algorithm": "Ed25519",
            "key_id": "synthetic-key",
            "signature": base64.b64encode(key.sign(raw)).decode(),
        }
    ).encode()
    result = verify_bundle(
        raw,
        signature,
        files,
        trusted_keys={"synthetic-key": key.public_key()},
        expected_sandbox_id="synthetic-sandbox",
        expected_capture_start=100,
        expected_capture_end=200,
    )
    print(json.dumps({"evidence": "synthetic", **asdict(result)}, indent=2))


if __name__ == "__main__":
    main()
