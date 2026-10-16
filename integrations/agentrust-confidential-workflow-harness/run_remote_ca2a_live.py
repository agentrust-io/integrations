"""Run the restricted software cA2A peer proof from a private operator config.

The config contains file paths and pinned PUBLIC keys, never private contents.
No implicit configuration, external discovery, or SSH host-key override.
"""
import argparse
import json
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness.remote_peer_client import run, ssh_sender


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    issuer = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(cfg["issuer_key"]).read_text().strip()))
    holder = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(cfg["holder_key"]).read_text().strip()))
    result = run(
        transaction_id="live-ca2a-" + uuid.uuid4().hex,
        nonce=uuid.uuid4().hex,
        repo=cfg["repo"], issuer_private=issuer, holder_private=holder,
        peer_public_key=cfg["peer_public_key"],
        trace_public_key=cfg["trace_public_key"],
        send=ssh_sender(cfg["host"], cfg["ssh_key"]))
    print(json.dumps(result.__dict__, sort_keys=True))
    if (result.outcome != "authenticated-remote-ca2a-software"
            or not result.remote_ca2a_verified
            or not result.trace_verified):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
