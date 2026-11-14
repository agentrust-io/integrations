"""Run the restricted software cA2A peer proof from a private operator config.

The config contains file paths and pinned PUBLIC keys, never private contents.
No implicit configuration, external discovery, or SSH host-key override.
"""
import argparse
import json
import os
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness.remote_peer_client import run, ssh_sender


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path, required=True)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    issuer = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(cfg["issuer_key"]).read_text().strip()))
    holder = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(cfg["holder_key"]).read_text().strip()))
    def write_packet(packet):
        args.evidence_out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=os.open(args.evidence_out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:
            json.dump(packet,f,sort_keys=True,indent=2)
            f.write("\n")

    result = run(
        transaction_id="live-ca2a-" + uuid.uuid4().hex,
        nonce=uuid.uuid4().hex,
        repo=cfg["repo"], issuer_private=issuer, holder_private=holder,
        peer_public_key=cfg["peer_public_key"],
        trace_public_key=cfg["trace_public_key"],
        send=ssh_sender(cfg["host"], cfg["ssh_key"]),
        evidence_sink=write_packet)
    print(json.dumps(result.__dict__, sort_keys=True))
    if (result.outcome != "authenticated-remote-ca2a-software"
            or not result.remote_ca2a_verified
            or not result.trace_verified):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
