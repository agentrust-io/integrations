"""Verify the externally replayable TRACE software packet with independent pins."""
import argparse
import json
from pathlib import Path
from harness.replay_export import verify_packet


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--packet",type=Path,required=True)
    p.add_argument("--trace-public",required=True)
    p.add_argument("--issuer-public",required=True)
    p.add_argument("--peer-public",required=True)
    a=p.parse_args()
    packet=json.loads(a.packet.read_text())
    result=verify_packet(
        packet, trace_public_key=a.trace_public,
        trusted_issuer=a.issuer_public,
        peer_public_key=a.peer_public)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
