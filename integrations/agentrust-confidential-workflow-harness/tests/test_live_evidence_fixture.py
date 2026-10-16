"""Reproduce the historical public software signature fixture without SSH."""
import copy
import hashlib
import json
import unittest
from pathlib import Path
from harness.replay_export import verify_packet

FILE = Path(__file__).resolve().parents[1] / "evidence/live-software-20261016.json"
FILE_SHA256 = "402a8f0cc05bc517d2918e7a49b10051cb60122fcac8909f1a9ed308c12fdc13"
TRACE_PUB = "2c6ba06dde1a1a7dc8c9676a7c38de76c3f2df6268413cc27779bc6eb0c2d7f1"
ISSUER_PUB = "880a6aa8cd1976f69176cb1a095b5deb8449579d253b14003fc14ff9d983ed02"
PEER_PUB = "69a7a6092973975edd92b2a836704a5c90c462825e69a08d20996e795a854d3d"


class PublishedEvidenceFixture(unittest.TestCase):
    def test_signed_packet_matches_pinned_digest(self):
        blob=FILE.read_bytes()
        self.assertEqual(hashlib.sha256(blob).hexdigest(), FILE_SHA256)
        packet=json.loads(blob)
        result=verify_packet(
            packet,trace_public_key=TRACE_PUB,
            trusted_issuer=ISSUER_PUB,peer_public_key=PEER_PUB)
        self.assertTrue(result["verified"])
        self.assertFalse(result["hardware_attested"])
        self.assertFalse(result["independent_custody"])
        self.assertEqual(result["freshness"],
                         "historical-signature-only-not-current")

    def test_modified_manifest_refused(self):
        packet=json.loads(FILE.read_bytes())
        mutated=copy.deepcopy(packet)
        mutated["execution"]["finish_receipt_hash"]="f"*64
        with self.assertRaises(Exception):
            verify_packet(
                mutated,trace_public_key=TRACE_PUB,
                trusted_issuer=ISSUER_PUB,peer_public_key=PEER_PUB)
        self.assertTrue(verify_packet(
            packet,trace_public_key=TRACE_PUB,
            trusted_issuer=ISSUER_PUB,peer_public_key=PEER_PUB)["verified"])
