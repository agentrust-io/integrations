"""Offline TRACE signature/manifest acceptance and paired mutation twins."""
import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness.replay_export import make_packet, verify_packet
from harness.trace_live_binding import sign_bundle


class ReplayExportTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.key.public_key().public_bytes_raw().hex()
        self.issuer="ab"*32
        self.peer="cd"*32
        self.execution={
            "session_id":"lab-session","start_receipt_hash":"1"*64,
            "finish_receipt_hash":"2"*64,"commit_sha":"abc","exit_code":0}
        bundle=sign_bundle(
            key=self.key,transaction_id="test-transaction",
            nonce="fixture-nonce",request_sha256="3"*64,
            execution=self.execution,repo="/home/ubuntu/src/integrations",
            trusted_issuer=self.issuer)
        self.packet=make_packet(
            transaction_id="test-transaction",nonce="fixture-nonce",
            request_sha256="3"*64,repo="/home/ubuntu/src/integrations",
            peer_public_key=self.peer,trusted_issuer=self.issuer,
            trace_bundle=bundle,execution=self.execution)

    def verify(self, packet=None, **kwargs):
        config={"trace_public_key":self.pub,"trusted_issuer":self.issuer,
                "peer_public_key":self.peer}
        config.update(kwargs)
        return verify_packet(packet if packet is not None else self.packet,**config)

    def assert_refuses_with_twin(self, modified):
        with self.assertRaises(Exception):
            self.verify(modified)
        self.assertTrue(self.verify()["verified"])

    def test_valid_signed_packet(self):
        result=self.verify()
        self.assertTrue(result["verified"])
        self.assertFalse(result["hardware_attested"])
        self.assertFalse(result["independent_custody"])
        self.assertEqual(result["origin_response_authentication"],
                         "not-offline-replayable")

    def test_modified_result_digest(self):
        p=copy.deepcopy(self.packet)
        p["execution"]["finish_receipt_hash"]="4"*64
        self.assert_refuses_with_twin(p)

    def test_wrong_signer(self):
        other=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        with self.assertRaises(Exception):
            self.verify(trace_public_key=other)
        self.assertTrue(self.verify()["verified"])

    def test_wrong_issuer_pin(self):
        with self.assertRaises(Exception):
            self.verify(trusted_issuer="ee"*32)
        self.assertTrue(self.verify()["verified"])

    def test_wrong_peer_pin(self):
        with self.assertRaises(Exception):
            self.verify(peer_public_key="ee"*32)
        self.assertTrue(self.verify()["verified"])

    def test_modified_request_identity(self):
        p=copy.deepcopy(self.packet)
        p["request_sha256"]="9"*64
        self.assert_refuses_with_twin(p)

    def test_modified_trace_record(self):
        p=copy.deepcopy(self.packet)
        p["trace_bundle"]["record"]["model"]["model_id"]="injected"
        self.assert_refuses_with_twin(p)

    def test_modified_trace_signature(self):
        p=copy.deepcopy(self.packet)
        p["trace_bundle"]["signature"]="00"*64
        self.assert_refuses_with_twin(p)

    def test_missing_field(self):
        p=copy.deepcopy(self.packet)
        del p["trace_bundle"]
        self.assert_refuses_with_twin(p)
