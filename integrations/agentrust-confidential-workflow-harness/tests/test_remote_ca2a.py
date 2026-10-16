"""Adversarial published-cA2A client/server interoperability and replay tests."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ca2a_runtime.delegation import new_keypair
from ca2a_runtime.response import encode

from harness.remote_peer_client import run
from harness.remote_peer_service import serve


class RemoteCA2ATests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "replay.sqlite"
        self.issuer, self.issuer_pub = new_keypair()
        self.holder, self.holder_pub = new_keypair()
        self.trace = Ed25519PrivateKey.generate()
        self.peer = X25519PrivateKey.generate()
        self.peer_pub = self.peer.public_key().public_bytes_raw().hex()
        self.secret = b"secret-for-test-only-" + bytes(range(32))
        self.dispatch_count = 0
        self.calls = []
        self.last_submit = None

    def dispatch(self, agent, repo):
        self.dispatch_count += 1
        return {"session_id":"session", "start_receipt_hash":"a"*64,
                "finish_receipt_hash":"b"*64,"commit_sha":"abc","exit_code":0}

    def send(self, request):
        self.calls.append(request["method"])
        if request["method"] == "execute":
            self.last_submit = json.loads(json.dumps(request))
        return serve(request, channel_private=self.peer,
                     challenge_secret=self.secret, trusted_issuer=self.issuer_pub,
                     replay_db=self.db, dispatch=self.dispatch,
                     trace_private=self.trace)

    def invoke(self, **kw):
        args = {"transaction_id": "transaction-1", "nonce": "0123456789abcdef",
                "repo": "/home/ubuntu/src/integrations",
                "issuer_private": self.issuer,"holder_private": self.holder,
                "peer_public_key": self.peer_pub,"send": self.send}
        args.update(kw)
        return run(**args)

    def test_real_library_roundtrip(self):
        r=self.invoke()
        self.assertEqual(r.outcome,"authenticated-remote-ca2a-software")
        self.assertTrue(r.remote_ca2a_verified)
        self.assertEqual(self.dispatch_count,1)
        self.assertEqual(self.calls,["challenge","execute"])

    def test_cmcp_refusal_before_network(self):
        self.assertEqual(self.invoke(permitted=False).outcome,"refused-cmcp")
        self.assertEqual(self.calls,[])
        self.assertEqual(self.dispatch_count,0)

    def test_untrusted_root_no_dispatch(self):
        attacker,_=new_keypair()
        self.assertEqual(self.invoke(issuer_private=attacker).outcome,
                         "refused-authenticated-peer")
        self.assertEqual(self.dispatch_count,0)

    def test_authenticated_response_mutation(self):
        def tamper(request):
            result=self.send(request)
            if request["method"]=="execute":
                result["envelope"]["body"]["nonce"]="bad-nonce"
            return result
        self.assertNotEqual(self.invoke(send=tamper).outcome,
                            "authenticated-remote-ca2a-software")

    def test_substituted_credential_scope_no_dispatch(self):
        def tamper(request):
            if request["method"]=="execute":
                request["credential"]["scope"]=["conduit.delete"]
            return self.send(request)
        self.assertEqual(self.invoke(send=tamper).outcome,"refused-authenticated-peer")
        self.assertEqual(self.dispatch_count,0)

    def test_substituted_envelope_no_dispatch(self):
        def tamper(request):
            if request["method"]=="execute":
                request["envelope"]["request"]["nonce"]="substituted"
            return self.send(request)
        self.assertNotEqual(self.invoke(send=tamper).outcome,
                            "authenticated-remote-ca2a-software")
        self.assertEqual(self.dispatch_count,0)

    def test_stale_or_wrong_peer_identity(self):
        wrong=X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        self.assertEqual(self.invoke(peer_public_key=wrong).outcome,
                         "refused-peer-identity")
        self.assertEqual(self.dispatch_count,0)

    def test_one_time_replay_is_refused(self):
        self.assertEqual(self.invoke().outcome,"authenticated-remote-ca2a-software")
        self.assertEqual(self.dispatch_count,1)
        replay=self.send(self.last_submit)
        self.assertEqual(replay["status"],403)
        self.assertEqual(self.dispatch_count,1)

    def test_unobserved_delivery_remains_unknown(self):
        def lose(request):
            if request["method"]=="execute":
                raise RuntimeError("transport-lost")
            return self.send(request)
        self.assertEqual(self.invoke(send=lose).outcome,"unknown-or-refused-transport")
        self.assertEqual(self.dispatch_count,0)

    def test_real_trace_signed_record(self):
        pub=self.trace.public_key().public_bytes_raw().hex()
        result=self.invoke(trace_public_key=pub)
        self.assertEqual(result.outcome,"authenticated-remote-ca2a-software")
        self.assertTrue(result.trace_verified)
        self.assertTrue(result.trace_record_hash.startswith("sha256:"))

    def test_untrusted_trace_issuer_refused(self):
        wrong=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        result=self.invoke(trace_public_key=wrong)
        self.assertEqual(result.outcome,"untrusted-trace-evidence")
        self.assertTrue(result.remote_ca2a_verified)
        self.assertFalse(result.trace_verified)
