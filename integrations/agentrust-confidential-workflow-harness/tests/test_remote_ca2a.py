"""Adversarial published-cA2A client/server interoperability and replay tests."""
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ca2a_runtime.delegation import new_keypair

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

    def dispatch(self, agent, repo, transaction_id):
        self.dispatch_count += 1
        return {"transaction_id": transaction_id, "session_id":"session", "start_receipt_hash":"a"*64,
                "finish_receipt_hash":"b"*64,"commit_sha":"a"*40,"exit_code":0}

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
                "peer_public_key": self.peer_pub,"send": self.send,
                "trace_public_key": self.trace.public_key().public_bytes_raw().hex()}
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

    def test_missing_trusted_trace_key_never_dispatches(self):
        self.assertEqual(self.invoke(trace_public_key=None).outcome,
                         "missing-trace-trust-anchor")
        self.assertEqual(self.dispatch_count,0)

    def test_expired_signed_credential_remote_refuses(self):
        result=self.invoke(credential_not_after_offset=-2)
        self.assertEqual(result.outcome,"refused-authenticated-peer")
        self.assertEqual(self.dispatch_count,0)

    def worker(self, agent, action, params):
        from test_conduit_live import receipt
        transaction = params["transaction_id"]
        session = "worker-session"
        start = receipt("job_start", session, transaction_id=transaction)
        if action == "job_start":
            return {"ok": True, "receipt": start, "result": {
                "transaction_id": transaction, "session_id": session,
                "intent": "inspect", "network": False,
                "repo": "/home/ubuntu/src/integrations", "commit_sha": "a" * 40}}
        return {"ok": True, "receipt": receipt(
            "job_poll", session, start["hash"], transaction_id=transaction),
            "result": {"transaction_id": transaction, "session_id": session,
                "running": False, "exit_code": 0, "commit_sha": "a" * 40,
                "commit_sha_end": "a" * 40, "worktree_clean_start": True,
                "worktree_clean_end": True}}

    def test_actual_worker_through_signed_service_and_client(self):
        from unittest.mock import patch
        from harness.remote_peer_service import execute_job
        self.dispatch = execute_job
        with patch("harness.remote_peer_service._agent", side_effect=self.worker) as agent:
            result = self.invoke()
        self.assertEqual(result.outcome, "authenticated-remote-ca2a-software")
        self.assertTrue(result.trace_verified)
        self.assertEqual([c.args[2]["transaction_id"] for c in agent.call_args_list],
                         ["transaction-1", "transaction-1"])

    def test_malformed_worker_never_gains_signed_success(self):
        import hashlib
        from unittest.mock import patch
        from harness.remote_peer_service import execute_job
        self.dispatch = execute_job
        missing = object()
        cases = []
        for action in ("job_start", "job_poll"):
            cases.extend((action, "top", "ok", v)
                         for v in (missing, "false", False, 1, None))
            cases.extend((action, "result", "transaction_id", v)
                         for v in (missing, None, "other-transaction"))
            cases.extend((action, "detail", "transaction_id", v)
                         for v in (missing, None, "other-transaction"))
            cases.extend((action, "result", "session_id", v)
                         for v in (missing, None, ""))
        cases.extend(("job_start", "result", "commit_sha", v)
                     for v in (missing, None, "abc", "A" * 40, "g" * 40))
        cases.extend(("job_poll", "result", "running", v)
                     for v in (missing, None, 0, "false", "", [], {}))
        cases.extend(("job_poll", "result", "exit_code", v)
                     for v in (missing, False, 0.0, "0", None, 1))
        for action, location, field, value in cases:
            def worker(agent, requested, params):
                response = self.worker(agent, requested, params)
                if requested == action:
                    target = (response if location == "top" else
                              response["receipt"]["detail"] if location == "detail"
                              else response["result"])
                    if value is missing:
                        target.pop(field, None)
                    else:
                        target[field] = value
                    if field == "session_id" and location == "result":
                        response["receipt"]["detail"][field] = target.get(field)
                    record = response["receipt"]
                    record["hash"] = hashlib.sha256(json.dumps(
                        {k: v for k, v in record.items() if k != "hash"},
                        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                return response
            with self.subTest(action=action, location=location, field=field, value=value):
                with patch("harness.remote_peer_service._agent", side_effect=worker):
                    result = self.invoke()
                self.assertEqual(result.outcome, "unknown-authenticated-execution")
                self.assertFalse(result.trace_verified)
                self.assertIsNone(result.finish_receipt_hash)
        with patch("harness.remote_peer_service._agent", side_effect=self.worker):
            self.assertEqual(self.invoke().outcome, "authenticated-remote-ca2a-software")

    def test_client_refuses_malformed_signed_execution(self):
        original = self.dispatch
        for field, value in (("exit_code", False), ("exit_code", 0.0),
                             ("session_id", None), ("session_id", ""),
                             ("commit_sha", "abc"), ("commit_sha", "A" * 40),
                             ("transaction_id", "other-transaction")):
            def dispatch(agent, repo, transaction_id):
                observed = original(agent, repo, transaction_id)
                observed[field] = value
                return observed
            self.dispatch = dispatch
            with self.subTest(field=field, value=value):
                self.assertIn(self.invoke().outcome,
                              {"refused-output-binding", "unknown-authenticated-execution"})

    def test_receipts_from_other_transaction_are_refused(self):
        from unittest.mock import patch
        from harness.remote_peer_service import execute_job
        self.dispatch = execute_job
        def stale(agent, action, params):
            return self.worker(agent, action, {**params, "transaction_id": "transaction-1"})
        with patch("harness.remote_peer_service._agent", side_effect=stale):
            self.assertEqual(self.invoke().outcome, "authenticated-remote-ca2a-software")
            result = self.invoke(transaction_id="transaction-2")
        self.assertEqual(result.outcome, "unknown-authenticated-execution")
        self.assertFalse(result.trace_verified)
