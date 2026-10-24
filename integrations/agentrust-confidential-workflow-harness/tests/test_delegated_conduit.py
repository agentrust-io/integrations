import tempfile
import unittest
from pathlib import Path

from ca2a_runtime.delegation import new_keypair
from ca2a_runtime.delegation.credential import DelegationCredential
from harness.delegated_conduit import run
from test_conduit_live import receipt


class DelegatedConduitTests(unittest.TestCase):
    def setUp(self):
        root, self.root_pub = new_keypair()
        self.holder, pub = new_keypair()
        self.credential = DelegationCredential(
            "test-delegation", self.root_pub, pub,
            frozenset({"conduit.inspect"}), 0).sign(root)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cli = str(Path(tmp.name) / "conduit")
        Path(self.cli).touch()
        self.calls = []
        self.start = receipt("job_start", "session")
        self.finish = receipt("job_poll", "session", self.start["hash"])

    def transport(self, cli, action, params):
        self.calls.append(action)
        if action == "job_start":
            return {"ok": True, "receipt": self.start,
                    "result": {"session_id": "session", "intent": "inspect",
                               "network": False, "commit_sha": "abc",
                               "repo": "/home/ubuntu/src/integrations"}}
        return {"ok": True, "receipt": self.finish,
                "result": {"session_id": "session", "running": False,
                           "exit_code": 0, "commit_sha": "abc",
                           "commit_sha_end": "abc",
                           "worktree_clean_start": True,
                           "worktree_clean_end": True}}

    def invoke(self, **override):
        kw = dict(transaction_id="test-id", repo="/home/ubuntu/src/integrations",
                  cli=self.cli, credential=self.credential, holder_private=self.holder,
                  trusted_issuer=self.root_pub, transport=self.transport)
        kw.update(override)
        return run(**kw)

    def test_positive_composed_software(self):
        result = self.invoke()
        self.assertEqual(result.outcome, "observed-live-conduit-inspect")
        self.assertEqual(self.calls, ["job_start", "job_poll"])
        self.assertFalse(result.ca2a_peer_transport)
        self.assertFalse(result.trace_verification)

    def test_untrusted_root_never_dispatches(self):
        _, other_root = new_keypair()
        self.assertEqual(self.invoke(trusted_issuer=other_root).outcome,
                         "refused-ca2a-delegation")
        self.assertEqual(self.calls, [])

    def test_wrong_holder_never_dispatches(self):
        attacker, _ = new_keypair()
        self.assertEqual(self.invoke(holder_private=attacker).outcome,
                         "refused-ca2a-delegation")
        self.assertEqual(self.calls, [])

    def test_modified_scope_never_dispatches(self):
        bad = DelegationCredential(
            "test-delegation", self.root_pub, self.credential.subject,
            frozenset({"conduit.delete"}), 0, signature=self.credential.signature)
        self.assertEqual(self.invoke(credential=bad).outcome,
                         "refused-ca2a-delegation")
        self.assertEqual(self.calls, [])
