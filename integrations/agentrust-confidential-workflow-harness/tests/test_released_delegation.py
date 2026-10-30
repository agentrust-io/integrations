import unittest
import time
from ca2a_runtime.delegation import (new_keypair, credential_digest,
    RevocationSnapshot, RevocationStatement)
from ca2a_runtime.delegation.credential import DelegationCredential
from harness.released_delegation import appraise


class ReleasedDelegationTests(unittest.TestCase):
    def setUp(self):
        self.root, self.root_pub = new_keypair()
        self.holder, holder_pub = new_keypair()
        self.credential = DelegationCredential(
            "experimental", self.root_pub, holder_pub,
            frozenset({"conduit.inspect"}), 0).sign(self.root)

    def check(self, **kw):
        return appraise(credential=kw.pop("credential", self.credential),
                       holder_private=kw.pop("holder_private", self.holder),
                       trusted_issuer=kw.pop("trusted_issuer", self.root_pub),
                       record_id="live-test", **kw)

    def test_valid_delegation(self):
        self.assertTrue(self.check().granted)

    def test_untrusted_root(self):
        _, other_root = new_keypair()
        self.assertFalse(self.check(trusted_issuer=other_root).granted)
        self.assertTrue(self.check().granted)

    def test_holder_substitution(self):
        other_holder, _ = new_keypair()
        self.assertFalse(self.check(holder_private=other_holder).granted)
        self.assertTrue(self.check().granted)

    def test_ungranted_capability(self):
        self.assertFalse(self.check(capability="conduit.delete").granted)
        self.assertTrue(self.check().granted)

    def test_policy_refusal(self):
        self.assertFalse(self.check(local_capabilities=frozenset()).granted)
        self.assertTrue(self.check().granted)

    def test_unsigned_credential(self):
        c = DelegationCredential("experimental",self.root_pub,
            self.credential.subject,frozenset({"conduit.inspect"}),0)
        self.assertFalse(self.check(credential=c).granted)
        self.assertTrue(self.check().granted)

    def test_signed_revocation_refuses_valid_delegation(self):
        now=int(time.time())
        statement=RevocationStatement(
            credential_digest(self.credential),self.root_pub,now).sign(self.root)
        snapshot=RevocationSnapshot(now,(statement,))
        self.assertFalse(self.check(revocations=snapshot,
            max_revocation_staleness=300).granted)
        self.assertTrue(self.check(revocations=RevocationSnapshot(now),
            max_revocation_staleness=300).granted)

    def test_stale_revocation_snapshot_fails_closed(self):
        now=int(time.time())
        self.assertFalse(self.check(revocations=RevocationSnapshot(now-1000),
            max_revocation_staleness=300).granted)
        self.assertTrue(self.check(revocations=RevocationSnapshot(now),
            max_revocation_staleness=300).granted)
