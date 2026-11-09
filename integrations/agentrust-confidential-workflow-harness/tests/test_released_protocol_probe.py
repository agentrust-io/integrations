import unittest
from harness.released_protocol_probe import probe
GOOD = dict(transaction_id="test-txn", subject="test-subject", tool_name="inspect",
            allowed_tools=("inspect",), policy_digest="sha256:"+"a"*64, nonce="test-nonce")
class ReleasedProtocolTests(unittest.TestCase):
    def test_positive_uses_published_apis_and_does_not_dispatch(self):
        result=probe(**GOOD)
        self.assertTrue(result.admitted, result.reason)
        self.assertEqual(len(result.hashes),2)
        self.assertNotEqual(*result.hashes)
        self.assertEqual(result.actual_dispatches,0)
        self.assertEqual(result.evidence_class,"synthetic")
    def test_disallowed_tool_refused(self):
        result=probe(**{**GOOD,"allowed_tools":("different",)})
        self.assertFalse(result.admitted)
        self.assertFalse(result.hashes)
    def test_missing_or_corrupted_context_refused(self):
        for overrides in ({"transaction_id":""},{"nonce":""},{"policy_digest":"invalid"},{"policy_digest":"sha256:"+"z"*64}):
            with self.subTest(overrides=overrides):
                result=probe(**{**GOOD,**overrides})
                self.assertFalse(result.admitted)
                self.assertFalse(result.hashes)
