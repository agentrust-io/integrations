import unittest
from harness.authenticated_exchange import exchange

GOOD = {"transaction_id": "test-transaction", "nonce": "nonce-01"}
class AuthenticatedExchangeTests(unittest.TestCase):
    def test_valid_authenticated_response_has_no_live_dispatch(self):
        result = exchange(**GOOD)
        self.assertEqual(result.outcome, "authenticated-process-local")
        self.assertEqual(result.actual_dispatches, 0)
        self.assertTrue(result.request_sha256)
    def test_disallowed_tool_refused(self):
        self.assertEqual(exchange(**GOOD,allowed=False).outcome,"refused-authorization")
    def test_tamper_refused(self):
        self.assertEqual(exchange(**GOOD,tamper=True).outcome,"refused-response-authentication")
    def test_authenticated_refusal(self):
        self.assertEqual(exchange(**GOOD,refusal=True).outcome,"refused-authenticated")
    def test_replay_refused(self):
        self.assertEqual(exchange(**GOOD,replay=True).outcome,"refused-replay")
    def test_timeout_refused(self):
        self.assertEqual(exchange(**GOOD,expired=True).outcome,"refused-response-authentication")
    def test_missing_receipt_remains_unknown(self):
        self.assertEqual(exchange(**GOOD,missing_receipt=True).outcome,"unknown-unobserved-delivery")
    def test_response_binding_mismatch_refused(self):
        self.assertEqual(exchange(**GOOD,binding_mismatch=True).outcome,"refused-response-binding")
    def test_valid_twin_independent_of_each_negative(self):
        for opt in ("tamper","replay","expired","refusal","binding_mismatch","missing_receipt"):
            with self.subTest(opt=opt):
                self.assertNotEqual(exchange(**GOOD, **{opt:True}).outcome, "authenticated-process-local")
                self.assertEqual(exchange(**GOOD).outcome,"authenticated-process-local")
