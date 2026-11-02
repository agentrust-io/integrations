"""Keep status observations and signed channel attribution claims explicit."""
import copy
import unittest

import test_replay_export as replay_fixture
from run_remote_ca2a_matrix import exact_replay_observation


class ReplayReportingTests(unittest.TestCase):
    def test_forged_mac_cannot_be_labelled_authenticated(self):
        observation = exact_replay_observation({
            "status": 403, "envelope": {"mac": "forged"}})
        self.assertTrue(observation["passed"])
        self.assertEqual(observation["observed"], "observed-status-403")
        self.assertEqual(observation["response_authentication"], "not-verified")

    def test_absent_or_other_status_is_not_a_denial_observation(self):
        for response in (None, {}, {"status": 200}, {"status": "403"}):
            with self.subTest(response=response):
                self.assertFalse(exact_replay_observation(response)["passed"])

    def test_relabelled_unsigned_peer_is_reported_as_metadata(self):
        fixture = replay_fixture.ReplayExportTests()
        fixture.setUp()
        packet = copy.deepcopy(fixture.packet)
        packet["peer_public_key"] = "ee" * 32
        result = fixture.verify(packet, peer_public_key="ee" * 32)
        self.assertTrue(result["verified"])
        self.assertEqual(result["peer_channel_binding"], "metadata-only-not-signed")
        with self.assertRaises(ValueError):
            fixture.verify(packet)  # Original pin still rejects inconsistent metadata.
        self.assertTrue(fixture.verify()["verified"])
