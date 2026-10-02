from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_DIR))

import delegation_scenario as scenario  # noqa: E402
from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: E402
from ca2a_runtime.delegation.credential import ScopeEscalation  # noqa: E402
from ca2a_runtime.errors import UntrustedDelegationRoot  # noqa: E402


class DelegationScenarioTests(unittest.TestCase):
    def test_valid_chain_verifies(self) -> None:
        chain = scenario.build_credit_chain()
        scenario.verify(chain)  # raises on any violation
        self.assertEqual(len(chain), 3)
        self.assertEqual(sorted(chain[-1].scope), ["read:bureau"])

    def test_each_hop_is_a_subset_of_its_parent(self) -> None:
        chain = scenario.build_credit_chain()
        for parent, child in zip(chain, chain[1:]):
            self.assertTrue(child.scope <= parent.scope, f"{child.scope} not subset of {parent.scope}")

    def test_write_authority_is_never_delegated(self) -> None:
        chain = scenario.build_credit_chain()
        self.assertIn(scenario.CAP_WRITE_REPORT, chain[0].scope)  # granted to the lead
        for child in chain[1:]:
            self.assertNotIn(scenario.CAP_WRITE_REPORT, child.scope)

    def test_continuity_issuer_is_previous_subject(self) -> None:
        chain = scenario.build_credit_chain()
        for parent, child in zip(chain, chain[1:]):
            self.assertEqual(child.issuer, parent.subject)

    def test_escalation_attempt_is_rejected(self) -> None:
        chain = scenario.build_escalation_attempt()
        with self.assertRaises(ScopeEscalation) as ctx:
            scenario.verify(chain)
        self.assertEqual(getattr(ctx.exception, "code", None), "SCOPE_ESCALATION")

    def test_chain_from_an_untrusted_root_is_rejected(self) -> None:
        # Signatures, continuity and attenuation all hold on a chain an
        # attacker mints from a key of their own. Only the root check stops it.
        attacker_priv, attacker_pub = new_keypair()
        _, agent_pub = new_keypair()
        forged = DelegationCredential(
            credential_id="credit-cred-0",
            issuer=attacker_pub,
            subject=agent_pub,
            scope=frozenset({scenario.CAP_WRITE_REPORT}),
            depth=0,
            parent_id=None,
        ).sign(attacker_priv)
        with self.assertRaises(UntrustedDelegationRoot):
            scenario.verify([forged])

    def test_chain_document_shape(self) -> None:
        doc = scenario.as_chain_document(scenario.build_credit_chain())
        self.assertIn("chain", doc)
        self.assertEqual(len(doc["chain"]), 3)
        for hop in doc["chain"]:
            self.assertIn("signature", hop)
            self.assertIn("credential_id", hop)


if __name__ == "__main__":
    unittest.main()
