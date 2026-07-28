"""TRACE v0.2 Level 0 conformance for Agent Sentinel's emitted records.

Runs the agentrust-trace-tests Level 0 suite (TR-ENV, TR-SIG, TR-POL) against
records produced by the signed claim generator, plus a signature round-trip.
"""

import json
import os
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import jwt as pyjwt
from sentinel.trace_claim_generator import TraceClaimGenerator, private_key_to_jwk

trace_loader = pytest.importorskip("trace_tests.loader")
trace_runner = pytest.importorskip("trace_tests.runner")
load_record = trace_loader.load_record
trace_run = trace_runner.run


ENFORCE_EVENT = {
    "event_id": "enforce-trace-001",
    "event_type": "ENFORCEMENT",
    "detection": {"detection_type": "delegation_escalation", "risk_score": 0.9},
    "input": {"agent_id": "alice", "delegation_chain": ["root", "admin", "finance"]},
}


@pytest.fixture
def generator():
    # Deterministic in-test key; no dependency on the environment.
    return TraceClaimGenerator(signing_key=Ed25519PrivateKey.generate())


def _run_level0(payload: dict) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(payload, f)
        fname = f.name
    try:
        record, fmt = load_record(fname)
        return trace_run(record, fmt, level=0)
    finally:
        os.unlink(fname)


class TestLevel0Conformance:
    def _assert_no_failures(self, results: dict) -> None:
        failures = [f for findings in results.values() for f in findings if f.failed()]
        assert not failures, f"Level 0 failures: {[f.message for f in failures]}"

    def test_deny_payload_passes_level0(self, generator):
        payload = generator.build_payload(ENFORCE_EVENT, agent_id="alice", decision="DENY")
        self._assert_no_failures(_run_level0(payload))

    def test_admit_payload_passes_level0(self, generator):
        payload = generator.build_payload(ENFORCE_EVENT, agent_id="bob", decision="ADMIT")
        self._assert_no_failures(_run_level0(payload))


class TestSigning:
    def test_claim_is_required_to_be_signed(self, monkeypatch):
        # With no key and no env var, generation fails closed instead of
        # emitting an unsigned record.
        monkeypatch.delenv("TRACE_PRIVATE_KEY_PEM", raising=False)
        with pytest.raises(RuntimeError):
            TraceClaimGenerator().generate_claim(ENFORCE_EVENT)

    def test_signature_verifies_against_cnf_jwk(self, generator):
        claim = generator.generate_claim(ENFORCE_EVENT, agent_id="alice", decision="DENY")
        public_key = generator._key().public_key()
        decoded = pyjwt.decode(claim.token, public_key, algorithms=["EdDSA"])
        assert decoded["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2"
        assert decoded["appraisal"]["status"] == "contraindicated"
        assert decoded["cnf"]["jwk"] == private_key_to_jwk(generator._key())
