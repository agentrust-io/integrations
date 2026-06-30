"""Security tests for Sentinel hardening.

Covers:
1. Keyed incident signatures (HMAC-SHA256) verify; tampering or a wrong key
   fails; signing with no key set fails closed.
2. The trace verification gate: unsigned / invalid traces are rejected by
   ingest (not scored); a properly-signed trace is accepted.
3. The dashboard render path HTML-escapes a <script>-bearing field.
"""

import base64
import importlib
import json
import os
from pathlib import Path

import pytest

from src import signing
from src.signing import SigningKeyMissing
from src import trace_verification
from src.trace_verification import TraceVerificationError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


# --------------------------------------------------------------------------- #
# Fix 1: keyed incident signatures
# --------------------------------------------------------------------------- #

def test_incident_signature_round_trip(monkeypatch):
    monkeypatch.setenv(signing.SIGNING_KEY_ENV, "key-K")
    payload = {"incident_id": "INC-1", "risk_score": 0.9}
    sig = signing.sign_payload(payload)
    assert signing.verify_payload(payload, sig) is True


def test_incident_signature_detects_tampering(monkeypatch):
    monkeypatch.setenv(signing.SIGNING_KEY_ENV, "key-K")
    payload = {"incident_id": "INC-1", "risk_score": 0.9}
    sig = signing.sign_payload(payload)
    tampered = {"incident_id": "INC-1", "risk_score": 0.1}
    assert signing.verify_payload(tampered, sig) is False


def test_incident_signature_wrong_key_fails(monkeypatch):
    monkeypatch.setenv(signing.SIGNING_KEY_ENV, "key-K")
    payload = {"incident_id": "INC-1"}
    sig = signing.sign_payload(payload)
    # Re-sign with a different key.
    monkeypatch.setenv(signing.SIGNING_KEY_ENV, "key-WRONG")
    assert signing.verify_payload(payload, sig) is False


def test_signing_fails_closed_with_no_key(monkeypatch):
    monkeypatch.delenv(signing.SIGNING_KEY_ENV, raising=False)
    assert signing.is_signing_configured() is False
    with pytest.raises(SigningKeyMissing):
        signing.sign_payload({"incident_id": "INC-1"})
    # Verification also fails closed (never accepts when no key is set).
    assert signing.verify_payload({"incident_id": "INC-1"}, "anything") is False


def test_signature_is_not_the_old_public_hash(monkeypatch):
    """Guard against regressing to base64(sha256+b'signed'), a keyless value."""
    import hashlib

    monkeypatch.setenv(signing.SIGNING_KEY_ENV, "key-K")
    payload = {"incident_id": "INC-1"}
    sig = signing.sign_payload(payload)
    legacy = base64.b64encode(
        hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest() + b"signed"
    ).decode()
    assert sig != legacy


# --------------------------------------------------------------------------- #
# Fix 2: trace verification gate
# --------------------------------------------------------------------------- #

def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return priv, {"kty": "OKP", "crv": "Ed25519", "x": x}


def _sign_trace(record, priv):
    body = json.dumps(
        {k: v for k, v in record.items() if k != "signature"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    sig = base64.urlsafe_b64encode(priv.sign(body)).rstrip(b"=").decode()
    return {**record, "signature": sig}


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv(trace_verification.TRUSTED_JWK_ENV, raising=False)
    monkeypatch.delenv(trace_verification.ALLOW_UNVERIFIED_ENV, raising=False)


def test_unsigned_trace_rejected(clean_env, monkeypatch):
    _priv, jwk = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk))
    with pytest.raises(TraceVerificationError):
        trace_verification.verify_trace({"agent_id": "evil", "tool_calls": []})


def test_signed_trace_accepted(clean_env, monkeypatch):
    priv, jwk = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk))
    signed = _sign_trace({"agent_id": "alice", "tool_calls": []}, priv)
    # Should not raise.
    trace_verification.verify_trace(signed)


def test_trace_signed_by_wrong_key_rejected(clean_env, monkeypatch):
    priv_attacker, _ = _make_keypair()
    _priv_trusted, jwk_trusted = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk_trusted))
    signed = _sign_trace({"agent_id": "alice"}, priv_attacker)
    with pytest.raises(TraceVerificationError):
        trace_verification.verify_trace(signed)


def test_no_trusted_key_rejects(clean_env):
    with pytest.raises(TraceVerificationError):
        trace_verification.verify_trace({"agent_id": "alice", "signature": "x"})


def test_allow_unverified_opt_out(clean_env, monkeypatch, caplog):
    monkeypatch.setenv(trace_verification.ALLOW_UNVERIFIED_ENV, "1")
    import logging
    with caplog.at_level(logging.WARNING):
        trace_verification.verify_trace({"agent_id": "alice"})  # no raise
    assert any("SKIPPING trace verification" in r.message for r in caplog.records)


def test_ingest_rejects_unsigned_trace(clean_env, monkeypatch, tmp_path):
    priv, jwk = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk))
    from src.trace_ingester import ingest_trace
    trace = {"trace_id": "t1", "steps": [{"agent_id": "a", "tool_calls": []}]}
    p = tmp_path / "unsigned.json"
    p.write_text(json.dumps(trace))
    with pytest.raises(TraceVerificationError):
        ingest_trace(str(p))


def test_ingest_accepts_signed_trace(clean_env, monkeypatch, tmp_path):
    priv, jwk = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk))
    from src.trace_ingester import ingest_trace
    trace = {"trace_id": "t1", "steps": [{"agent_id": "a", "tool_calls": []}]}
    signed = _sign_trace(trace, priv)
    p = tmp_path / "signed.json"
    p.write_text(json.dumps(signed))
    out = ingest_trace(str(p))  # should score without raising
    assert hasattr(out, "risk_score")


def test_evaluate_endpoint_rejects_unsigned(clean_env, monkeypatch):
    from fastapi.testclient import TestClient
    _priv, jwk = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk))
    from src import server
    client = TestClient(server.app)
    resp = client.post("/evaluate", json={"agents": [{"agent_id": "evil"}]})
    assert resp.status_code == 403
    assert "verification failed" in resp.json()["error"].lower()


def test_evaluate_endpoint_accepts_signed(clean_env, monkeypatch):
    from fastapi.testclient import TestClient
    priv, jwk = _make_keypair()
    monkeypatch.setenv(trace_verification.TRUSTED_JWK_ENV, json.dumps(jwk))
    from src import server
    client = TestClient(server.app)
    signed = _sign_trace({"agent_id": "alice", "tool_calls": []}, priv)
    resp = client.post("/evaluate", json={"agents": [signed]})
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# Fix 1 + endpoint: incident export / verify fail closed and verify keyed sig
# --------------------------------------------------------------------------- #

def test_export_incident_marks_unsigned_without_key(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.delenv(signing.SIGNING_KEY_ENV, raising=False)
    from src import server
    client = TestClient(server.app)
    resp = client.post("/export/incident/claim-1", json={"agent_id": "a", "detection_type": "tool_drift", "risk_score": 0.5, "risk_level": "high"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["signature_status"] == "unsigned"
    assert body["signature"] is None


def test_verify_endpoint_round_trip_with_key(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv(signing.SIGNING_KEY_ENV, "key-K")
    from src import server
    client = TestClient(server.app)
    exp = client.post("/export/incident/claim-1", json={"agent_id": "a", "detection_type": "tool_drift", "risk_score": 0.5, "risk_level": "high"})
    report = exp.json()
    assert report["signature_status"] == "signed"
    ver = client.post("/verify/claim-1", json={"report": report})
    assert ver.json()["status"] == "VERIFIED"
    # Tamper and re-verify.
    report["risk_score"] = 0.01
    ver2 = client.post("/verify/claim-1", json={"report": report})
    assert ver2.json()["status"] == "TAMPERED"


def test_verify_endpoint_unverifiable_without_key(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.delenv(signing.SIGNING_KEY_ENV, raising=False)
    from src import server
    client = TestClient(server.app)
    ver = client.post("/verify/claim-1", json={"report": {"agent_id": "a"}})
    assert ver.json()["status"] == "UNVERIFIABLE"


# --------------------------------------------------------------------------- #
# Fix 3: dashboard render path escapes a <script>-bearing field
# --------------------------------------------------------------------------- #

def test_dashboard_escapes_untrusted_fields():
    """The client render path runs `esc()` over every trace-derived field
    before inserting it into innerHTML, and carries untrusted values on
    data-* attributes read by addEventListener instead of inline on* handlers.

    There is no JS test harness in this repo, so this asserts the source-level
    invariants that make a <script>-bearing agent_id / reason inert:
      * an esc() helper exists that encodes < > & " ',
      * the claim render template escapes claim_id / agent_id / reason /
        detection_type,
      * no inline onclick carries an interpolated claim/agent value.
    """
    html = (Path(__file__).resolve().parent.parent / "src" / "templates" / "dashboard.html").read_text(encoding="utf-8")

    # esc() helper present and encodes the dangerous characters.
    assert "function esc(" in html
    for token in ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"]:
        assert token in html

    # Trace-derived fields are escaped in the claim render path.
    assert "${esc(claim.claim_id)}" in html
    assert "${esc(claim.agent_id)}" in html
    assert "${esc(claim.reason)}" in html
    assert "${esc(claim.detection_type" in html
    assert "${esc(event.description)}" in html

    # No inline onclick interpolates an untrusted claim/agent value.
    assert "onclick=\"enforceClaim(" not in html
    assert "onclick=\"exportIncident(" not in html
    assert "onclick=\"verifyIncident(" not in html
    assert "onclick=\"exportReceipt(" not in html

    # Listeners are attached programmatically instead.
    assert "addEventListener('click'" in html
    assert "data-action=" in html
