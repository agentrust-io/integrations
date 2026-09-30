"""The incident-report signature must need Sentinel's key to produce.

It used to be sha256(payload) + b"signed", which anyone could recompute, so
/verify accepted a forged report as VERIFIED.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from sentinel.server import app, hash_payload, sign_payload


@pytest.fixture
def client(monkeypatch):
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    monkeypatch.setenv("TRACE_PRIVATE_KEY_PEM", pem)
    return TestClient(app)


def _report(sign) -> dict:
    body = {"agent_id": "a1", "detection_type": "tool_drift", "risk_score": 0.9, "incident_id": "INC-1"}
    return dict(
        body,
        claim_hash=hash_payload({"claim_id": "c1", "agent_id": "a1", "detection_type": "tool_drift", "risk_score": 0.9}),
        incident_hash=hash_payload(body),
        signature=sign(body),
    )


def _keyless(payload: dict) -> str:
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest()
    return base64.b64encode(digest + b"signed").decode()


def test_report_signed_by_sentinel_verifies(client):
    r = client.post("/verify/c1", json={"report": _report(sign_payload)}).json()
    assert r["status"] == "VERIFIED"


def test_keyless_forgery_is_tampered(client):
    r = client.post("/verify/c1", json={"report": _report(_keyless)}).json()
    assert r["status"] == "TAMPERED"
    assert r["details"]["signature_valid"] is False


def test_report_signed_by_another_key_is_tampered(client):
    other = Ed25519PrivateKey.generate()
    forged = _report(lambda p: base64.b64encode(other.sign(json.dumps(p, sort_keys=True).encode())).decode())
    assert client.post("/verify/c1", json={"report": forged}).json()["status"] == "TAMPERED"


def test_edited_report_is_tampered(client):
    report = _report(sign_payload)
    report["risk_score"] = 0.1
    assert client.post("/verify/c1", json={"report": report}).json()["status"] == "TAMPERED"


def test_signing_without_a_key_fails_closed(monkeypatch):
    monkeypatch.delenv("TRACE_PRIVATE_KEY_PEM", raising=False)
    with pytest.raises(RuntimeError):
        sign_payload({"x": 1})
