"""The sample manifest was issued by Provenza (an MCP-served agent with one
approved tool). The tests run offline against it."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import cbor2
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import verify_provenza_manifest as v  # noqa: E402

HERE = Path(__file__).resolve().parent
ENVELOPE = (HERE / "agent-1-manifest.cose").read_bytes()
KEYS = json.loads((HERE / "trusted_keys.json").read_text())


def test_signatures_catalog_and_profile():
    report = v.check(ENVELOPE, KEYS)
    assert report["signatures_verified"] and report["signers"] == 2  # Ed25519 + ML-DSA-65
    assert report["catalog_hash_matches"] and report["tools"] == ["files.read"]
    assert report["profile"] == "composition-only"
    assert "system_prompt" in report["unbound_artifacts"] and "policy_bundle" in report["unbound_artifacts"]


def test_verdict_is_incomplete_not_valid():
    # a composition-only manifest authenticates; it never claims to be complete.
    # (After expires_at the engine reports the expiry instead.)
    report = v.check(ENVELOPE, KEYS)
    assert report["verdict"] in ("INCOMPLETE", "EXPIRED")


def test_a_changed_payload_fails():
    tag = cbor2.loads(ENVELOPE)
    parts = list(tag.value)
    parts[2] = parts[2].replace(b"files.read", b"files.rm!!")
    forged = cbor2.dumps(cbor2.CBORTag(tag.tag, parts), canonical=True)
    with pytest.raises(Exception):
        v.check(forged, KEYS)


def test_unknown_keys_fail():
    with pytest.raises(Exception):
        v.check(ENVELOPE, {"00" * 32: "AAAA"})


def test_cli_exit_codes(tmp_path, capsys):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(KEYS))
    assert v.main([str(HERE / "agent-1-manifest.cose"), "--keys", str(keys)]) in (0, 1)
    out = json.loads(capsys.readouterr().out)
    assert out["signatures_verified"] is True
