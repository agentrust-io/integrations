"""The sample manifest was issued by Provenza (an MCP-served agent with one
approved tool). The tests run offline against it."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import agent_manifest._verify as sdk_verify
import cbor2
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import verify_provenza_manifest as v  # noqa: E402

HERE = Path(__file__).resolve().parent
ENVELOPE = (HERE / "agent-1-manifest.cose").read_bytes()
KEYS = json.loads((HERE / "trusted_keys.json").read_text())

# The sample's validity window: issued 2026-11-02T05:12:23Z, expires 2027-01-31T05:12:23Z.
WITHIN = datetime(2026, 12, 1, tzinfo=timezone.utc)
AFTER = datetime(2027, 2, 1, tzinfo=timezone.utc)

ED25519, ML_DSA_65 = -19, -49


@pytest.fixture
def clock(monkeypatch):
    """Fix the time the SDK's verification engine checks the validity window
    against, so a test does not change meaning when the sample expires."""

    def set_now(now: datetime) -> None:
        class Frozen(datetime):
            @classmethod
            def now(cls, tz=None):
                return now if tz is None else now.astimezone(tz)

        monkeypatch.setattr(sdk_verify, "datetime", Frozen)

    return set_now


def _keeping(algorithm: int) -> bytes:
    """The sample envelope with every signer but ``algorithm`` removed. The
    remaining signature is untouched and still verifies on its own: COSE_Sign
    signers do not cover each other."""
    tag = cbor2.loads(ENVELOPE)
    protected, unprotected, payload, signatures = tag.value
    kept = [s for s in signatures if cbor2.loads(s[0])[1] == algorithm]
    assert len(kept) == 1
    return cbor2.dumps(cbor2.CBORTag(tag.tag, [protected, unprotected, payload, kept]), canonical=True)


def _run(tmp_path, envelope: bytes, capsys) -> tuple[int, dict]:
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(KEYS))
    code = v.main([str(path), "--keys", str(keys)])
    return code, json.loads(capsys.readouterr().out)


def test_signatures_catalog_and_profile():
    report = v.check(ENVELOPE, KEYS)
    assert report["signatures_verified"] and report["signers"] == 2
    assert report["algorithms"] == [ML_DSA_65, ED25519] and report["hybrid"] is True
    assert report["missing_signers"] == []
    assert report["catalog_hash_matches"] and report["tools"] == ["files.read"]
    assert report["profile"] == "composition-only"
    assert "system_prompt" in report["unbound_artifacts"] and "policy_bundle" in report["unbound_artifacts"]


def test_verdict_is_incomplete_not_valid(clock):
    # a composition-only manifest authenticates; it never claims to be complete
    clock(WITHIN)
    assert v.check(ENVELOPE, KEYS)["verdict"] == "INCOMPLETE"


@pytest.mark.parametrize("kept, missing", [(ED25519, "ml-dsa-65"), (ML_DSA_65, "ed25519")])
def test_one_signer_is_not_the_hybrid_signature(tmp_path, capsys, clock, kept, missing):
    # The remaining signature verifies against the supplied key and the verdict
    # is unchanged; the envelope is still refused, whichever half is left.
    clock(WITHIN)
    code, report = _run(tmp_path, _keeping(kept), capsys)
    assert report["signatures_verified"] is True and report["signers"] == 1
    assert report["algorithms"] == [kept] and report["verdict"] == "INCOMPLETE"
    assert report["hybrid"] is False and report["missing_signers"] == [missing]
    assert code == 1


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


def test_cli_succeeds_within_the_validity_window(tmp_path, capsys, clock):
    clock(WITHIN)
    code, report = _run(tmp_path, ENVELOPE, capsys)
    assert report["hybrid"] is True and report["verdict"] == "INCOMPLETE"
    assert code == 0


def test_cli_fails_once_expired(tmp_path, capsys, clock):
    clock(AFTER)
    code, report = _run(tmp_path, ENVELOPE, capsys)
    assert report["hybrid"] is True and report["verdict"] == "EXPIRED"
    assert code == 1
