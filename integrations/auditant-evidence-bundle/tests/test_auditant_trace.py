from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import generate_key, sign_record, verify_record

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

import auditant_trace as at  # noqa: E402
import make_demo_bundle  # noqa: E402


@pytest.fixture()
def bundle_bytes(tmp_path: Path) -> bytes:
    return make_demo_bundle.build(tmp_path / "bundle.json").read_bytes()


def _record(raw: bytes, **kw):
    kw.setdefault("enforcement_mode", "declared")
    kw.setdefault("data_class", "internal")
    return at.build_trust_record(raw, **kw)


def test_demo_bundle_verifies(bundle_bytes: bytes) -> None:
    check = at.check_bundle(json.loads(bundle_bytes))
    assert check.ok, check.reasons
    assert check.anchored_through_size == check.events == 6


def test_record_is_valid_signed_level0(bundle_bytes: bytes) -> None:
    key = generate_key()
    signed = sign_record(_record(bundle_bytes), key)
    TrustRecord.model_validate(signed)
    verify_record(signed, key.public_key())
    assert signed["runtime"]["platform"] == "software-only"
    assert signed["origin"]["kind"] == "log-import"
    assert signed["appraisal"]["status"] == "none"
    assert signed["subject"] == "spiffe://auditant.dev/demo_org/dev"


def test_transcript_hash_is_the_bundle_bytes(bundle_bytes: bytes) -> None:
    record = _record(bundle_bytes)
    assert record["tool_transcript"]["hash"] == "sha256:" + hashlib.sha256(bundle_bytes).hexdigest()
    assert record["tool_transcript"]["call_count"] == 2


def test_model_taken_from_the_bundle(bundle_bytes: bytes) -> None:
    assert _record(bundle_bytes)["model"] == {"provider": "demo-provider", "model_id": "demo-model"}


def test_enforcement_mode_has_no_default(bundle_bytes: bytes) -> None:
    with pytest.raises(TypeError):
        at.build_trust_record(bundle_bytes, data_class="internal")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        _record(bundle_bytes, enforcement_mode="strict")


def _mutate(raw: bytes, fn) -> bytes:
    bundle = json.loads(raw)
    fn(bundle)
    return json.dumps(bundle).encode()


@pytest.mark.parametrize(
    "name,fn,needle",
    [
        ("edited event", lambda b: b["events"][2].update(outcome="error"), "content altered at 2"),
        ("deleted event", lambda b: b["events"].pop(3), "sequence gap"),
        ("reordered", lambda b: b["events"].reverse(), "sequence gap"),
        ("truncated", lambda b: b["events"].pop(), "no verified checkpoint covers"),
        (
            "forged signature",
            lambda b: b["checkpoints"][0].update(signature=b["checkpoints"][0]["signature"][:-8] + "AAAAAAA="),
            "signature does not verify",
        ),
        ("missing key", lambda b: b.update(publicKeys=[]), "no public key"),
        ("unknown format", lambda b: b.update(bundleVersion="9.9.9"), "unsupported bundleVersion"),
    ],
)
def test_tampered_bundle_yields_no_record(bundle_bytes: bytes, name: str, fn, needle: str) -> None:
    with pytest.raises(at.BundleNotVerified) as exc:
        _record(_mutate(bundle_bytes, fn))
    assert any(needle in r for r in exc.value.reasons), (name, exc.value.reasons)


def test_pinned_key_must_match(bundle_bytes: bytes) -> None:
    bundle = json.loads(bundle_bytes)
    key_id = bundle["publicKeys"][0]["keyId"]
    assert _record(bundle_bytes, pinned_keys={key_id: bundle["publicKeys"][0]["pem"]})
    other = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(at.BundleNotVerified):
        _record(bundle_bytes, pinned_keys={key_id: other})


def test_several_models_need_an_explicit_choice(tmp_path: Path) -> None:
    raw = make_demo_bundle.build(
        tmp_path / "two-models.json",
        models=(("demo-provider", "demo-model"), ("demo-provider", "other-model")),
    ).read_bytes()
    assert at.check_bundle(json.loads(raw)).ok
    with pytest.raises(ValueError, match="names 2 models"):
        _record(raw)
    record = _record(raw, model_provider="demo-provider", model_id="other-model")
    assert record["model"] == {"provider": "demo-provider", "model_id": "other-model"}
