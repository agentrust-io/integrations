"""Synthetic producer fixtures: ordinary JSON serialization and direct signing.

No OpenShell process, credential, hardware or producer implementation is used.
"""

import base64
import copy
import hashlib
import json

import pytest
from agentrust_trace_adapters.openshell_bundle import BundleError, verify_bundle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def producer():
    key = Ed25519PrivateKey.generate()
    events = [
        {
            "time": 100 + i,
            "metadata": {
                "uid": "sandbox-a",
                "sequence": i,
                "product": {"version": "synthetic"},
            },
        }
        for i in (10, 11, 12)
    ]
    manifest = {
        "format": "agentrust.openshell-evidence-candidate.v1",
        "sandbox_id": "sandbox-a",
        "openshell_version": "synthetic",
        "policy_revision": "policy-1",
        "capture_start": 100,
        "capture_end": 200,
        "complete": True,
        "incomplete_reason": None,
        "event_count": 3,
        "sequence": {"epoch": "synthetic-boot-1", "first": 10, "last": 12},
    }

    def build(*, transform=None, raw_manifest=None):
        m, e = copy.deepcopy(manifest), copy.deepcopy(events)
        if transform:
            transform(m, e)
        files = {
            "effective-policy.yaml": b"network: deny\n",
            "events.ocsf.jsonl": b"".join(json.dumps(x).encode() + b"\n" for x in e),
        }
        m["event_count"] = len(e)
        m["files"] = {
            name: "sha256:" + hashlib.sha256(raw).hexdigest()
            for name, raw in files.items()
        }
        raw = json.dumps(m, indent=2).encode() if raw_manifest is None else raw_manifest
        sig = json.dumps(
            {
                "algorithm": "Ed25519",
                "key_id": "gateway-1",
                "signature": base64.b64encode(key.sign(raw)).decode(),
            }
        ).encode()
        return raw, sig, files

    return build, key


def check(producer, bundle=None, **kwargs):
    build, key = producer
    return verify_bundle(
        *(bundle or build()),
        trusted_keys={"gateway-1": key.public_key()},
        expected_sandbox_id="sandbox-a",
        expected_capture_start=100,
        expected_capture_end=200,
        **kwargs,
    )


def test_positive_control(producer):
    result = check(producer)
    assert result.coverage == "verified_complete_over_range"
    assert result.signature_verified and result.file_integrity_verified
    assert result.event_count == 3


@pytest.mark.parametrize("index", [0, 1, 2])
def test_signed_missing_event_at_every_position(producer, index):
    bundle = producer[0](transform=lambda m, e: e.pop(index))
    assert check(producer, bundle).coverage == "provable_gap"


@pytest.mark.parametrize("index", [0, 1, 2])
def test_unsigned_event_removal_fails_integrity(producer, index):
    raw, sig, files = producer[0]()
    lines = files["events.ocsf.jsonl"].splitlines(keepends=True)
    lines.pop(index)
    files["events.ocsf.jsonl"] = b"".join(lines)
    with pytest.raises(BundleError, match="digest mismatch"):
        check(producer, (raw, sig, files))


@pytest.mark.parametrize(
    "field,value",
    [
        ("complete", False),
        ("sandbox_id", "b"),
        ("capture_start", 99),
        ("capture_end", 201),
        ("files", {}),
        ("sequence", {"epoch": "another", "first": 0, "last": 1}),
    ],
)
def test_manifest_tampering(producer, field, value):
    raw, sig, files = producer[0]()
    m = json.loads(raw)
    m[field] = value
    with pytest.raises(BundleError, match="signature"):
        check(producer, (json.dumps(m).encode(), sig, files))


def test_exact_bytes_not_reserialized(producer):
    raw, sig, files = producer[0]()
    with pytest.raises(BundleError, match="signature"):
        check(producer, (raw + b"\n", sig, files))


@pytest.mark.parametrize("mode", ["empty", "bounds", "sequence", "incomplete"])
def test_not_established(producer, mode):
    def transform(m, e):
        if mode == "empty":
            e.clear()
        elif mode == "bounds":
            m["sequence"] = None
        elif mode == "sequence":
            del e[1]["metadata"]["sequence"]
        else:
            m.update(complete=False, incomplete_reason="restart")

    assert (
        check(producer, producer[0](transform=transform)).coverage == "not_established"
    )


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (lambda m, e: m.update(sandbox_id="other"), "unexpected sandbox"),
        (lambda m, e: m.update(capture_start=99), "unexpected capture"),
        (lambda m, e: m.update(complete="true"), "boolean"),
        (lambda m, e: m.update(complete=False), "nonempty text"),
        (lambda m, e: m.update(policy_revision=""), "nonempty text"),
        (lambda m, e: e[1]["metadata"].update(uid="other"), "sandbox mismatch"),
        (
            lambda m, e: e[1]["metadata"].update(product={"version": "other"}),
            "version mismatch",
        ),
        (lambda m, e: e[1].update(time=999), "outside capture"),
        (lambda m, e: e[1]["metadata"].update(sequence=True), "integer"),
        (lambda m, e: e[1]["metadata"].update(sequence=10), "duplicate"),
        (lambda m, e: e.reverse(), "unordered"),
        (lambda m, e: e[1]["metadata"].update(sequence=2**53), "integer"),
        (lambda m, e: e[1]["metadata"].update(sequence=99), "outside sequence"),
        (lambda m, e: m["sequence"].update(first=13), "reversed"),
    ],
)
def test_authenticated_bad_input(producer, mutation, reason):
    with pytest.raises(BundleError, match=reason):
        check(producer, producer[0](transform=mutation))


def test_single_event_control(producer):
    def transform(m, e):
        del e[1:]
        m["sequence"]["last"] = 10

    assert (
        check(producer, producer[0](transform=transform)).coverage
        == "verified_complete_over_range"
    )


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b"[]", b"\xff", b"{"])
def test_signed_invalid_json(producer, raw):
    with pytest.raises(BundleError):
        check(producer, producer[0](raw_manifest=raw))


@pytest.mark.parametrize(
    "field,value",
    [("algorithm", "none"), ("key_id", "attacker"), ("signature", "not-base64")],
)
def test_bad_signature_envelope(producer, field, value):
    raw, sig, files = producer[0]()
    envelope = json.loads(sig)
    envelope[field] = value
    with pytest.raises(BundleError):
        check(producer, (raw, json.dumps(envelope).encode(), files))


def test_untrusted_signer(producer):
    raw, sig, files = producer[0]()
    envelope = json.loads(sig)
    envelope["signature"] = base64.b64encode(
        Ed25519PrivateKey.generate().sign(raw)
    ).decode()
    with pytest.raises(BundleError, match="signature"):
        check(producer, (raw, json.dumps(envelope).encode(), files))


@pytest.mark.parametrize("name", ["effective-policy.yaml", "events.ocsf.jsonl"])
def test_substituted_file(producer, name):
    raw, sig, files = producer[0]()
    files[name] += b"changed"
    with pytest.raises(BundleError, match="digest mismatch"):
        check(producer, (raw, sig, files))


def test_extra_file_rejected(producer):
    raw, sig, files = producer[0]()
    files["../secret"] = b"ignored?"
    with pytest.raises(BundleError, match="file set"):
        check(producer, (raw, sig, files))


def test_huge_signed_range_is_constant_space(producer):
    bundle = producer[0](transform=lambda m, e: m["sequence"].update(last=2**53 - 1))
    assert check(producer, bundle).coverage == "provable_gap"


def test_signed_wrong_event_count(producer):
    raw, _, files = producer[0]()
    manifest = json.loads(raw)
    manifest["event_count"] = 99
    raw = json.dumps(manifest).encode()
    envelope = json.dumps(
        {
            "algorithm": "Ed25519",
            "key_id": "gateway-1",
            "signature": base64.b64encode(producer[1].sign(raw)).decode(),
        }
    ).encode()
    with pytest.raises(BundleError, match="event count"):
        check(producer, (raw, envelope, files))


@pytest.mark.parametrize("name", ["effective-policy.yaml", "events.ocsf.jsonl"])
def test_missing_file(producer, name):
    raw, sig, files = producer[0]()
    del files[name]
    with pytest.raises(BundleError, match="file set"):
        check(producer, (raw, sig, files))


def test_malformed_signed_jsonl(producer):
    raw, _, files = producer[0]()
    files["events.ocsf.jsonl"] += b"\n"
    m = json.loads(raw)
    m["files"]["events.ocsf.jsonl"] = (
        "sha256:" + hashlib.sha256(files["events.ocsf.jsonl"]).hexdigest()
    )
    raw = json.dumps(m).encode()
    sig = json.dumps(
        {
            "algorithm": "Ed25519",
            "key_id": "gateway-1",
            "signature": base64.b64encode(producer[1].sign(raw)).decode(),
        }
    ).encode()
    with pytest.raises(BundleError, match="JSON"):
        check(producer, (raw, sig, files))
