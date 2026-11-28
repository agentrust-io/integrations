from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from agentrust_trace_adapters import MissingEvidence
from agentrust_trace_adapters.builder import software_measurement
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import generate_key, key_to_jwk, sign_record, verify_record

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import auditant_trace as at  # noqa: E402

# Bundles made by Auditant's own TypeScript core, not by the code under test (fixtures/README.md).
FIXTURES = ROOT / "fixtures"
FULL = (FIXTURES / "auditant-full.json").read_bytes()
RANGED = (FIXTURES / "auditant-ranged.json").read_bytes()
TWO_MODELS = (FIXTURES / "auditant-two-models.json").read_bytes()

SUBJECT = "spiffe://example.org/agent/refund-agent"
POLICY = b'permit(principal, action == Action::"issue_refund", resource) when { context.amount <= 100 };\n'
WORKLOAD = "sha256:" + hashlib.sha256(b"refund-agent image").hexdigest()
KEY = generate_key()


def _record(raw: bytes, **kw: Any) -> dict[str, Any]:
    kw.setdefault("subject", SUBJECT)
    kw.setdefault("policy_bundle", POLICY)
    kw.setdefault("enforcement_mode", "advisory")
    kw.setdefault("workload_digest", WORKLOAD)
    kw.setdefault("data_class", "internal")
    kw.setdefault("jwk", key_to_jwk(KEY))
    return at.build_trust_record(raw, **kw)


def _mutate(raw: bytes, fn) -> bytes:
    bundle = json.loads(raw)
    fn(bundle)
    return json.dumps(bundle).encode()


def _refused(raw: bytes, needle: str, **kw: Any) -> list[str]:
    with pytest.raises(at.BundleNotVerified) as exc:
        _record(raw, **kw)
    assert any(needle in r for r in exc.value.reasons), exc.value.reasons
    return exc.value.reasons


def _test_key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return key, pem


def _signed(cp: dict[str, Any], key: ec.EllipticCurvePrivateKey, key_id: str, body: str | None = None) -> dict:
    body = at.checkpoint_body(cp) if body is None else body
    sig = base64.b64encode(key.sign(body.encode(), ec.ECDSA(hashes.SHA256()))).decode()
    return {"checkpoint": cp, "body": body, "keyId": key_id, "signature": sig}


# ── the fixtures verify ─────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,events", [(FULL, 8), (RANGED, 4), (TWO_MODELS, 8)])
def test_auditant_bundles_verify(raw: bytes, events: int) -> None:
    check = at.check_bundle(json.loads(raw))
    assert check.ok, check.reasons
    assert check.events == events
    assert check.anchored_through_size == 8
    assert check.anchored_event_id == "evt_000008"


def test_record_is_a_valid_signed_level0_record() -> None:
    signed = sign_record(_record(FULL), KEY)
    TrustRecord.model_validate(signed)
    verify_record(signed, KEY.public_key())
    assert signed["runtime"]["platform"] == "software-only"
    assert signed["appraisal"]["status"] == "none"
    assert signed["build_provenance"] == {"slsa_level": 0, "digest": WORKLOAD}


# ── TRACE field semantics ───────────────────────────────────────────────────


def test_subject_comes_from_the_operator_not_the_log() -> None:
    assert _record(FULL)["subject"] == SUBJECT
    with pytest.raises(ValueError, match="SPIFFE URI or a DID"):
        _record(FULL, subject="refund-agent")


def test_origin_names_auditant_and_the_anchored_event() -> None:
    origin = _record(FULL)["origin"]
    assert origin == {"kind": "log-import", "producer": "https://auditant.co", "source_event_id": "evt_000008"}


def test_policy_bundle_hash_is_the_policy_bytes() -> None:
    policy = _record(FULL)["policy"]
    assert policy["bundle_hash"] == "sha256:" + hashlib.sha256(POLICY).hexdigest()
    with pytest.raises(MissingEvidence):
        _record(FULL, policy_bundle=b"")


def test_transcript_hash_is_the_tool_call_events() -> None:
    bundle = json.loads(FULL)
    tool_calls = [e for e in bundle["events"] if e["actionType"] == "tool_call"]
    transcript = _record(FULL)["tool_transcript"]
    assert transcript["hash"] == "sha256:" + hashlib.sha256(rfc8785.dumps(tool_calls)).hexdigest()
    assert transcript["hash"] != "sha256:" + hashlib.sha256(FULL).hexdigest()
    assert transcript["call_count"] == 3


def test_measurement_is_a_software_commitment_not_the_checkpoint() -> None:
    record = _record(FULL)
    assert record["runtime"]["measurement"] == software_measurement(
        "https://auditant.co", SUBJECT, record["policy"]["bundle_hash"]
    )
    body = at.check_bundle(json.loads(FULL)).anchoring_body
    assert record["runtime"]["measurement"] != "sha256:" + hashlib.sha256(body.encode()).hexdigest()


def test_workload_digest_is_required() -> None:
    with pytest.raises(MissingEvidence):
        _record(FULL, workload_digest=None)


def test_enforcement_mode_has_no_default_and_declared_is_refused_after_decisions() -> None:
    with pytest.raises(TypeError):
        at.build_trust_record(  # type: ignore[call-arg]
            FULL, subject=SUBJECT, policy_bundle=POLICY, workload_digest=WORKLOAD,
            data_class="internal", jwk=key_to_jwk(KEY),
        )
    with pytest.raises(ValueError):
        _record(FULL, enforcement_mode="strict")
    with pytest.raises(ValueError, match="policy decision"):
        _record(FULL, enforcement_mode="declared")


# ── model identity ──────────────────────────────────────────────────────────


def test_one_model_is_taken_from_the_bundle() -> None:
    assert _record(FULL)["model"] == {"provider": "demo-provider", "model_id": "demo-model"}


def test_several_models_need_a_choice_from_the_bundle() -> None:
    with pytest.raises(ValueError, match="names 2 models"):
        _record(TWO_MODELS)
    with pytest.raises(ValueError, match="names 2 models"):
        _record(TWO_MODELS, model_provider="demo-provider")
    chosen = _record(TWO_MODELS, model_provider="demo-provider", model_id="other-model")
    assert chosen["model"] == {"provider": "demo-provider", "model_id": "other-model"}
    assert _record(TWO_MODELS, model_id="other-model")["model"]["provider"] == "demo-provider"


@pytest.mark.parametrize(
    "provider,model_id",
    [
        ("demo-provider", "never-called"),
        ("other-provider", "demo-model"),
        ("other-provider", None),
        (None, "never-called"),
    ],
)
def test_explicit_model_must_appear_in_the_bundle(provider, model_id) -> None:
    with pytest.raises(ValueError, match="is not a model the bundle"):
        _record(FULL, model_provider=provider, model_id=model_id)


def test_a_model_call_without_a_named_model_is_missing_evidence() -> None:
    bundle = json.loads(FULL)
    next(e for e in bundle["events"] if e["actionType"] == "model_call").pop("cost")
    with pytest.raises(MissingEvidence, match="does not name its provider"):
        at.models_in_bundle(bundle)


# ── tampering ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fn,needle",
    [
        (lambda b: b["events"][2].update(outcome="error"), "content altered at 2"),
        (lambda b: b["events"].pop(3), "sequence gap"),
        (lambda b: b["events"].reverse(), "sequence gap"),
        (lambda b: b["events"].pop(), "no verified checkpoint covers the last event"),
        (lambda b: b["events"][0].update(prevHash="sha256:" + "1" * 64), "broken link at 0"),
        (lambda b: b.update(publicKeys=[]), "which the bundle does not list"),
        (lambda b: b.update(bundleVersion="9.9.9"), "unsupported bundleVersion"),
        (lambda b: b.update(checkpoints=[]), "no verified checkpoint covers the last event"),
    ],
)
def test_tampered_bundle_yields_no_record(fn, needle: str) -> None:
    _refused(_mutate(FULL, fn), needle)


def test_ranged_export_must_link_to_its_start_head() -> None:
    _refused(
        _mutate(RANGED, lambda b: b["startHead"].update(headHash="sha256:" + "2" * 64)),
        "broken link at 4",
    )


@pytest.mark.parametrize("n", [1, 3])
def test_deleting_the_first_events_is_caught(n: int) -> None:
    raw = _mutate(FULL, lambda b: b["events"].__delitem__(slice(0, n)))
    _refused(raw, "no verified checkpoint signs the head it starts from")


def test_an_excerpt_pinned_by_a_checkpoint_verifies_but_yields_no_record() -> None:
    excerpt = _mutate(FULL, lambda b: b["events"].__delitem__(slice(0, 4)))
    assert at.check_bundle(json.loads(excerpt)).ok
    _refused(excerpt, "starts at seq 4, not 0")
    assert at.check_bundle(json.loads(RANGED)).ok
    _refused(RANGED, "starts at seq 4, not 0")


def test_a_ranged_export_needs_a_signed_start() -> None:
    raw = _mutate(RANGED, lambda b: b["checkpoints"].pop(0))
    _refused(raw, "no verified checkpoint signs the head it starts from")


def test_a_start_head_at_zero_must_be_genesis() -> None:
    raw = _mutate(FULL, lambda b: b.update(startHead={"treeSize": 0, "headHash": "sha256:" + "1" * 64}))
    _refused(raw, "startHead at tree size 0 is not the genesis hash")


# ── checkpoints fail closed ─────────────────────────────────────────────────


def test_a_failed_checkpoint_fails_the_bundle_even_when_another_anchors_it() -> None:
    def forge_first(b: dict) -> None:
        sig = base64.b64decode(b["checkpoints"][0]["signature"])
        b["checkpoints"][0]["signature"] = base64.b64encode(sig[:-1] + bytes([sig[-1] ^ 1])).decode()

    reasons = _refused(_mutate(FULL, forge_first), "checkpoint 0 (tree size 4)")
    assert not any("checkpoint 1" in r for r in reasons), reasons


def test_an_extra_checkpoint_under_an_unknown_key_fails_the_bundle() -> None:
    def add(b: dict) -> None:
        extra = copy.deepcopy(b["checkpoints"][1])
        extra["keyId"] = "auditant-unknown"
        b["checkpoints"].append(extra)

    _refused(_mutate(FULL, add), "'auditant-unknown', which the bundle does not list")


def test_a_validly_signed_checkpoint_that_contradicts_the_chain_fails() -> None:
    key, pem = _test_key()

    def add(b: dict) -> None:
        cp = {"origin": "auditant.dev/demo_org/prod", "treeSize": 4, "headHash": "sha256:" + "3" * 64,
              "timestamp": "2026-11-27T10:05:00.000Z"}
        b["publicKeys"].append({"keyId": "second", "pem": pem})
        b["checkpoints"].append(_signed(cp, key, "second"))

    _refused(_mutate(FULL, add), "contradicts the chain")


def test_a_checkpoint_for_another_log_fails() -> None:
    key, pem = _test_key()

    def add(b: dict) -> None:
        cp = dict(b["checkpoints"][1]["checkpoint"], origin="auditant.dev/someone_else/prod")
        b["publicKeys"].append({"keyId": "second", "pem": pem})
        b["checkpoints"].append(_signed(cp, key, "second"))

    _refused(_mutate(FULL, add), "is not this log's")


def test_pinned_keys_cover_every_checkpoint() -> None:
    bundle = json.loads(FULL)
    key_id, pem = bundle["publicKeys"][0]["keyId"], bundle["publicKeys"][0]["pem"]
    assert _record(FULL, pinned_keys={key_id: pem})
    _, other = _test_key()
    _refused(FULL, "is not a pinned key", pinned_keys={key_id: other})

    key, second_pem = _test_key()

    def add(b: dict) -> None:
        b["publicKeys"].append({"keyId": "second", "pem": second_pem})
        b["checkpoints"].append(_signed(dict(b["checkpoints"][1]["checkpoint"]), key, "second"))

    raw = _mutate(FULL, add)
    assert at.check_bundle(json.loads(raw)).ok  # unpinned, both checkpoints verify
    _refused(raw, "'second' is not a pinned key", pinned_keys={key_id: pem})


# ── strict encodings and input handling ─────────────────────────────────────


def _non_canonical(b64: str) -> str:
    """Same bytes, different text: set the unused low bits of the last data character."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    pad = len(b64) - len(b64.rstrip("="))
    assert pad, "a no-padding string has no unused bits"
    i = len(b64) - pad - 1
    return b64[:i] + alphabet[alphabet.index(b64[i]) | 1] + b64[i + 1 :]


@pytest.mark.parametrize(
    "fn",
    [
        lambda s: _non_canonical(s),
        lambda s: s.rstrip("="),
        lambda s: s[:10] + "\n" + s[10:],
        lambda s: s.replace("+", "-").replace("/", "_") if ("+" in s or "/" in s) else "*" + s[1:],
    ],
    ids=["unused-bits", "no-padding", "newline", "urlsafe-alphabet"],
)
def test_signature_base64_must_be_canonical(fn) -> None:
    bundle = json.loads(FULL)
    # A DER signature is 70 to 72 bytes; take one whose base64 is padded, so it has unused bits.
    i = next(n for n, cp in enumerate(bundle["checkpoints"]) if cp["signature"].endswith("="))
    sig = bundle["checkpoints"][i]["signature"]
    altered = fn(sig)
    assert altered != sig
    bundle["checkpoints"][i]["signature"] = altered
    _refused(json.dumps(bundle).encode(), f"checkpoint {i} (tree size {4 * (i + 1)}): signature is unreadable")


def test_a_signed_body_with_non_canonical_base64_fails() -> None:
    key, pem = _test_key()

    def add(b: dict) -> None:
        cp = b["checkpoints"][1]["checkpoint"]
        lines = at.checkpoint_body(cp).split("\n")
        lines[2] = _non_canonical(lines[2])
        b["publicKeys"].append({"keyId": "second", "pem": pem})
        b["checkpoints"].append(_signed(dict(cp), key, "second", body="\n".join(lines)))

    _refused(_mutate(FULL, add), "fields do not match the signed body")


@pytest.mark.parametrize(
    "fn,needle",
    [
        (lambda b: b["checkpoints"][1]["checkpoint"].update(treeSize=True), "treeSize is not a positive integer"),
        (lambda b: b["events"][0].update(seq=False), "events[0].seq is not a non-negative integer"),
        (lambda b: b["checkpoints"][1]["checkpoint"].update(treeSize=8.0), "treeSize is not a positive integer"),
        (lambda b: b["events"][1].pop("eventHash"), "events[1].eventHash is not a sha256 digest"),
        (lambda b: b["events"].__setitem__(2, "event"), "events[2] is not an object"),
        (lambda b: b.update(events={"0": {}}), "events is missing, empty or not a list"),
        (lambda b: b.update(publicKeys={"k": "pem"}), "publicKeys is missing or not a list"),
        (lambda b: b["publicKeys"].append(dict(b["publicKeys"][0])), "more than once"),
        (lambda b: b["checkpoints"][0].pop("body"), "checkpoints[0].body is not a string"),
        (lambda b: b["checkpoints"].append("cp"), "checkpoints[2] is not a signed checkpoint object"),
        (lambda b: b.update(startHead=[]), "startHead needs"),
        (lambda b: b.pop("logId"), "logId is missing"),
        (lambda b: b["events"][7].pop("eventId"), "events[7].eventId is not a non-empty string"),
        (lambda b: b["events"][7].update(eventId=5), "events[7].eventId is not a non-empty string"),
    ],
)
def test_malformed_structure_is_reported_not_raised(fn, needle: str) -> None:
    bundle = json.loads(FULL)
    fn(bundle)
    check = at.check_bundle(bundle)  # must not raise
    assert not check.ok and any(needle in r for r in check.reasons), check.reasons
    _refused(json.dumps(bundle).encode(), needle)


@pytest.mark.parametrize(
    "raw,needle",
    [
        (b"[]", "not an object"),
        (b"null", "not an object"),
        (b'"bundle"', "not an object"),
        (b"{not json", "not valid JSON"),
        (b"\xff\xfe", "not valid JSON"),
        (b'{"logId": "a", "logId": "b"}', "duplicate JSON key 'logId'"),
        (b"[" * 200_000, "nests too deeply"),
        (b'{"a":' * 200_000, "nests too deeply"),
    ],
)
def test_bad_bytes_are_refused(raw: bytes, needle: str) -> None:
    _refused(raw, needle)


def test_an_unreadable_listed_key_fails_closed() -> None:
    _refused(
        _mutate(FULL, lambda b: b["publicKeys"][0].update(pem="-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")),
        "is unreadable",
    )


# ── the CLI ─────────────────────────────────────────────────────────────────


def test_cli_writes_a_record_only_for_a_verified_bundle(tmp_path: Path) -> None:
    policy = tmp_path / "policy.cedar"
    policy.write_bytes(POLICY)
    key_pem = KEY.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    signing = tmp_path / "signing.pem"
    signing.write_bytes(key_pem)
    args = ["--subject", SUBJECT, "--policy-bundle", str(policy), "--enforcement-mode", "advisory",
            "--workload-digest", WORKLOAD, "--data-class", "internal", "--signing-key", str(signing)]

    good, out = tmp_path / "good.json", tmp_path / "good.trace.json"
    good.write_bytes(FULL)
    assert at.main([str(good), "--out", str(out), *args]) == 0
    TrustRecord.model_validate(json.loads(out.read_text()))

    bad, none = tmp_path / "bad.json", tmp_path / "bad.trace.json"
    bad.write_bytes(_mutate(FULL, lambda b: b["events"][2].update(outcome="error")))
    assert at.main([str(bad), "--out", str(none), *args]) == 2
    assert not none.exists()

    assert at.main([str(good), "--out", str(none), *args[:5], "declared", *args[6:]]) == 2
    assert not none.exists()

    missing = str(tmp_path / "missing.json")
    assert at.main([missing, "--out", str(none), *args]) == 2
    assert at.main([str(good), "--out", str(none), *args, "--pin-key", f"k={missing}"]) == 2
    assert at.main([str(good), "--out", str(none), *args, "--pin-key", "no-equals-sign"]) == 2
    assert not none.exists()
