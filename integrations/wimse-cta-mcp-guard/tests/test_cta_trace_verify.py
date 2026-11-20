"""Relying-party verification: strict parsing, key hygiene, and forged-but-signed artifacts."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re

import cta_trace_guard as g
import cta_trace_verify as v
import pytest
from agentrust_trace import key_to_jwk
from conftest import (
    NOW,
    OTHER_KEY,
    POLICY_KEY,
    Harness,
    forge_bridge,
    raw_public,
    resign_record,
    verify_all,
)

ZERO_DIGEST = "sha256:" + "0" * 64
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
POLICY_JWK = key_to_jwk(POLICY_KEY)


def _alternate_spelling(value: str) -> str:
    """Same bytes under a lenient decoder: flip a low bit of the last character."""
    return value[:-1] + ALPHABET[ALPHABET.index(value[-1]) ^ 1]


# --- Strict JSON ------------------------------------------------------------

@pytest.mark.parametrize(
    "data, fragment",
    [
        (b'{"a": 1, "a": 2}', "duplicate key"),
        (b'{"a": {"b": 1, "b": 2}}', "duplicate key"),
        (b'[{"a": 1, "a": 1}]', "duplicate key"),
        (b'{"a": NaN}', "non-finite JSON constant"),
        (b'{"a": Infinity}', "non-finite JSON constant"),
        (b'{"a": -Infinity}', "non-finite JSON constant"),
        (b'{"a": 1e999}', "non-finite JSON number"),
        (b'{"a": -1e999}', "non-finite JSON number"),
        (b"\xff", "not valid UTF-8"),
        (b'{"a": ', "malformed JSON"),
        (b"\xef\xbb\xbf{}", "malformed JSON"),
        ("1" * 5000, "malformed JSON"),
        (("[" * 100000).encode(), "too deep"),
        (123, "bytes or str"),
        (None, "bytes or str"),
    ],
)
def test_loads_unique_refuses(data, fragment):
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        v.loads_unique(data)


def test_loads_unique_accepts_ordinary_json_as_bytes_or_str():
    text = '{"a": [1, 2.5, "x", null, true], "b": {"c": -3}}'
    expected = {"a": [1, 2.5, "x", None, True], "b": {"c": -3}}
    assert v.loads_unique(text) == expected
    assert v.loads_unique(text.encode()) == expected
    assert v.loads_unique(bytearray(text.encode())) == expected


@pytest.mark.parametrize(
    "value",
    [{"a": {1, 2}}, {"a": b"x"}, {"a": float("nan")}, {"a": float("inf")}, {"a": 2**53}, {"a": "\ud800"}, {1: 2}],
)
def test_canonical_bytes_refuses_values_without_a_jcs_form(value):
    with pytest.raises(v.CtaVerifyError, match="RFC 8785"):
        v.canonical_bytes(value)


def test_canonical_bytes_refuses_excessive_nesting():
    nested: list = []
    for _ in range(100000):
        nested = [nested]
    with pytest.raises(v.CtaVerifyError):
        v.canonical_bytes(nested)


def test_digest_jcs_is_key_order_independent():
    assert v.digest_jcs({"a": 1, "b": 2}) == v.digest_jcs({"b": 2, "a": 1})
    assert v.digest_jcs({"a": 1}) != v.digest_jcs({"a": 2})


# --- Scalars ----------------------------------------------------------------

@pytest.mark.parametrize("value", [True, False, 1.0, -1, v.SAFE_INT_MAX + 1, "1", None])
def test_timestamps_must_be_non_negative_safe_integers_and_not_booleans(value):
    with pytest.raises(v.CtaVerifyError, match="Unix timestamp"):
        v.require_timestamp(value, "t")


def test_timestamp_bounds_are_inclusive():
    assert v.require_timestamp(0, "t") == 0
    assert v.require_timestamp(v.SAFE_INT_MAX, "t") == v.SAFE_INT_MAX


@pytest.mark.parametrize("value", ["", "a b", "a\nb", "a\n", "caf\u00e9", "x" * 513, 12345, None])
def test_identifiers_are_printable_ascii_without_whitespace(value):
    with pytest.raises(v.CtaVerifyError):
        v.require_identifier(value, "id")


def test_identifier_accepts_urns_and_the_length_bound():
    assert v.require_identifier("urn:uuid:7f9c2b10-44a1-49e2-910b-88a12c34e901", "id")
    assert v.require_identifier("x" * 512, "id")


@pytest.mark.parametrize("value", ["sha256:" + "A" * 64, "sha256:" + "a" * 63, "a" * 64, ZERO_DIGEST + "\n", None])
def test_digests_are_lowercase_sha256_hex(value):
    with pytest.raises(v.CtaVerifyError):
        v.require_digest(value, "d")


def test_b64url_decode_has_one_spelling_per_byte_string():
    raw = bytes(range(32))
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert v.b64url_decode(encoded, field="x") == raw
    assert v.b64url_decode(encoded, field="x", length=32) == raw
    assert v.b64url_decode("", field="x") == b""
    with pytest.raises(v.CtaVerifyError, match="not canonical"):
        v.b64url_decode(_alternate_spelling(encoded), field="x")


@pytest.mark.parametrize(
    "value, fragment",
    [
        ("AA==", "unpadded"),
        ("AA\n", "unpadded"),
        (" AAAA", "unpadded"),
        ("A+AA", "unpadded"),
        ("A/AA", "unpadded"),
        ("\u00e9AAA", "unpadded"),
        ("A", "impossible"),
        ("AAAAA", "impossible"),
        ("AB", "not canonical"),
        (123, "must be a base64url string"),
        (None, "must be a base64url string"),
    ],
)
def test_b64url_decode_refuses(value, fragment):
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        v.b64url_decode(value, field="x")


def test_b64url_decode_enforces_an_expected_length():
    with pytest.raises(v.CtaVerifyError, match="decode to 32 bytes"):
        v.b64url_decode("AAAA", field="x", length=32)


# --- JWK hygiene ------------------------------------------------------------

def test_public_jwk_yields_the_key_and_its_raw_bytes():
    _, raw = v.public_key_from_jwk(POLICY_JWK)
    assert raw == raw_public(POLICY_KEY)
    v.public_key_from_jwk({**POLICY_JWK, "kid": v.key_id(raw)})


@pytest.mark.parametrize("member", v.PRIVATE_JWK_MEMBERS)
def test_jwk_with_a_private_member_is_refused(member):
    with pytest.raises(v.CtaVerifyError, match="private key members"):
        v.public_key_from_jwk({**POLICY_JWK, member: "AAAA"})


@pytest.mark.parametrize(
    "jwk, fragment",
    [
        ("not a mapping", "must be an object"),
        ({**POLICY_JWK, "alg": "EdDSA"}, "unsupported members"),
        ({**POLICY_JWK, "kty": "EC"}, "not an OKP Ed25519"),
        ({**POLICY_JWK, "crv": "X25519"}, "not an OKP Ed25519"),
        ({**POLICY_JWK, "x": _alternate_spelling(POLICY_JWK["x"])}, "not canonical"),
        ({**POLICY_JWK, "x": POLICY_JWK["x"][:-1]}, "x"),
        ({"kty": "OKP", "crv": "Ed25519"}, "must be a base64url string"),
        ({**POLICY_JWK, "kid": ZERO_DIGEST}, "kid is not the SHA-256"),
    ],
)
def test_malformed_public_jwk_is_refused(jwk, fragment):
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        v.public_key_from_jwk(jwk)


def test_key_id_is_sha256_of_the_raw_public_key():
    raw = raw_public(POLICY_KEY)
    assert v.key_id(raw) == "sha256:" + hashlib.sha256(raw).hexdigest()


# --- did:key ----------------------------------------------------------------

@pytest.mark.parametrize(
    "did, fragment",
    [
        ("did:web:example.com", "not a base58btc did:key"),
        ("did:key:z" + "1" * 200, "not a base58btc did:key"),
        (5, "not a base58btc did:key"),
        ("did:key:z0OIl", "invalid base58btc character"),
        ("did:key:z" + g._base58btc(b"\xec\x01" + raw_public(POLICY_KEY)), "multicodec"),
        ("did:key:z" + g._base58btc(b"\xed\x01" + b"\x07" * 31), "32-byte"),
    ],
)
def test_did_key_decoding_is_strict(did, fragment):
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        v.did_key_public_bytes(did)


def test_did_key_round_trips():
    assert v.did_key_public_bytes(g.did_key(POLICY_KEY)) == raw_public(POLICY_KEY)


# --- Decision basis and identifier ------------------------------------------

def test_decision_basis_is_determined_by_effect_class_and_taint():
    assert v.expected_basis(v.READ_ONLY, v.TRUSTED_ONLY) == v.BASIS_READ_ONLY
    assert v.expected_basis(v.READ_ONLY, v.UNTRUSTED_INGESTED) == v.BASIS_READ_ONLY
    assert v.expected_basis(v.STATE_MUTATING, v.TRUSTED_ONLY) == v.BASIS_TRUSTED_CONTEXT
    assert v.expected_basis(v.STATE_MUTATING, v.UNTRUSTED_INGESTED) == v.BASIS_STEP_UP


def test_authorization_id_names_the_decision_not_the_signer_or_the_window(trusted_run):
    authorization = trusted_run.outcome.record_artifacts.authorization.bridge["authorization"]
    assert v.authorization_id_for(authorization) == authorization["authorization_id"]
    resigned = {
        **authorization, "authorizer": "someone-else", "authorizer_key_id": ZERO_DIGEST,
        "authorized_at": 1, "expires_at": 2,
    }
    assert v.authorization_id_for(resigned) == authorization["authorization_id"]
    assert v.authorization_id_for({**authorization, "args_digest": ZERO_DIGEST}) != authorization["authorization_id"]


# --- Bridge -----------------------------------------------------------------

def _verify_bridge(run, bridge, **overrides):
    authz = run.outcome.record_artifacts.authorization
    kwargs = {"authorizer_jwk": authz.authorizer_jwk, "declaration": authz.declaration, "tool_call": authz.tool_call}
    kwargs.update(overrides)
    return v.verify_bridge(bridge, **kwargs)


def test_genuine_bridge_verifies_from_objects_bytes_and_text(trusted_run):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    assert _verify_bridge(trusted_run, bridge) == bridge["authorization"]
    assert _verify_bridge(trusted_run, json.dumps(bridge)) == bridge["authorization"]
    assert _verify_bridge(trusted_run, json.dumps(bridge).encode()) == bridge["authorization"]


def test_bridge_text_with_a_duplicate_member_is_refused(trusted_run):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    text = json.dumps(bridge)[:-1] + ', "signature": "AAAA"}'
    with pytest.raises(v.CtaVerifyError, match="duplicate key"):
        _verify_bridge(trusted_run, text)


@pytest.mark.parametrize("bad", [42, ["list"], None, "[1]"])
def test_bridge_must_be_a_json_object(trusted_run, bad):
    with pytest.raises(v.CtaVerifyError, match="must be a JSON object"):
        _verify_bridge(trusted_run, bad)


@pytest.mark.parametrize(
    "edit, fragment",
    [
        (lambda a: a.update(decision="deny"), "not allow"),
        (lambda a: a.update(cta_version="2.0"), "cta_version"),
        (lambda a: a.update(authorizer=""), "authorizer"),
        (lambda a: a.update(authorizer_key_id=ZERO_DIGEST), "authorizer_key_id"),
        (lambda a: a.update(authorized_at=True), "authorized_at"),
        (lambda a: a.update(expires_at=True), "expires_at"),
        (lambda a: a.update(expires_at=a["authorized_at"]), "after authorized_at"),
        (lambda a: a.update(session_id="has space"), "session_id"),
        (lambda a: a.update(request_id=""), "request_id"),
        (lambda a: a.update(tool_effect_class="PRIVILEGED_ACTUATE"), "known effect class"),
        (lambda a: a.update(taint_lattice_level="MIXED_TAINT"), "known level"),
        (lambda a: a.update(args_digest="sha256:short"), "args_digest"),
        (lambda a: a.update(decision_basis="step-up-receipt"), "inconsistent"),
        (lambda a: a.update(step_up_receipt_hash=ZERO_DIGEST), "exactly for a step-up basis"),
        (lambda a: a.update(extra="x"), "unknown fields"),
        (lambda a: a.pop("tool_name"), "missing required fields"),
        (lambda a: a.update(args_digest=v.digest_jcs({"path": "evil"})), "args_digest does not match"),
    ],
)
def test_forged_but_correctly_signed_bridge_is_refused(trusted_run, edit, fragment):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        _verify_bridge(trusted_run, forge_bridge(bridge, edit))


def test_bridge_cannot_claim_a_trusted_context_for_a_tainted_session(trusted_run):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    forged = forge_bridge(bridge, lambda a: a.update(taint_lattice_level=v.UNTRUSTED_INGESTED))
    with pytest.raises(v.CtaVerifyError, match="inconsistent"):
        _verify_bridge(trusted_run, forged)


@pytest.mark.parametrize("bad_id", ["urn:sha256:xyz", 5, "urn:sha256:" + "0" * 64])
def test_authorization_id_must_be_the_hash_of_the_decision(trusted_run, bad_id):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    forged = forge_bridge(bridge, lambda a: a.update(authorization_id=bad_id), reid=False)
    with pytest.raises(v.CtaVerifyError, match="authorization_id"):
        _verify_bridge(trusted_run, forged)


def test_bridge_signed_by_another_key_is_refused(trusted_run):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    with pytest.raises(v.CtaVerifyError, match="bridge signature is invalid"):
        _verify_bridge(trusted_run, forge_bridge(bridge, key=OTHER_KEY))


def test_editing_a_signed_bridge_without_resigning_is_refused(trusted_run):
    bridge = copy.deepcopy(trusted_run.outcome.record_artifacts.authorization.bridge)
    bridge["authorization"]["tool_name"] = "other_tool"
    with pytest.raises(v.CtaVerifyError, match="bridge signature is invalid"):
        _verify_bridge(trusted_run, bridge)


@pytest.mark.parametrize(
    "edit, fragment",
    [
        (lambda b: b.update(profile="tag:agentrust-io.com,2026:pic-trace-bridge-v1"), "unknown bridge profile"),
        (lambda b: b.update(extra=1), "unknown fields"),
        (lambda b: b.pop("signature"), "missing required fields"),
        (lambda b: b.update(authorization="not-an-object"), "must be an object"),
    ],
)
def test_bridge_envelope_shape_is_exact(trusted_run, edit, fragment):
    bridge = copy.deepcopy(trusted_run.outcome.record_artifacts.authorization.bridge)
    edit(bridge)
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        _verify_bridge(trusted_run, bridge)


def test_bridge_validity_window_is_checked_at_the_supplied_instant(trusted_run):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    assert _verify_bridge(trusted_run, bridge, now=NOW + 299)
    with pytest.raises(v.CtaVerifyError, match="expired"):
        _verify_bridge(trusted_run, bridge, now=NOW + 300)
    with pytest.raises(v.CtaVerifyError, match="not yet valid"):
        _verify_bridge(trusted_run, bridge, now=NOW - 1)
    with pytest.raises(v.CtaVerifyError, match="now must be"):
        _verify_bridge(trusted_run, bridge, now=True)


def test_bridge_verification_uses_only_the_pinned_public_key(trusted_run):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    private = {**trusted_run.guard.authorizer_jwk, "d": "AAAA"}
    with pytest.raises(v.CtaVerifyError, match="private key members"):
        _verify_bridge(trusted_run, bridge, authorizer_jwk=private)
    with pytest.raises(v.CtaVerifyError, match="signature is invalid"):
        _verify_bridge(trusted_run, bridge, authorizer_jwk=key_to_jwk(OTHER_KEY))


@pytest.mark.parametrize(
    "edit, fragment",
    [
        (lambda d: d.update(tool="other"), "different tool"),
        (lambda d: d.update(effect_class="READ_ONLY"), "effect class differs"),
        (lambda d: d.update(output_trust="untrusted"), "declaration_digest does not match"),
        (lambda d: d.update(output_trust="maybe"), "output_trust is not a known value"),
        (lambda d: d.update(profile="other"), "unknown declaration profile"),
        (lambda d: d.update(extra=1), "unknown fields"),
    ],
)
def test_declaration_must_be_the_one_the_bridge_was_signed_over(trusted_run, edit, fragment):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    declaration = copy.deepcopy(trusted_run.outcome.record_artifacts.authorization.declaration)
    edit(declaration)
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        _verify_bridge(trusted_run, bridge, declaration=declaration)


@pytest.mark.parametrize(
    "edit, fragment",
    [
        (lambda c: c.update(name="other"), "names a different tool"),
        (lambda c: c["arguments"].update(path="evil"), "tool_call_digest does not match"),
        (lambda c: c.update(arguments=[1]), "arguments must be an object"),
        (lambda c: c.update(extra=1), "unknown fields"),
    ],
)
def test_tool_call_must_be_the_one_the_bridge_was_signed_over(trusted_run, edit, fragment):
    bridge = trusted_run.outcome.record_artifacts.authorization.bridge
    call = copy.deepcopy(trusted_run.outcome.record_artifacts.authorization.tool_call)
    edit(call)
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        _verify_bridge(trusted_run, bridge, tool_call=call)


# --- Receipt ----------------------------------------------------------------

def test_receipt_verification_requires_a_valid_reference_time(stepup_run):
    authz = stepup_run.outcome.record_artifacts.authorization
    body = authz.step_up_receipt["receipt"]
    kwargs = {
        "policy_jwk": authz.policy_engine_jwk, "session_id": body["session_id"],
        "request_id": body["request_id"], "tool_name": body["tool_name"],
        "args_digest": body["args_digest"],
    }
    digest = v.verify_step_up_receipt(authz.step_up_receipt, now=NOW, **kwargs)["digest"]
    assert digest == v.digest_jcs(authz.step_up_receipt)
    with pytest.raises(v.CtaVerifyError, match="now must be"):
        v.verify_step_up_receipt(authz.step_up_receipt, now=True, **kwargs)
    with pytest.raises(v.CtaVerifyError, match="expired"):
        v.verify_step_up_receipt(authz.step_up_receipt, now=NOW + 300, **kwargs)


def test_receipt_may_start_within_the_skew_allowance_but_not_beyond_it():
    h = Harness()
    kwargs = {
        "policy_jwk": POLICY_JWK, "session_id": "s1", "request_id": "r1", "tool_name": "delete_demo_marker",
        "args_digest": v.digest_jcs({"path": "marker.txt"}),
    }
    early_ok = h.receipt(iat=NOW + 60, exp=NOW + 400)
    assert v.verify_step_up_receipt(early_ok, now=NOW, **kwargs)
    early_bad = h.receipt(iat=NOW + 61, exp=NOW + 400)
    with pytest.raises(v.CtaVerifyError, match="not yet valid"):
        v.verify_step_up_receipt(early_bad, now=NOW, **kwargs)


# --- Bridge-only artifacts --------------------------------------------------

def test_bridge_only_verification_of_a_step_up_basis_needs_the_receipt_and_the_key(stepup_run):
    authz = stepup_run.outcome.record_artifacts.authorization
    common = {
        "bridge": authz.bridge, "declaration": authz.declaration, "tool_call": authz.tool_call,
        "authorizer_jwk": authz.authorizer_jwk,
    }
    checked = v.verify_authorization_artifacts(
        **common, receipt=authz.step_up_receipt, policy_jwk=authz.policy_engine_jwk,
    )
    assert checked["step_up_receipt_bound"] is True
    with pytest.raises(v.CtaVerifyError, match="needs the receipt"):
        v.verify_authorization_artifacts(**common)
    with pytest.raises(v.CtaVerifyError, match="needs the receipt"):
        v.verify_authorization_artifacts(**common, receipt=authz.step_up_receipt)
    with pytest.raises(v.CtaVerifyError, match="signature is invalid"):
        v.verify_authorization_artifacts(
            **common, receipt=authz.step_up_receipt, policy_jwk=key_to_jwk(OTHER_KEY),
        )


def test_cited_receipt_digest_must_match_the_supplied_receipt(stepup_run):
    authz = stepup_run.outcome.record_artifacts.authorization
    sibling = stepup_run.harness.receipt(receipt_id="a-different-valid-receipt")
    with pytest.raises(v.CtaVerifyError, match="step_up_receipt_hash does not match"):
        v.verify_authorization_artifacts(
            bridge=authz.bridge, declaration=authz.declaration, tool_call=authz.tool_call,
            authorizer_jwk=authz.authorizer_jwk, receipt=sibling, policy_jwk=authz.policy_engine_jwk,
        )


def test_receipt_supplied_for_a_bridge_that_cites_none_is_refused(trusted_run):
    authz = trusted_run.outcome.record_artifacts.authorization
    with pytest.raises(v.CtaVerifyError, match="cites none"):
        v.verify_authorization_artifacts(
            bridge=authz.bridge, declaration=authz.declaration, tool_call=authz.tool_call,
            authorizer_jwk=authz.authorizer_jwk, receipt=trusted_run.harness.receipt(),
        )


# --- Record and transcript --------------------------------------------------

def test_artifact_checks_can_skip_the_optional_policy_and_transcript_inputs(trusted_run):
    checked = verify_all(trusted_run, policy_bundle=None, transcript=None)
    assert "policy_bytes_bound" not in checked and "transcript_bound_and_hashed" not in checked
    assert checked["record_signature"] is True


def test_editing_a_signed_record_breaks_the_signature(trusted_run):
    record = copy.deepcopy(trusted_run.outcome.record_artifacts.record)
    record["data_class"] = "restricted"
    with pytest.raises(v.CtaVerifyError, match="artifact verification failed"):
        verify_all(trusted_run, record=record)


def test_record_that_violates_the_trace_schema_is_refused(trusted_run):
    record = copy.deepcopy(trusted_run.outcome.record_artifacts.record)
    del record["subject"]
    with pytest.raises(v.CtaVerifyError, match="artifact verification failed"):
        verify_all(trusted_run, record=record)


def test_a_non_mapping_record_is_refused_with_the_modules_error(trusted_run):
    with pytest.raises(v.CtaVerifyError, match="artifact verification failed"):
        verify_all(trusted_run, record=42)


def test_record_signed_by_another_key_is_refused_by_the_pinned_key(trusted_run):
    other_signed = resign_record(trusted_run.outcome.record_artifacts.record, lambda r: None, key=OTHER_KEY)
    with pytest.raises(v.CtaVerifyError, match="pinned record key"):
        verify_all(trusted_run, record=other_signed)


def test_pinned_record_jwk_must_be_public(trusted_run):
    with pytest.raises(v.CtaVerifyError, match="private key members"):
        verify_all(trusted_run, record_jwk={**trusted_run.guard.record_jwk, "d": "AAAA"})


def test_verification_time_must_be_an_integer(trusted_run):
    with pytest.raises(v.CtaVerifyError, match="verification_time"):
        verify_all(trusted_run, verification_time=True)


def test_record_age_limit_is_enforced_when_requested(trusted_run):
    assert verify_all(trusted_run, verification_time=NOW + 100, max_record_age_seconds=1000)
    with pytest.raises(v.CtaVerifyError, match="artifact verification failed"):
        verify_all(trusted_run, verification_time=NOW + 1000, max_record_age_seconds=10)


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda r: r["origin"].update(source_event_id=ZERO_DIGEST), "source_event_id"),
        (lambda r: r["origin"].update(kind="log-import"), "origin.kind"),
        (lambda r: r["references"][0].update(digest=ZERO_DIGEST), "digest mismatch"),
        (lambda r: r["references"][0].update(rel="behavior-trace"), "rel is not authorized-intent"),
        (lambda r: r.update(references=[]), "exactly one reference"),
        (lambda r: r.pop("references"), "exactly one reference"),
        (lambda r: r["references"].append(dict(r["references"][0])), "exactly one reference"),
        (lambda r: r["policy"].update(enforcement_mode="advisory"), "enforcement_mode"),
        (lambda r: r["policy"].update(bundle_hash=ZERO_DIGEST), "bundle_hash"),
        (lambda r: r["runtime"].update(measurement=ZERO_DIGEST), "measurement"),
        (lambda r: r.update(subject=g.did_key(OTHER_KEY)), "did:key does not decode"),
        (lambda r: r["tool_transcript"].update(hash=ZERO_DIGEST), "tool_transcript.hash"),
        (lambda r: r["tool_transcript"].update(call_count=2), "call_count"),
    ],
)
def test_correctly_signed_record_with_wrong_content_is_refused(trusted_run, mutate, fragment):
    record = resign_record(trusted_run.outcome.record_artifacts.record, mutate)
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        verify_all(trusted_run, record=record)


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda t: t.update(profile="other"), "unknown transcript profile"),
        (lambda t: t.update(authorization_bridge_digest=ZERO_DIGEST), "authorization_bridge_digest"),
        (lambda t: t["tool_call"]["arguments"].update(path="evil"), "tool_call does not match"),
        (lambda t: t.update(step_up_receipt_digest=ZERO_DIGEST), "step_up_receipt_digest"),
        (lambda t: t["observation"]["observation"].update(request_id="other"), "different request"),
        (lambda t: t["observation"].update(observed_at=NOW + 5), "postdates the record"),
        (lambda t: t.update(tool_response={"ok": False}), "tool_transcript.hash"),
        (lambda t: t.pop("tool_response"), "missing required fields"),
        (lambda t: t.update(extra=1), "unknown fields"),
    ],
)
def test_transcript_preimage_must_match_the_signed_hash_and_the_bridge(trusted_run, mutate, fragment):
    transcript = copy.deepcopy(trusted_run.outcome.record_artifacts.transcript)
    mutate(transcript)
    with pytest.raises(v.CtaVerifyError, match=re.escape(fragment)):
        verify_all(trusted_run, transcript=transcript)


def test_transcript_is_accepted_as_json_text(trusted_run):
    transcript = trusted_run.outcome.record_artifacts.transcript
    assert verify_all(trusted_run, transcript=json.dumps(transcript))["transcript_bound_and_hashed"] is True


def test_policy_bytes_that_differ_from_the_recorded_bundle_are_refused(trusted_run):
    with pytest.raises(v.CtaVerifyError, match="bundle_hash"):
        verify_all(trusted_run, policy_bundle=b'{"profile": "cta-gate-policy/v1"}\n')


def test_every_artifact_check_passes_for_a_step_up_run(stepup_run):
    checked = verify_all(stepup_run)
    assert checked["step_up_receipt_bound"] is True and all(checked.values())
