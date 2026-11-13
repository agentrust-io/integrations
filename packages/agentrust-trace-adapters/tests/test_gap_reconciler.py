"""Section 3.3.4 vectors, plus the consumer cases the #416 contract review required.

The vendored fixtures are the trace-spec corpus. Their chain booleans are not
inputs to the library. Each vector is rebuilt as signed elements, and the
fixture file remains the oracle for the outcome codes.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace_adapters.gap_reconciler import (
    COMPLETE,
    DISCLOSURE_TYPE,
    EFFECT_UNKNOWN,
    GAP_DISCLOSURE_UNVERIFIED,
    HIERARCHY_TYPE,
    INVENTORY_NOT_SUPPLIED,
    RECEIPT_GAP_DISCLOSED,
    RECEIPT_INVALID,
    RECEIPT_MISSING_REQUIRED,
    RECEIPT_PRESENT,
    MalformedInput,
    element_digest,
    parse_untrusted_json,
    reconcile_chain,
    verify_disclosure,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "gap-disclosure"
SESSION = "trace-session-2026-07-06T15:22:11Z"
ISSUER = "did:web:factory.example:safety-controller"
KEY_ID = f"{ISSUER}#ed25519-2026q3"
PARENT_KEY_ID = f"{ISSUER}#ed25519-workload-attestation"
FOREIGN_KEY_ID = f"{ISSUER}#ed25519-unrelated-but-trusted"
CONFUSABLE_KEY_ID = f"{ISSUER}#ED25519-WORKLOAD-ATTESTATION"
UNKNOWN_KEY_ID = f"{ISSUER}#ed25519-2027q1"

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PARENT = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
FOREIGN = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"trace-spec#117 unrelated trusted key").digest()
)
CONFUSABLE = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"trace-spec#117 confusable ancestor key").digest()
)
KEYS = {
    KEY_ID: KEY,
    PARENT_KEY_ID: PARENT,
    FOREIGN_KEY_ID: FOREIGN,
    CONFUSABLE_KEY_ID: CONFUSABLE,
}
FORBIDDEN = {
    "predecessor_present",
    "successor_present",
    "permitted_ancestor_key_ids",
    "claimed_absent_but_present",
}


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64u(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    }


def sign(document: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {field: value for field, value in document.items() if field != "signature"}
    return {**document, "signature": b64u(key.sign(rfc8785.dumps(body)))}


def trust(*key_ids: str, **extra: dict[str, str]) -> dict[str, dict[str, str]]:
    store = {key_id: jwk(KEYS[key_id]) for key_id in key_ids}
    store.update(extra)
    return store


def receipt(
    *,
    issuer_key_id: str,
    key: Ed25519PrivateKey,
    credential_id: str,
    previous: str | None,
    sequence: int,
    session_id: str = SESSION,
    **extra: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": "TraceHop/1.0",
        "credential_id": credential_id,
        "issuer_key_id": issuer_key_id,
        "previous_receipt_hash": previous,
        "sequence": sequence,
        "session_id": session_id,
    }
    body.update(extra)
    return sign(body, key)


def hierarchy(subject_key_id: str, ancestor_key_id: str, key: Ed25519PrivateKey) -> dict[str, Any]:
    return sign(
        {
            "type": HIERARCHY_TYPE,
            "subject_key_id": subject_key_id,
            "ancestor_key_id": ancestor_key_id,
            "issuer_key_id": ancestor_key_id,
        },
        key,
    )


def disclosure_for(
    *,
    previous: str,
    issuer_key_id: str,
    key: Ed25519PrivateKey,
    session_id: str = SESSION,
    cause: str | None = "crash",
    estimate: int | None = 3,
    type_name: str | None = DISCLOSURE_TYPE,
    credential_id: str | None = None,
    omit_estimate: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "previous_receipt_hash": previous,
        "session_id": session_id,
        "issuer_key_id": issuer_key_id,
    }
    if type_name is not None:
        body["type"] = type_name
    if cause is not None:
        body["cause"] = cause
    if not omit_estimate:
        body["receipts_lost_estimate"] = estimate
    if credential_id is not None:
        body["credential_id"] = credential_id
    body.update(extra)
    return sign(body, key)


def tail_flip(value: str) -> str:
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def dumps(element: dict[str, Any]) -> bytes:
    return json.dumps(element).encode("utf-8")


def load_fixtures() -> list[tuple[str, dict[str, Any]]]:
    paths = sorted(FIXTURE_DIR.glob("*.json"))
    return [(path.name, json.loads(path.read_text(encoding="utf-8"))) for path in paths]


def signing_key(key_id: str) -> Ed25519PrivateKey:
    return KEYS.get(key_id, KEY)


def rebuild(doc: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, dict[str, str]]]:
    """Build signed elements that isolate the same rule as one fixture.

    Fixture chain booleans drive the builder. They are not passed to the library.
    """
    flags = doc["context"]["chain"]
    source = doc["gap_disclosure"]
    issuer_key_id = source.get("issuer_key_id", KEY_ID)
    predecessor_issuer = flags["predecessor_issuer_key_id"]
    trusted = doc["trusted_issuer_keys"]
    predecessor = receipt(
        issuer_key_id=predecessor_issuer,
        key=signing_key(predecessor_issuer),
        credential_id="cred-predecessor",
        previous=None,
        sequence=1,
    )
    predecessor_hash = element_digest(predecessor)
    link = source.get("previous_receipt_hash")
    if flags["predecessor_present"] and link == flags["predecessor_hash"]:
        previous = predecessor_hash
    elif flags["predecessor_present"] and link != flags["predecessor_hash"]:
        previous = tail_flip(predecessor_hash)
    else:
        previous = "sha256:" + "b2" * 32

    run = int(flags["consecutive_disclosures"])
    chain: list[dict[str, Any]] = []
    if flags["predecessor_present"]:
        chain.append(predecessor)
    if issuer_key_id == PARENT_KEY_ID:
        chain.append(hierarchy(predecessor_issuer, PARENT_KEY_ID, PARENT))
    cursor = predecessor_hash
    disclosures: list[dict[str, Any]] = []
    for index in range(run):
        last = index == run - 1
        earlier_issuer = predecessor_issuer if predecessor_issuer in KEYS else KEY_ID
        body_issuer = issuer_key_id if last else earlier_issuer
        body_key = signing_key(body_issuer if body_issuer in KEYS else KEY_ID)
        if not last:
            item = disclosure_for(previous=cursor, issuer_key_id=earlier_issuer, key=KEYS[earlier_issuer])
        else:
            estimate = source["receipts_lost_estimate"] if "receipts_lost_estimate" in source else 3
            signed_cause = "crash" if source.get("cause") == "shutdown" else source.get("cause", "crash")
            item = disclosure_for(
                previous=previous if run == 1 else cursor,
                issuer_key_id=body_issuer,
                key=body_key,
                session_id=source.get("session_id", SESSION),
                cause=signed_cause,
                estimate=estimate,
                type_name=source["type"] if "type" in source else None,
                omit_estimate="receipts_lost_estimate" not in source,
            )
            if source.get("signature") == b64u(bytes(32)):
                item = {**item, "signature": b64u(bytes(32))}
            elif source.get("cause") == "shutdown":
                item = {**item, "cause": "shutdown"}
        disclosures.append(item)
        cursor = element_digest(item)
    target = disclosures[-1]
    chain.extend(disclosures)
    if flags["claimed_absent_but_present"]:
        inserted = receipt(
            issuer_key_id=KEY_ID,
            key=KEY,
            credential_id="cred-present-inside-gap",
            previous=predecessor_hash,
            sequence=2,
        )
        chain.insert(1 if flags["predecessor_present"] else 0, inserted)
    if flags["successor_present"]:
        fixture_seal = flags["successor_previous_receipt_hash"]
        fixture_digest = element_digest(source)
        if fixture_seal == fixture_digest:
            seal = element_digest(target)
        elif fixture_seal == flags["predecessor_hash"]:
            seal = predecessor_hash
        else:
            seal = tail_flip(element_digest(target))
        chain.append(
            receipt(
                issuer_key_id=KEY_ID,
                key=KEY,
                credential_id="cred-successor",
                previous=seal,
                sequence=9,
            )
        )
    return target, chain, trusted


@pytest.fixture(scope="module")
def fixtures() -> list[tuple[str, dict[str, Any]]]:
    return load_fixtures()


def test_fixture_corpus_is_the_twenty_vectors(fixtures: list[tuple[str, dict[str, Any]]]) -> None:
    assert [name for name, _ in fixtures] == [
        "01-gap-disclosed-valid.json",
        "02-gap-disclosure-dangling-predecessor.json",
        "03-gap-disclosure-successor-does-not-link.json",
        "04-gap-disclosure-contradicted.json",
        "05-gap-disclosure-foreign-key.json",
        "06-gap-disclosed-parent-key-null-estimate.json",
        "07-gap-disclosure-unknown-key.json",
        "08-gap-disclosure-tampered.json",
        "09-gap-disclosure-key-case-variant.json",
        "10-gap-disclosure-signature-malformed.json",
        "11-gap-disclosure-confusable-ancestor-key.json",
        "12-gap-disclosure-replayed-stream.json",
        "13-gap-disclosure-stream-case-variant.json",
        "14-gap-disclosure-predecessor-link-tail.json",
        "15-gap-disclosure-seal-tail-mismatch.json",
        "16-gap-disclosure-contradicted-at-tail.json",
        "17-gap-disclosure-at-unsealed-tail.json",
        "18-gap-disclosure-tail-with-stale-link.json",
        "19-gap-disclosure-type-version-unknown.json",
        "20-gap-disclosure-type-absent.json",
    ]
    for _, doc in fixtures:
        assert doc["source"]["spec"] == "spec/trace-v0.2.md section 3.3.4"
        assert doc["expected"]["controller_outcome"] == "unknown"


def test_generator_keys_match_the_vendored_trust_anchors() -> None:
    doc = json.loads((FIXTURE_DIR / "01-gap-disclosed-valid.json").read_text(encoding="utf-8"))
    for key_id, key in ((KEY_ID, KEY), (PARENT_KEY_ID, PARENT), (FOREIGN_KEY_ID, FOREIGN)):
        assert doc["trusted_issuer_keys"][key_id] == jwk(key)


def test_every_registered_rule_has_two_fixture_vectors(fixtures: list[tuple[str, dict[str, Any]]]) -> None:
    counts: dict[str, int] = {}
    for _, doc in fixtures:
        expected = doc["expected"]
        for code in [*expected["failures"], *expected["warnings"]]:
            if code != RECEIPT_GAP_DISCLOSED:
                counts[code] = counts.get(code, 0) + 1
    assert set(counts) == {
        "disclosure_type_unsupported",
        "disclosure_issuer_not_chain_key",
        "disclosure_stream_mismatch",
        "disclosure_predecessor_absent",
        "disclosure_contradicted",
        "disclosure_not_sealed_by_successor",
        "disclosure_signature_invalid",
        "disclosure_key_unknown",
        "disclosure_not_yet_sealed",
    }
    assert all(count >= 2 for count in counts.values())


def test_live_tail_contrast_is_pinned_by_identical_fixture_disclosures() -> None:
    sealed = json.loads((FIXTURE_DIR / "01-gap-disclosed-valid.json").read_text(encoding="utf-8"))
    tail = json.loads((FIXTURE_DIR / "17-gap-disclosure-at-unsealed-tail.json").read_text(encoding="utf-8"))
    assert sealed["gap_disclosure"] == tail["gap_disclosure"]
    assert sealed["expected"]["status"] == RECEIPT_GAP_DISCLOSED
    assert tail["expected"]["status"] == GAP_DISCLOSURE_UNVERIFIED
    assert tail["expected"]["failures"] == []


@pytest.mark.parametrize("name,doc", load_fixtures(), ids=lambda item: item if isinstance(item, str) else item["name"])
def test_fixture_vector(name: str, doc: dict[str, Any]) -> None:
    target, chain, trusted = rebuild(doc)
    verdict = verify_disclosure(
        target,
        chain,
        session_id=doc["context"]["session_id"],
        trusted_issuer_keys=trusted,
    )
    expected = doc["expected"]
    assert verdict.status == expected["status"], name
    assert verdict.failures == tuple(expected["failures"]), name
    assert verdict.warnings == tuple(expected["warnings"]), name
    assert verdict.consecutive_disclosures == expected["consecutive_disclosures"], name
    assert verdict.controller_outcome == "unknown"
    assert verdict.effect_status == EFFECT_UNKNOWN
    assert verdict.retry_authorized is False
    assert verdict.cause == target.get("cause") if isinstance(target.get("cause"), str) else None
    assert verdict.linked_predecessor == target.get("previous_receipt_hash")
    assert FORBIDDEN.isdisjoint(verdict.as_fixture_dict())


@pytest.mark.parametrize("name,doc", load_fixtures(), ids=lambda item: item if isinstance(item, str) else "")
def test_fixture_assertion_object_is_not_derived_evidence(name: str, doc: dict[str, Any]) -> None:
    hostile = dict(doc["context"]["chain"])
    verdict = verify_disclosure(
        doc["gap_disclosure"],
        [hostile, doc["gap_disclosure"]],
        session_id=doc["context"]["session_id"],
        trusted_issuer_keys=doc["trusted_issuer_keys"],
    )
    assert verdict.status != RECEIPT_GAP_DISCLOSED, name
    assert verdict.derived_predecessor_present is False


def test_public_api_rejects_fixture_assertion_parameters() -> None:
    for function in (verify_disclosure, reconcile_chain):
        assert FORBIDDEN.isdisjoint(inspect.signature(function).parameters)
    with pytest.raises(TypeError):
        reconcile_chain(  # type: ignore[call-arg]
            [],
            session_id=SESSION,
            trusted_issuer_keys={},
            predecessor_present=True,
        )


def _workflow(
    *,
    include_disclosure: bool,
    seal: bool,
    bind: bool,
    inventory: list[str] | None,
    cause: str = "crash",
    estimate: int | None = 3,
    fence: int | None = None,
    signer: str = KEY_ID,
    ancestor: bool = False,
) -> tuple[list[bytes], dict[str, dict[str, str]], str]:
    first = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-0",
        previous=None,
        sequence=1,
    )
    elements: list[dict[str, Any]] = [first]
    if ancestor:
        elements.append(hierarchy(KEY_ID, PARENT_KEY_ID, PARENT))
    previous = element_digest(first)
    if include_disclosure:
        gap = disclosure_for(
            previous=previous,
            issuer_key_id=signer,
            key=signing_key(signer),
            cause=cause,
            estimate=estimate,
            credential_id="cred-2" if bind else None,
        )
        elements.append(gap)
        previous = element_digest(gap)
    if seal:
        extra = {"cas_fence_epoch": fence} if fence is not None else {}
        elements.append(
            receipt(
                issuer_key_id=KEY_ID,
                key=KEY,
                credential_id="cred-1",
                previous=previous,
                sequence=4,
                **extra,
            )
        )
    trusted = trust(KEY_ID, PARENT_KEY_ID, FOREIGN_KEY_ID)
    return [dumps(element) for element in elements], trusted, SESSION


def test_case_a_missing_hop_without_disclosure_is_not_gap_disclosed() -> None:
    elements, trusted, session = _workflow(include_disclosure=False, seal=True, bind=False, inventory=["cred-0", "cred-1", "cred-2"])
    result = reconcile_chain(
        elements,
        session_id=session,
        trusted_issuer_keys=trusted,
        expected_credential_ids=["cred-0", "cred-1", "cred-2"],
    )
    assert result.status == RECEIPT_MISSING_REQUIRED
    assert result.credentials[-1].status == RECEIPT_MISSING_REQUIRED
    assert result.accepted_as_complete is False
    assert result.policy_accepted is False
    assert result.retry_authorized is False


def test_case_b_two_sided_splice_is_gap_disclosed_not_execution() -> None:
    elements, trusted, session = _workflow(include_disclosure=True, seal=True, bind=True, inventory=["cred-0", "cred-1", "cred-2"])
    result = reconcile_chain(
        elements,
        session_id=session,
        trusted_issuer_keys=trusted,
        expected_credential_ids=["cred-0", "cred-1", "cred-2"],
        accept_disclosed_gaps=True,
    )
    assert result.disclosures[0].status == RECEIPT_GAP_DISCLOSED
    assert result.disclosures[0].derived_predecessor_present is True
    assert result.disclosures[0].derived_successor_present is True
    assert result.credentials[2].status == RECEIPT_GAP_DISCLOSED
    assert result.status == RECEIPT_GAP_DISCLOSED
    assert result.accepted_as_complete is False
    assert result.effect_status == EFFECT_UNKNOWN
    assert result.retry_authorized is False
    assert result.policy_accepted is True
    refused = reconcile_chain(
        elements,
        session_id=session,
        trusted_issuer_keys=trusted,
        expected_credential_ids=["cred-0", "cred-1", "cred-2"],
        completeness_required=True,
        accept_disclosed_gaps=True,
    )
    assert refused.policy_accepted is False
    assert refused.accepted_as_complete is False


def test_tail_disclosure_is_unverified_and_not_coverage() -> None:
    elements, trusted, session = _workflow(include_disclosure=True, seal=False, bind=True, inventory=["cred-0", "cred-2"])
    result = reconcile_chain(
        elements,
        session_id=session,
        trusted_issuer_keys=trusted,
        expected_credential_ids=["cred-0", "cred-2"],
        accept_disclosed_gaps=True,
    )
    assert result.disclosures[0].status == GAP_DISCLOSURE_UNVERIFIED
    assert result.disclosures[0].failures == ()
    assert result.disclosures[0].warnings == ("disclosure_not_yet_sealed",)
    assert result.credentials[1].status == GAP_DISCLOSURE_UNVERIFIED
    assert result.status == GAP_DISCLOSURE_UNVERIFIED
    assert result.policy_accepted is False
    assert result.accepted_as_complete is False


def test_truncated_chain_does_not_infer_the_omitted_credential() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    second = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(first),
        sequence=2,
    )
    chain = [dumps(first), dumps(second)]
    trusted = trust(KEY_ID)
    without_inventory = reconcile_chain(chain, session_id=SESSION, trusted_issuer_keys=trusted)
    assert without_inventory.status == INVENTORY_NOT_SUPPLIED
    assert without_inventory.credentials == ()
    with_inventory = reconcile_chain(
        chain,
        session_id=SESSION,
        trusted_issuer_keys=trusted,
        expected_credential_ids=["cred-0", "cred-1", "cred-2"],
    )
    assert [item.status for item in with_inventory.credentials] == [
        RECEIPT_PRESENT,
        RECEIPT_PRESENT,
        RECEIPT_MISSING_REQUIRED,
    ]
    assert with_inventory.status == RECEIPT_MISSING_REQUIRED


def test_unbound_disclosure_does_not_cover_an_omitted_credential() -> None:
    elements, trusted, session = _workflow(
        include_disclosure=True,
        seal=True,
        bind=False,
        inventory=["cred-0", "cred-1", "cred-2"],
    )
    result = reconcile_chain(
        elements,
        session_id=session,
        trusted_issuer_keys=trusted,
        expected_credential_ids=["cred-0", "cred-1", "cred-2"],
    )
    assert result.disclosures[0].status == RECEIPT_GAP_DISCLOSED
    assert result.credentials[2].status == RECEIPT_MISSING_REQUIRED
    assert result.status == RECEIPT_MISSING_REQUIRED


def test_cause_and_fence_epoch_do_not_change_the_outcome_or_authorize_retry() -> None:
    baselines = []
    for cause, estimate, fence in (
        ("crash", 3, None),
        ("delegation_revoked", 0, 1),
        ("lease_id=lease-9", None, 4),
        ("cas_fence_epoch=99", 99, 99),
        ("lease_id=lease-9; cas_fence_epoch=100", -1, 100),
    ):
        elements, trusted, session = _workflow(
            include_disclosure=True,
            seal=True,
            bind=True,
            inventory=["cred-0", "cred-1", "cred-2"],
            cause=cause,
            estimate=estimate,
            fence=fence,
        )
        result = reconcile_chain(
            elements,
            session_id=session,
            trusted_issuer_keys=trusted,
            expected_credential_ids=["cred-0", "cred-1", "cred-2"],
        )
        baselines.append(
            (
                result.status,
                result.disclosures[0].failures,
                result.disclosures[0].warnings,
                result.effect_status,
                result.retry_authorized,
                result.credentials[2].status,
            )
        )
        assert result.disclosures[0].cause == cause
        assert result.disclosures[0].receipts_lost_estimate == estimate
    assert baselines == [baselines[0]] * len(baselines)
    assert baselines[0][0] == RECEIPT_GAP_DISCLOSED
    assert baselines[0][4] is False


def test_malformed_descriptive_fields_do_not_select_an_outcome_by_value() -> None:
    statuses = []
    for cause in ({"lease_id": "lease-1"}, {"unrelated": True}, 5):
        first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
        unsigned = {
            "type": DISCLOSURE_TYPE,
            "previous_receipt_hash": element_digest(first),
            "session_id": SESSION,
            "issuer_key_id": KEY_ID,
            "cause": cause,
            "receipts_lost_estimate": 3,
        }
        gap = sign(unsigned, KEY)
        successor = receipt(
            issuer_key_id=KEY_ID,
            key=KEY,
            credential_id="cred-1",
            previous=element_digest(gap),
            sequence=3,
        )
        verdict = verify_disclosure(gap, [first, gap, successor], session_id=SESSION, trusted_issuer_keys=trust(KEY_ID))
        statuses.append((verdict.status, verdict.failures, verdict.effect_status, verdict.retry_authorized))
    assert statuses == [(RECEIPT_INVALID, ("disclosure_descriptive_field_malformed",), EFFECT_UNKNOWN, False)] * 3


def test_claimed_absent_record_inside_the_gap_impeaches_the_disclosure() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    hidden = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-hidden", previous=element_digest(first), sequence=2)
    gap = disclosure_for(previous=element_digest(first), issuer_key_id=KEY_ID, key=KEY)
    successor = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(gap),
        sequence=6,
    )
    verdict = verify_disclosure(
        gap,
        [first, hidden, gap, successor],
        session_id=SESSION,
        trusted_issuer_keys=trust(KEY_ID),
    )
    assert verdict.status == RECEIPT_INVALID
    assert verdict.failures == ("disclosure_contradicted",)
    assert element_digest(hidden) in verdict.derived_contradicting_digests


def test_sequence_inside_the_splice_span_is_a_contradiction() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    gap = disclosure_for(previous=element_digest(first), issuer_key_id=KEY_ID, key=KEY)
    successor = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(gap),
        sequence=6,
    )
    outside = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-late",
        previous=element_digest(successor),
        sequence=3,
    )
    verdict = verify_disclosure(
        gap,
        [first, gap, successor, outside],
        session_id=SESSION,
        trusted_issuer_keys=trust(KEY_ID),
    )
    assert "disclosure_contradicted" in verdict.failures
    assert element_digest(outside) in verdict.derived_contradicting_digests


def test_unauthorized_and_confusable_ancestor_signers_are_rejected() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    foreign = disclosure_for(previous=element_digest(first), issuer_key_id=FOREIGN_KEY_ID, key=FOREIGN)
    sealed = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(foreign),
        sequence=4,
    )
    trusted = trust(KEY_ID, FOREIGN_KEY_ID, PARENT_KEY_ID)
    verdict = verify_disclosure(foreign, [first, foreign, sealed], session_id=SESSION, trusted_issuer_keys=trusted)
    assert verdict.failures == ("disclosure_issuer_not_chain_key",)

    listed = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-0",
        previous=None,
        sequence=1,
        permitted_ancestor_key_ids=[PARENT_KEY_ID],
    )
    parent_signed = disclosure_for(previous=element_digest(listed), issuer_key_id=PARENT_KEY_ID, key=PARENT)
    parent_seal = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(parent_signed),
        sequence=4,
    )
    unsigned_list = verify_disclosure(
        parent_signed,
        [listed, parent_signed, parent_seal],
        session_id=SESSION,
        trusted_issuer_keys=trusted,
    )
    assert unsigned_list.failures == ("disclosure_issuer_not_chain_key",)
    assert unsigned_list.derived_ancestor_key_ids == ()

    statement = hierarchy(KEY_ID, PARENT_KEY_ID, PARENT)
    authorized_gap = disclosure_for(previous=element_digest(first), issuer_key_id=PARENT_KEY_ID, key=PARENT)
    authorized_seal = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(authorized_gap),
        sequence=4,
    )
    authorized = verify_disclosure(
        authorized_gap,
        [first, statement, authorized_gap, authorized_seal],
        session_id=SESSION,
        trusted_issuer_keys=trusted,
    )
    assert authorized.status == RECEIPT_GAP_DISCLOSED
    assert authorized.derived_ancestor_key_ids == (PARENT_KEY_ID,)


def test_duplicate_hop_is_not_a_fenced_retry() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    again = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-0",
        previous=element_digest(first),
        sequence=2,
        cas_fence_epoch=8,
    )
    result = reconcile_chain(
        [dumps(first), dumps(again)],
        session_id=SESSION,
        trusted_issuer_keys=trust(KEY_ID),
        expected_credential_ids=["cred-0"],
    )
    assert result.credentials[0].status == RECEIPT_INVALID
    assert result.retry_authorized is False
    assert result.effect_status == EFFECT_UNKNOWN


def test_complete_inventory_is_accepted_only_without_a_gap() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    second = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(first),
        sequence=2,
    )
    result = reconcile_chain(
        [dumps(first), dumps(second)],
        session_id=SESSION,
        trusted_issuer_keys=trust(KEY_ID),
        expected_credential_ids=["cred-0", "cred-1"],
        completeness_required=True,
    )
    assert result.status == COMPLETE
    assert result.accepted_as_complete is True
    assert result.policy_accepted is True


@pytest.mark.parametrize(
    "payload,message",
    [
        (b'{"a":1,"a":2}', "duplicate JSON key"),
        (b'{"a":NaN}', "non-finite JSON number"),
        (b'{"a":Infinity}', "non-finite JSON number"),
        (b'{"a":1.5}', "non-integral JSON number"),
        (b"[1]", "untrusted JSON must be an object"),
        (b'{"n":9007199254740993}', "integer outside the safe range"),
        (b'{"d":' + b'{"x":' * 40 + b"1" + b"}" * 40 + b"}", "JSON nesting exceeds"),
    ],
)
def test_bounded_parser_refuses_malformed_input(payload: bytes, message: str) -> None:
    with pytest.raises(MalformedInput, match=message):
        parse_untrusted_json(payload)


def test_oversize_element_is_refused() -> None:
    with pytest.raises(MalformedInput, match="size bound"):
        parse_untrusted_json(b'{"pad":"' + b"a" * 70_000 + b'"}')


def test_private_jwk_is_not_a_trust_anchor() -> None:
    private = {**jwk(KEY), "d": b64u(bytes(range(32)))}
    with pytest.raises(MalformedInput, match="private key material"):
        reconcile_chain([], session_id=SESSION, trusted_issuer_keys={KEY_ID: private})


def test_non_canonical_signature_is_invalid_not_an_exception() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    gap = disclosure_for(previous=element_digest(first), issuer_key_id=KEY_ID, key=KEY)
    padded = {**gap, "signature": gap["signature"] + "="}
    successor = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(gap),
        sequence=3,
    )
    verdict = verify_disclosure(
        padded,
        [first, padded, successor],
        session_id=SESSION,
        trusted_issuer_keys=trust(KEY_ID),
    )
    assert verdict.failures[0] == "disclosure_signature_invalid"


def test_identical_disclosure_bytes_change_outcome_only_when_the_seal_exists() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    gap = disclosure_for(previous=element_digest(first), issuer_key_id=KEY_ID, key=KEY)
    successor = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(gap),
        sequence=3,
    )
    trusted = trust(KEY_ID)
    sealed = verify_disclosure(gap, [first, gap, successor], session_id=SESSION, trusted_issuer_keys=trusted)
    tail = verify_disclosure(gap, [first, gap], session_id=SESSION, trusted_issuer_keys=trusted)
    assert sealed.status == RECEIPT_GAP_DISCLOSED
    assert tail.status == GAP_DISCLOSURE_UNVERIFIED
    assert tail.failures == ()
    assert tail.warnings == ("disclosure_not_yet_sealed",)


def test_reconcile_chain_judges_a_typeless_disclosure() -> None:
    first = receipt(issuer_key_id=KEY_ID, key=KEY, credential_id="cred-0", previous=None, sequence=1)
    gap = disclosure_for(
        previous=element_digest(first),
        issuer_key_id=KEY_ID,
        key=KEY,
        type_name=None,
    )
    assert "type" not in gap
    successor = receipt(
        issuer_key_id=KEY_ID,
        key=KEY,
        credential_id="cred-1",
        previous=element_digest(gap),
        sequence=3,
    )
    result = reconcile_chain(
        [dumps(first), dumps(gap), dumps(successor)],
        session_id=SESSION,
        trusted_issuer_keys=trust(KEY_ID),
        expected_credential_ids=["cred-0", "cred-1"],
    )
    assert result.disclosures[0].failures == ("disclosure_type_unsupported",)
    assert result.status == RECEIPT_INVALID
