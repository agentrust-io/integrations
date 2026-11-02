"""xChk sealed receipts as TRACE `approval-outcome` references.

Re-verifies examples/approval-outcome/ without xChk installed. The fixtures were
minted by the registry at in.xchk.io (scripts/trace-fixtures.js in minitru/xchk-server),
which also wrote expected.json. A generator's own summary of its output is a claim, so
every outcome here is recomputed from the committed bytes and compared with
expected.json, never read from it: the Trust Records with this repository's library,
the reference digests with rfc8785, and the bundles with the registry's own
standard-library verifier, vendored beside the fixtures and run as a subprocess.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature

from agentrust_trace import verify_record

XCHK_DIR = Path(__file__).resolve().parents[1] / "examples" / "approval-outcome"
VERIFIER = Path(__file__).resolve().parents[1] / "verify_receipt.py"
# 2 Nov 2026 (review of #350, drk-ram): the registry's key document, /.well-known/xchk-keys.json as served on 2 Nov 2026,
# pinned here as the relying party would pin it (the Trust Record signer is pinned the same way in expected.json). The
# verifier checks every signature with the keys the BUNDLE carries; only this document says those keys are the registry's.
KEY_DOCUMENT = XCHK_DIR / "xchk-keys" / "in.xchk.io.2026-11-02.json"
# The fixtures were minted on 17 Oct 2026; a historical record is re-verified under an explicit, finite bound (ten
# years, the same as the workflow), never by switching the bound off (section 3.2.2).
MAX_AGE = 315360000
EXPECTED = json.loads((XCHK_DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
OUTCOME_KEYS = ("trace_record_verifies", "reference_resolves", "digest_matches", "bundle_verifies",
                "disposition", "registry_keys_pinned", "verdict")


def _load(name: str) -> dict:
    return json.loads((XCHK_DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _verify(bundle_path: Path, require_approval: bool = False, key_document: Path | None = None) -> dict:
    """The registry's offline verifier, run as it ships, with --json: the structured report (exit, result, the checks
    that ran, the pending count, the approval evidence still missing, the amendment's standing). Exit 0 means no check
    FAILED (pending steps are listed, not failed); with --require-approval it also means the approval evidence was
    present and checked. Absence of failure is not verification of an approval, so the verdict below asks for both,
    and it reads the amendment from the report, never from the bundle's unsigned text. With --keys (2 Nov 2026) the
    bundle's pinned keys are also checked against the registry's key document; `keyDocument.allPinned` says so."""
    args = [sys.executable, "-I", str(VERIFIER), str(bundle_path), "--json"] + (["--require-approval"] if require_approval else [])
    if key_document is not None:
        args += ["--keys", str(key_document)]
    proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=60)
    report = json.loads(proc.stdout)
    assert report["exit"] == proc.returncode
    return report


def _approval_reference(record: dict) -> dict:
    refs = [r for r in record["references"] if r["rel"] == "approval-outcome"]
    assert len(refs) == 1, "one approval-outcome per fixture"
    return refs[0]


def _record_verifies(record: dict) -> bool:
    try:
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=MAX_AGE)
    except (InvalidSignature, ValueError):
        return False
    return True


def _assess(record: dict, bundle_name: str | None, bundle_override: dict | None = None, tmp_dir: Path | None = None,
            key_document: Path | None = KEY_DOCUMENT) -> dict:
    """What a relying party concludes about the approval a record points at. `bundle_override` lets a test present
    a mutated bundle for the same record; it is written to `tmp_dir` for the verifier. `key_document` is the registry's
    key document the relying party pinned (2 Nov 2026); None means it pinned nothing, and the strongest verdict is then
    approval-consistent-key-not-pinned: consistent under the bundle's own keys, which is all the verifier can check."""
    verifies = _record_verifies(record)
    if not verifies:
        # A Trust Record that does not verify is not evidence of anything, including the reference it carries: no
        # verdict about the approval is drawn from it, with or without a bundle (review of #350, 20 Oct 2026). Before
        # this, the record check ran and was reported but did not decide the verdict, so a record with one signed field
        # changed still reached approval-confirmed through its intact bundle.
        return {"trace_record_verifies": False, "reference_resolves": None,
                "digest_matches": None, "bundle_verifies": None, "disposition": None,
                "registry_keys_pinned": None, "verdict": "record-invalid"}
    reference = _approval_reference(record)
    assert reference["resolver"] == EXPECTED["resolver"]
    assert len(reference["id"]) == 64
    if bundle_name is None:
        return {"trace_record_verifies": verifies, "reference_resolves": False,
                "digest_matches": None, "bundle_verifies": None, "disposition": None,
                "registry_keys_pinned": None, "verdict": "approval-unconfirmed"}
    if bundle_override is not None:
        bundle = bundle_override
        assert tmp_dir is not None
        bundle_path = tmp_dir / bundle_name
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    else:
        bundle = _load(bundle_name)
        bundle_path = XCHK_DIR / bundle_name
    digest_matches = _jcs_sha256(bundle["record"]) == reference["digest"]
    report = _verify(bundle_path)
    bundle_ok = report["exit"] == 0
    disposition = bundle["record"].get("disposition")
    # an approval is "as amended" only when the verifier found the SEALED record committing to the amended command and
    # the amendment citing the signed ask; the bundle's decision.amendment text selects nothing on its own
    amended = bool(report["amendment"] and report["amendment"]["committed"])
    keys_pinned = None
    if not (digest_matches and bundle_ok):
        verdict = "approval-contradicted"
    elif disposition != "approved":
        verdict = "not-an-approval"
    elif (strict := _verify(bundle_path, require_approval=True))["exit"] != 0:
        # approved on the record, but the evidence that would confirm it is absent: not contradicted, not confirmed.
        # Approval evidence present with the seal chain incomplete is its own verdict (review of #350, 20 Oct 2026):
        # the person's answer checks out, the receipt's place in the sealed chain does not.
        verdict = "approval-unverified" if strict["approvalEvidenceMissing"] else "approval-unsealed"
    elif key_document is None or (pinned := _verify(bundle_path, require_approval=True, key_document=key_document))["exit"] != 0:
        # 2 Nov 2026 (review of #350, drk-ram): every check so far was made with the keys the bundle carries, so a
        # bundle re-signed under someone else's keys reaches this point with every check passed (fixture 09). Only the
        # registry's key document, pinned by the relying party, says the keys are the registry's. Without it, or with
        # a key the document does not list, the approval is consistent, never confirmed.
        keys_pinned = False if key_document is not None else None
        if key_document is not None:
            assert pinned["keyDocument"]["allPinned"] is False, "the only check --keys adds is the key document's"
        verdict = "approval-consistent-key-not-pinned"
    elif amended:
        keys_pinned = True
        verdict = "approval-confirmed-as-amended"
    else:
        keys_pinned = True
        verdict = "approval-confirmed"
    return {"trace_record_verifies": verifies, "reference_resolves": True,
            "digest_matches": digest_matches, "bundle_verifies": bundle_ok,
            "disposition": disposition, "registry_keys_pinned": keys_pinned, "verdict": verdict}


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    committed = {
        p.name for p in XCHK_DIR.glob("0*.json") if not p.name.endswith(".bundle.json")
    }
    assert committed == set(CASES)
    for name in CASES:
        bundle = EXPECTED["cases"][name]["bundle"]
        assert bundle is None or (XCHK_DIR / bundle).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_trust_record(name: str) -> None:
    """Rule 3 of section 3.1.2: the record stands whatever the reference resolves to."""
    verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=MAX_AGE)


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    got = _assess(_load(name), EXPECTED["cases"][name]["bundle"])
    want = {k: EXPECTED["cases"][name][k] for k in OUTCOME_KEYS}
    assert got == want


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-approval-confirmed.json"))
    _approval_reference(record)["id"] = "0" * 64
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=MAX_AGE)


def test_a_stale_record_is_rejected_under_the_default_bound() -> None:
    """The bound is finite and explicit; the fixtures are historical, so the library's default 24 hours rejects them."""
    with pytest.raises(ValueError):
        verify_record(_load("01-approval-confirmed.json"), EXPECTED["trace_signer_jwk"])


@pytest.mark.parametrize("strip", ["approver", "assertion", "binding", "challenge"])
def test_missing_approval_evidence_is_not_a_confirmation(strip: str, tmp_path: Path) -> None:
    """Removing evidence leaves the verifier with pending steps and exit 0; an approval verdict needs more than
    'nothing failed'. The record stays approved on its face; the verdict is unverified, never confirmed."""
    record, bundle = _load("01-approval-confirmed.json"), _load("01-approval-confirmed.bundle.json")
    if strip == "approver":
        bundle.pop("approver")
    else:
        bundle["approver"].pop(strip)
    got = _assess(record, "01-approval-confirmed.bundle.json", bundle_override=bundle, tmp_dir=tmp_path)
    assert got["digest_matches"] and got["bundle_verifies"]
    assert got["verdict"] == "approval-unverified"


def test_an_assertion_for_another_ceremony_by_the_same_credential_is_refused(tmp_path: Path) -> None:
    """The genuine denial's passkey answer (same credential, another ceremony), placed beside the approval's genuine
    signed binding, with the outer attestation id edited to agree with it. Every signature is real; the ask does
    not name the ceremony the sealed record and the binding commit to."""
    record = _load("01-approval-confirmed.json")
    good, denied = _load("01-approval-confirmed.bundle.json"), _load("03-decision-is-a-denial.bundle.json")
    assert good["approver"]["credentialId"] == denied["approver"]["credentialId"]
    b = copy.deepcopy(good)
    for k in ("assertion", "challenge", "attestationId"):
        b["approver"][k] = copy.deepcopy(denied["approver"][k])
    b["decision"] = copy.deepcopy(denied["decision"])
    assert b["record"] == good["record"] and b["approver"]["binding"] == good["approver"]["binding"]
    got = _assess(record, "01-approval-confirmed.bundle.json", bundle_override=b, tmp_dir=tmp_path)
    assert got["digest_matches"] and not got["bundle_verifies"]
    assert got["verdict"] == "approval-contradicted"


def test_unsigned_outer_labels_are_not_the_evidence() -> None:
    """The approver's email and assurance a relying party reports must come from the signed binding; the outer
    fields are not evidence. This pins the binding's values as the ones to read."""
    bundle = _load("01-approval-confirmed.bundle.json")
    bound = bundle["approver"]["binding"]["fields"]
    assert bound["approverEmail"] == bundle["approver"]["email"]
    assert bound["authLevel"] == bundle["approver"]["authLevel"]
    bundle["approver"]["email"] = "synthetic-other-person@example.invalid"
    bundle["approver"]["authLevel"] = "synthetic-elevated-assurance"
    assert bundle["approver"]["binding"]["fields"] == bound, "the signed statement is untouched by an outer edit"


def test_the_reference_digest_is_the_registry_record_hash() -> None:
    """One number on both sides: rfc8785 over bundle.record equals the registry's own hash."""
    bundle = _load("01-approval-confirmed.bundle.json")
    assert _jcs_sha256(bundle["record"]) == "sha256:" + bundle["recordHash"]
    reference = _approval_reference(_load("01-approval-confirmed.json"))
    assert reference["digest"] == "sha256:" + bundle["recordHash"]


def test_the_altered_bundle_differs_in_one_field_only() -> None:
    before = _load("01-approval-confirmed.bundle.json")
    after = _load("02-bundle-altered-after-issue.bundle.json")
    assert after["record"]["summary"] != before["record"]["summary"]
    after["record"]["summary"] = before["record"]["summary"]
    assert after == before


def test_the_impersonated_approver_offers_a_key_the_binding_does_not_name() -> None:
    """The assertion in 06 verifies with the key the bundle offers; the binding names another."""
    before = _load("01-approval-confirmed.bundle.json")
    after = _load("06-assertion-from-another-credential.bundle.json")
    a_before, a_after = before["approver"], after["approver"]
    assert a_after["publicKey"]["raw"] != a_before["publicKey"]["raw"]
    assert a_after["binding"] == a_before["binding"]
    assert a_after["binding"]["fields"]["publicKey"] == a_before["publicKey"]["raw"]
    for field in ("authenticatorData", "clientDataJSON"):
        assert a_after["assertion"][field] == a_before["assertion"][field]
    assert a_after["assertion"]["signature"] != a_before["assertion"]["signature"]


def test_the_crossed_assertion_is_the_same_persons_answer_to_another_ask() -> None:
    """08: key, binding and user verification all genuine; the challenge the device signed names
    another ask."""
    before = _load("01-approval-confirmed.bundle.json")
    after = _load("08-assertion-over-another-ask.bundle.json")
    a_before, a_after = before["approver"], after["approver"]
    assert a_after["publicKey"] == a_before["publicKey"]
    assert a_after["binding"] == a_before["binding"]
    assert a_after["credentialId"] == a_before["credentialId"]
    assert a_after["challenge"] == a_before["challenge"]
    assert a_after["challenge"]["rule"] == "ask-v1"
    assert a_after["assertion"] != a_before["assertion"]
    a_after["assertion"] = a_before["assertion"]
    assert after == before


def test_an_amendment_typed_into_the_bundle_is_not_an_approval_with_changes(tmp_path: Path) -> None:
    """decision.amendment is unsigned text. Added to the plain approval after issue, with every signature intact, it
    selects nothing: the sealed record's paramsHash does not recompute over it, the verifier fails, and the verdict
    is contradicted, never 'as amended'."""
    record, bundle = _load("01-approval-confirmed.json"), _load("01-approval-confirmed.bundle.json")
    bundle["decision"]["amendment"] = {"command": "synthetic alternate command", "byEmail": bundle["decision"]["by"],
                                       "at": bundle["decision"]["respondedAt"],
                                       "originalParamsHash": bundle["decision"]["actionParamsHash"]}
    got = _assess(record, "01-approval-confirmed.bundle.json", bundle_override=bundle, tmp_dir=tmp_path)
    assert got["digest_matches"] and not got["bundle_verifies"]
    assert got["verdict"] == "approval-contradicted"


def test_the_amended_command_is_the_one_the_sealed_record_commits_to(tmp_path: Path) -> None:
    """07 as committed: record.paramsHash is the registry's action-binding digest over the AMENDED command with the
    record's own tool and summary (recomputed here with rfc8785, not with the verifier), and the amendment cites the
    ask the person signed. Edit either and the approval is contradicted."""
    record, bundle = _load("07-amended.json"), _load("07-amended.bundle.json")
    am = bundle["decision"]["amendment"]
    binding = {"tool": bundle["record"]["tool"], "command": am["command"][:2000], "path": None,
               "summary": bundle["record"]["summary"][:2000], "amount": None, "artifactHash": None}
    assert bundle["record"]["paramsHash"] == hashlib.sha256(rfc8785.dumps(binding)).hexdigest()
    assert am["originalParamsHash"] == bundle["decision"]["actionParamsHash"] == bundle["approver"]["challenge"]["fields"]["actionParamsHash"]
    assert bundle["record"]["paramsHash"] != am["originalParamsHash"], "the sealed act is not the ask as proposed"
    assert _assess(record, "07-amended.bundle.json")["verdict"] == "approval-confirmed-as-amended"
    for mutate in (lambda b: b["decision"]["amendment"].__setitem__("command", am["command"] + " ; synthetic extra"),
                   lambda b: b["decision"]["amendment"].__setitem__("originalParamsHash", "0" * 64),
                   lambda b: b["decision"]["amendment"].pop("originalParamsHash")):
        b = copy.deepcopy(bundle)
        mutate(b)
        got = _assess(record, "07-amended.bundle.json", bundle_override=b, tmp_dir=tmp_path)
        assert got["digest_matches"] and not got["bundle_verifies"]
        assert got["verdict"] == "approval-contradicted"


def test_the_crossed_ask_stripped_of_its_challenge_is_never_confirmed(tmp_path: Path) -> None:
    """08 with approver.challenge removed. The bundle cannot tell an ask-v1 ceremony whose challenge was deleted from a
    ceremony before ask-v1, so the verdict falls from contradicted to unverified: weaker evidence, never a
    confirmation. Pinned here so a change that lets it reach 'approval-confirmed' fails."""
    record, bundle = _load("08-assertion-over-another-ask.json"), _load("08-assertion-over-another-ask.bundle.json")
    bundle["approver"].pop("challenge")
    got = _assess(record, "08-assertion-over-another-ask.bundle.json", bundle_override=bundle, tmp_dir=tmp_path)
    assert got["verdict"] == "approval-unverified"


def test_relabelled_identity_is_reported_from_the_binding(tmp_path: Path) -> None:
    """The verifier's structured report names the person from the registry-signed binding, not the readable labels."""
    bundle = _load("01-approval-confirmed.bundle.json")
    bound = bundle["approver"]["binding"]["fields"]
    bundle["approver"]["email"] = "synthetic-other-person@example.invalid"
    bundle["approver"]["authLevel"] = "synthetic-elevated-assurance"
    p = tmp_path / "relabelled.bundle.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    report = _verify(p, require_approval=True)
    assert report["exit"] == 0
    assert report["boundIdentity"]["email"] == bound["approverEmail"]
    assert report["boundIdentity"]["authLevel"] == bound["authLevel"]


@pytest.mark.parametrize("strip", ["seal", "merkle", "seal+merkle", "seal-signature"])
def test_an_approval_without_its_seal_chain_is_not_confirmed(strip: str, tmp_path: Path) -> None:
    """Review of #350 (noah-ing, 20 Oct 2026): the approval evidence intact, the seal, the Merkle path or the registry's
    signature over the seal removed. Strict mode refuses, and the verdict is approval-unsealed, never confirmed."""
    record, bundle = _load("01-approval-confirmed.json"), _load("01-approval-confirmed.bundle.json")
    if strip in ("seal", "seal+merkle"):
        bundle.pop("seal")
    if strip in ("merkle", "seal+merkle"):
        bundle.pop("merkle")
    if strip == "seal-signature":
        bundle["registrySignature"].pop("signature", None)
        bundle["registrySignature"].pop("signatures", None)
    got = _assess(record, "01-approval-confirmed.bundle.json", bundle_override=bundle, tmp_dir=tmp_path)
    assert got["digest_matches"] and got["bundle_verifies"]
    assert got["verdict"] == "approval-unsealed"


def test_a_bundle_re_keyed_outside_the_registry_is_consistent_never_confirmed(tmp_path: Path) -> None:
    """Review of #350 (drk-ram, 2 Nov 2026): fixture 01 re-signed under his own Ed25519 and ML-DSA-65 keys, the pinned
    key list and the root statement's list rewritten to match (09, rebuilt by tests/rekey_fixture.py). The verifier
    passed it under --require-approval and this assessor said approval-confirmed, because every key either checks is
    the one the bundle carries. Now: with the registry's key document pinned, 09 is approval-consistent-key-not-pinned
    and 01 is confirmed; with no document pinned, even 01 is only consistent. The Trust Record is 01's, unchanged: the
    record points at the same sealed receipt, and the tampering is on the carrier."""
    before, after = _load("01-approval-confirmed.bundle.json"), _load("09-re-keyed-outside-the-registry.bundle.json")
    assert after["record"] == before["record"] and after["seal"] == before["seal"] and after["merkle"] == before["merkle"]
    assert after["approver"]["assertion"] == before["approver"]["assertion"]
    assert {k["keyId"] for k in after["registrySignature"]["keys"]}.isdisjoint({k["keyId"] for k in before["registrySignature"]["keys"]})
    record = _load("09-re-keyed-outside-the-registry.json")
    assert record == _load("01-approval-confirmed.json")
    got = _assess(record, "09-re-keyed-outside-the-registry.bundle.json")
    assert got["digest_matches"] and got["bundle_verifies"] and got["registry_keys_pinned"] is False
    assert got["verdict"] == "approval-consistent-key-not-pinned"
    assert _verify(XCHK_DIR / "09-re-keyed-outside-the-registry.bundle.json", require_approval=True)["exit"] == 0, "the finding: strict mode alone passes it"
    control = _assess(_load("01-approval-confirmed.json"), "01-approval-confirmed.bundle.json")
    assert control["verdict"] == "approval-confirmed" and control["registry_keys_pinned"] is True
    unpinned = _assess(_load("01-approval-confirmed.json"), "01-approval-confirmed.bundle.json", key_document=None)
    assert unpinned["verdict"] == "approval-consistent-key-not-pinned" and unpinned["registry_keys_pinned"] is None
    assert _assess(_load("07-amended.json"), "07-amended.bundle.json", key_document=None)["verdict"] == "approval-consistent-key-not-pinned"
    # a verdict below confirmed is unchanged by the document: a contradicted bundle stays contradicted, pinned or not
    assert _assess(_load("02-bundle-altered-after-issue.json"), "02-bundle-altered-after-issue.bundle.json", key_document=None)["verdict"] == "approval-contradicted"


@pytest.mark.parametrize("field,value", [("data_class", "public")])
def test_a_tampered_trust_record_is_never_a_confirmed_approval(field: str, value: str) -> None:
    """The intact record confirms; the same record with one signed field changed and the bundle and reference untouched
    is record-invalid, not approval-confirmed (review of #350, 20 Oct 2026)."""
    record = _load("01-approval-confirmed.json")
    bundle = EXPECTED["cases"]["01-approval-confirmed.json"]["bundle"]
    control = _assess(record, bundle)
    assert control["trace_record_verifies"] is True
    assert control["verdict"] == "approval-confirmed"
    altered = copy.deepcopy(record)
    assert altered[field] != value
    altered[field] = value
    result = _assess(altered, bundle)
    assert result["trace_record_verifies"] is False
    assert result["verdict"] == "record-invalid"
    # the same holds with no bundle to read: an invalid record is not even an unconfirmed approval
    assert _assess(altered, None)["verdict"] == "record-invalid"
