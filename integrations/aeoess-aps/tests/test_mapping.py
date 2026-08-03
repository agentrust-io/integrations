"""APS to TRACE mapping tests.

Covers the mapping itself, the refusals that keep an unverified APS decision
from becoming a TRACE record, and a level 0 conformance run against the emitted
record. Decisions are minted in-process with ephemeral keys, so no network
access, no credentials and no committed fixtures are involved.

A committed decision fixture is impossible here on purpose: APS decisions
expire five minutes after evaluation and the mapper refuses expired input.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import agentrust_trace
import pytest
from agent_passport.crypto import generate_key_pair
from agent_passport.policy import FloorValidatorV1, create_action_intent, evaluate_intent

from aps_trace import EAT_PROFILE, VERDICT_TO_APPRAISAL, build_trace_record

FLOOR_VERSION = "floor-1.0"

#: TRACE v0.2 schema-required fields an APS policy decision cannot supply.
#: Pinned so the omission stays deliberate. See the README.
DOCUMENTED_ABSENT_REQUIRED = {"model", "data_class", "build_provenance"}


def _jwk() -> dict:
    return agentrust_trace.key_to_jwk(agentrust_trace.generate_key())


def _context(*, scope: list[str], spend_limit: int | None = None, spent: int = 0) -> dict:
    delegation: dict = {
        "scope": scope,
        "revoked": False,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "maxDepth": 3,
        "currentDepth": 1,
    }
    if spend_limit is not None:
        delegation["spendLimit"] = spend_limit
        delegation["spentAmount"] = spent
    return {
        "floorVersion": FLOOR_VERSION,
        "agentRegistered": True,
        "agentAttestationValid": True,
        "delegation": delegation,
    }


def _decide(action: dict, context: dict, *, ttl_minutes: int = 5) -> dict:
    agent = generate_key_pair()
    evaluator = generate_key_pair()
    intent = create_action_intent(
        agent_id="agent_test",
        agent_public_key=agent["publicKey"],
        delegation_id="dlg_test",
        action=action,
        private_key=agent["privateKey"],
    )
    return evaluate_intent(
        intent=intent,
        validator=FloorValidatorV1(),
        validation_context=context,
        evaluator_id="eval_test",
        evaluator_public_key=evaluator["publicKey"],
        evaluator_private_key=evaluator["privateKey"],
        decision_ttl_minutes=ttl_minutes,
    )


def _permit() -> dict:
    return _decide({"scopeRequired": "repo:read"}, _context(scope=["repo:read"]))


@pytest.fixture()
def permit_decision() -> dict:
    return _permit()


@pytest.fixture()
def record(permit_decision: dict) -> dict:
    return build_trace_record(permit_decision, trace_jwk=_jwk())


# --- the decision the mapper consumes ---------------------------------------

def test_permit_decision_has_the_expected_keys(permit_decision):
    assert set(permit_decision) == {
        "decisionId", "intentId", "evaluatorId", "evaluatorPublicKey", "verdict",
        "principlesEvaluated", "constraints", "reason", "floorVersion",
        "evaluatedAt", "expiresAt", "signature",
    }
    assert permit_decision["verdict"] == "permit"


# --- field mapping -----------------------------------------------------------

def test_eat_profile_is_the_v02_string(record):
    assert record["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2"
    assert record["eat_profile"] == EAT_PROFILE


def test_subject_is_a_spiffe_uri_naming_evaluator_and_decision(record, permit_decision):
    assert record["subject"].startswith("spiffe://agent-passport.org/")
    assert permit_decision["evaluatorId"] in record["subject"]
    assert permit_decision["decisionId"] in record["subject"]


def test_iat_comes_from_evaluated_at(record, permit_decision):
    evaluated = datetime.fromisoformat(permit_decision["evaluatedAt"])
    assert record["iat"] == int(evaluated.timestamp())


def test_policy_bundle_hash_is_a_sha256_digest(record):
    assert record["policy"]["bundle_hash"].startswith("sha256:")
    assert len(record["policy"]["bundle_hash"]) == len("sha256:") + 64


def test_runtime_measurement_is_a_sha256_digest_and_platform_is_software_only(record):
    assert record["runtime"]["platform"] == "software-only"
    assert record["runtime"]["measurement"].startswith("sha256:")
    assert len(record["runtime"]["measurement"]) == len("sha256:") + 64


def test_bundle_hash_and_measurement_are_different_preimages(record):
    assert record["policy"]["bundle_hash"] != record["runtime"]["measurement"]


def test_cnf_carries_the_supplied_trace_jwk(permit_decision):
    jwk = _jwk()
    rec = build_trace_record(permit_decision, trace_jwk=jwk)
    assert rec["cnf"]["jwk"] == jwk
    assert rec["cnf"]["jwk"]["kty"] == "OKP"


def test_appraisal_names_the_aps_evaluator(record, permit_decision):
    assert record["appraisal"]["verifier"] == f"urn:aps:evaluator:{permit_decision['evaluatorId']}"
    assert record["appraisal"]["policy_ref"] == f"urn:aps:floor:{FLOOR_VERSION}"
    assert record["appraisal"]["timestamp"] == record["iat"]


def test_record_carries_no_aps_signature(record):
    """The APS evaluator signature must not leak into the TRACE record."""
    assert "signature" not in record
    assert "evaluatorPublicKey" not in record


# --- verdict to appraisal ----------------------------------------------------

def test_permit_maps_to_affirming(record):
    assert record["appraisal"]["status"] == "affirming"


def test_narrow_maps_to_warning():
    decision = _decide(
        {"scopeRequired": "repo:read", "spend": {"amount": 100, "currency": "USD"}},
        _context(scope=["repo:read"], spend_limit=50, spent=0),
    )
    assert decision["verdict"] == "narrow"
    assert build_trace_record(decision, trace_jwk=_jwk())["appraisal"]["status"] == "warning"


def test_deny_maps_to_contraindicated():
    decision = _decide({"scopeRequired": "repo:write"}, _context(scope=["repo:read"]))
    assert decision["verdict"] == "deny"
    assert build_trace_record(decision, trace_jwk=_jwk())["appraisal"]["status"] == "contraindicated"


def test_every_known_verdict_maps_to_a_valid_ear_status():
    valid = set(agentrust_trace.SCHEMA["properties"]["appraisal"]["properties"]["status"]["enum"])
    assert set(VERDICT_TO_APPRAISAL.values()) <= valid


def test_enforcement_mode_is_enforce_when_a_principle_is_inline(record, permit_decision):
    modes = {p.get("enforcementMode") for p in permit_decision["principlesEvaluated"]}
    assert "inline" in modes
    assert record["policy"]["enforcement_mode"] == "enforce"


# --- refusals ----------------------------------------------------------------

def test_tampered_verdict_is_refused(permit_decision):
    """Flipping the verdict breaks the evaluator signature, so no record is produced."""
    forged = dict(permit_decision, verdict="deny")
    with pytest.raises(ValueError, match="failed verification"):
        build_trace_record(forged, trace_jwk=_jwk())


def test_corrupt_signature_is_refused(permit_decision):
    bad = dict(permit_decision, signature="00" * 64)
    with pytest.raises(ValueError, match="Invalid decision signature"):
        build_trace_record(bad, trace_jwk=_jwk())


def test_expired_decision_is_refused():
    expired = _decide({"scopeRequired": "repo:read"}, _context(scope=["repo:read"]), ttl_minutes=-1)
    with pytest.raises(ValueError, match="expired"):
        build_trace_record(expired, trace_jwk=_jwk())


def test_missing_field_is_refused(permit_decision):
    incomplete = {k: v for k, v in permit_decision.items() if k != "evaluatorPublicKey"}
    with pytest.raises(ValueError, match="missing required fields"):
        build_trace_record(incomplete, trace_jwk=_jwk())


def test_unknown_verdict_is_refused():
    """A verdict this mapper cannot appraise is refused rather than guessed."""
    agent = generate_key_pair()
    evaluator = generate_key_pair()

    class OddValidator(FloorValidatorV1):
        def evaluate(self, intent, ctx):
            result = super().evaluate(intent, ctx)
            result["verdict"] = "escalate"
            return result

    intent = create_action_intent(
        agent_id="agent_test",
        agent_public_key=agent["publicKey"],
        delegation_id="dlg_test",
        action={"scopeRequired": "repo:read"},
        private_key=agent["privateKey"],
    )
    decision = evaluate_intent(
        intent=intent,
        validator=OddValidator(),
        validation_context=_context(scope=["repo:read"]),
        evaluator_id="eval_test",
        evaluator_public_key=evaluator["publicKey"],
        evaluator_private_key=evaluator["privateKey"],
    )
    with pytest.raises(ValueError, match="unknown APS verdict"):
        build_trace_record(decision, trace_jwk=_jwk())


def test_non_dict_is_refused():
    with pytest.raises(ValueError, match="must be a dict"):
        build_trace_record("not-a-decision", trace_jwk=_jwk())  # type: ignore[arg-type]


# --- TRACE sign and verify round-trip ---------------------------------------

def test_sign_verify_roundtrip(record):
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), key)
    agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)


def test_tampered_signed_record_fails_verification(record):
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), key)
    signed["appraisal"]["status"] = "affirming" if signed["appraisal"]["status"] != "affirming" else "denying"
    with pytest.raises(Exception):
        agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)


# --- conformance -------------------------------------------------------------

def test_absent_schema_required_fields_are_exactly_the_documented_set(record):
    """APS carries no model, data class or build provenance. Nothing is invented."""
    required = set(agentrust_trace.SCHEMA["required"])
    assert required - record.keys() == DOCUMENTED_ABSENT_REQUIRED


def test_present_fields_all_validate_against_the_v02_schema(record):
    """Every field the mapper does emit must be schema-clean."""
    errors = agentrust_trace.iter_errors(record)
    unexpected = [e for e in errors if e.message.split("'")[1::2][:1] != []
                  and e.validator != "required"]
    assert unexpected == [], [e.message for e in unexpected]
    missing = {e.message.split("'")[1] for e in errors if e.validator == "required"}
    assert missing == DOCUMENTED_ABSENT_REQUIRED


def test_record_passes_trace_tests_level_0(record):
    """Level 0 must pass, with TR-SIG-005 UNVERIFIED on the unsigned record."""
    runner = pytest.importorskip("trace_tests.runner")
    from trace_tests.result import Status

    results = runner.run(record, "trace", 0)
    findings = [f for module in results.values() for f in module]

    assert [f.code for f in findings if f.status is Status.FAIL] == []
    unverified = [f for f in findings if f.status is Status.UNVERIFIED]
    assert [f.code for f in unverified] == ["TR-SIG-005"]
