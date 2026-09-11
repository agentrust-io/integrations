"""APS to TRACE mapping tests.

Covers the mapping itself, the refusals that keep an unverified APS decision
from being mapped into TRACE record shape, and a level 0 coverage run against
the mapping output. Decisions are minted in-process with ephemeral keys, so no network
access, no credentials and no committed fixtures are involved.

A committed decision fixture is impossible here on purpose: APS decisions
expire five minutes after evaluation and the mapper refuses expired input.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import agentrust_trace
import pytest
from agent_passport.crypto import generate_key_pair
from agent_passport.policy import FloorValidatorV1, create_action_intent, evaluate_intent

from aps_trace import APPRAISAL_STATUS, EAT_PROFILE, KNOWN_VERDICTS, TRUST_DOMAIN, build_trace_record

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
    expected = (
        f"spiffe://{TRUST_DOMAIN}"
        f"/evaluator/{quote(permit_decision['evaluatorId'], safe='')}"
        f"/decision/{quote(permit_decision['decisionId'], safe='')}"
    )
    assert record["subject"] == expected


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

def test_permit_does_not_appraise(record):
    """The verdict is a policy decision, so it does not set an appraisal status."""
    assert record["appraisal"]["status"] == "none"


def test_narrow_does_not_appraise():
    decision = _decide(
        {"scopeRequired": "repo:read", "spend": {"amount": 100, "currency": "USD"}},
        _context(scope=["repo:read"], spend_limit=50, spent=0),
    )
    assert decision["verdict"] == "narrow"
    assert build_trace_record(decision, trace_jwk=_jwk())["appraisal"]["status"] == "none"


def test_deny_does_not_appraise():
    decision = _decide({"scopeRequired": "repo:write"}, _context(scope=["repo:read"]))
    assert decision["verdict"] == "deny"
    assert build_trace_record(decision, trace_jwk=_jwk())["appraisal"]["status"] == "none"


def test_every_known_verdict_maps_to_a_valid_ear_status():
    valid = set(agentrust_trace.SCHEMA["properties"]["appraisal"]["properties"]["status"]["enum"])
    assert APPRAISAL_STATUS in valid


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

def test_signed_mapping_has_no_level0_findings(record):
    """Signing works and the signature checks out, on a schema-incomplete mapping output.

    Level 0 is a coverage probe here, not a conformance gate. The unsigned output
    leaves TR-SIG-005 UNVERIFIED; once signed, nothing should be unverified.
    """
    runner = pytest.importorskip("trace_tests.runner")
    from trace_tests.result import Status

    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), key)
    assert signed["signature"]

    results = runner.run(signed, "trace", 0)
    findings = [f for module in results.values() for f in module]

    assert [f.code for f in findings if f.status is Status.FAIL] == []
    assert [f.code for f in findings if f.status is Status.UNVERIFIED] == []


def test_verify_record_refuses_schema_incomplete_mapping(record):
    """The boundary this integration lives on, asserted rather than assumed.

    agentrust-trace 0.10.0 made ``verify_record`` enforce the full v0.2 schema,
    on the stated grounds that "signature validity is not schema validity": a
    caller must not be able to treat a signed object missing required claims as
    a verified Trust Record. That rule is right, and this record is deliberately
    missing three of them, see DOCUMENTED_ABSENT_REQUIRED and the "Deliberately
    absent" section of aps_trace.py.

    So the round-trip this test used to assert is one the format no longer
    offers, and should not. Pinning the refusal means the day APS starts
    carrying a model identity, somebody has to come here and decide that
    deliberately rather than discover it through a green suite.
    """
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), key)

    with pytest.raises(ValueError, match="does not conform to the TRACE v0.2 schema"):
        agentrust_trace.verify_record(
            signed, allow_embedded_key=True, max_age_seconds=None
        )


def test_tampered_signed_record_fails_verification(record):
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(dict(record), key)
    signed["appraisal"]["status"] = "affirming"  # any value != the emitted constant
    with pytest.raises(Exception):
        agentrust_trace.verify_record(signed, allow_embedded_key=True, max_age_seconds=None)


def test_appraisal_status_is_a_constant_not_a_parameter():
    """Every accepted verdict emits the same appraisal status.

    The agentrust-trace-adapters convention (commit e1aa231, 2026-08-08) makes
    appraisal.status a constant for records assembled from someone else's
    evidence. If a future edit reintroduces a verdict-to-status mapping, this
    fails.
    """
    assert APPRAISAL_STATUS == "none"
    assert KNOWN_VERDICTS == {"permit", "narrow", "deny"}


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


def test_mapping_level0_coverage_result(record):
    """Level 0 coverage result: 8 checks, TR-SIG-005 UNVERIFIED on the unsigned output."""
    runner = pytest.importorskip("trace_tests.runner")
    from trace_tests.result import Status

    results = runner.run(record, "trace", 0)
    findings = [f for module in results.values() for f in module]

    assert [f.code for f in findings if f.status is Status.FAIL] == []
    unverified = [f for f in findings if f.status is Status.UNVERIFIED]
    assert [f.code for f in unverified] == ["TR-SIG-005"]


def test_integration_metadata_claims_no_level():
    """#170: external-evidence-source, and no conformance level anywhere in the manifest."""
    import pathlib
    import re
    text = pathlib.Path(__file__).resolve().parents[1].joinpath("integration.yaml").read_text()
    # Parsed with re rather than a YAML library so the test extras stay as they are.
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    roles = re.search(r"^trace_roles:\n((?:  - .*\n?)+)", body, re.M)
    assert roles is not None
    assert [r.strip()[2:] for r in roles.group(1).strip().splitlines()] == ["external-evidence-source"]
    assert re.search(r"^trace_conformance_level:", body, re.M) is None
