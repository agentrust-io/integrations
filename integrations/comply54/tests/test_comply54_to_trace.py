"""
Tests for comply54 -> TRACE v0.1 adapter.
Run: pip install -r requirements.txt && python -m pytest tests/ -v
"""

import json
import base64
import pytest
import jsonschema
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from comply54_to_trace import comply54_to_trace_payload, load_or_generate_key, private_key_to_jwk


# ── Fixtures ──────────────────────────────────────────────────────────────────

ALLOW_RESULT = {
    "overall": "allow",
    "audit_id": "test-audit-001",
    "decisions": [
        {"pack": "nigeria/cbn", "regulation": "CBN Transaction Controls",
         "jurisdiction": "NG", "action": "allow", "messages": []},
        {"pack": "nigeria/ndpa", "regulation": "Nigeria Data Protection Act 2023",
         "jurisdiction": "NG", "action": "allow", "messages": []},
        {"pack": "universal/pii-leakage", "regulation": "OWASP LLM06",
         "jurisdiction": "UNIVERSAL", "action": "allow", "messages": []},
    ],
}

DENY_RESULT = {
    "overall": "deny",
    "audit_id": "test-audit-002",
    "decisions": [
        {"pack": "nigeria/cbn", "regulation": "CBN Transaction Controls",
         "jurisdiction": "NG", "action": "deny",
         "messages": ["CBN NIP cap exceeded: ₦15,000,000 > ₦10,000,000 limit"]},
        {"pack": "nigeria/ndpa", "regulation": "Nigeria Data Protection Act 2023",
         "jurisdiction": "NG", "action": "allow", "messages": []},
    ],
}

ESCALATE_RESULT = {
    "overall": "escalate",
    "audit_id": "test-audit-003",
    "decisions": [
        {"pack": "nigeria/nfiu-aml", "regulation": "NFIU AML Guidelines",
         "jurisdiction": "NG", "action": "escalate",
         "messages": ["Currency Transaction Report required: ₦6,000,000 exceeds ₦5,000,000 threshold"]},
    ],
}

AUDIT_RESULT = {
    "overall": "audit",
    "audit_id": "test-audit-005",
    "decisions": [
        {"pack": "nigeria/ndpa", "regulation": "Nigeria Data Protection Act 2023",
         "jurisdiction": "NG", "action": "audit",
         "messages": ["Data subject rights audit trail required per NDPA s.25"]},
    ],
}

PAN_AFRICAN_RESULT = {
    "overall": "deny",
    "audit_id": "test-audit-004",
    "decisions": [
        {"pack": "nigeria/cbn", "regulation": "CBN Transaction Controls", "jurisdiction": "NG", "action": "deny", "messages": ["CBN NIP cap exceeded"]},
        {"pack": "kenya/kdpa", "regulation": "Kenya Data Protection Act 2019", "jurisdiction": "KE", "action": "allow", "messages": []},
        {"pack": "south-africa/popia", "regulation": "POPIA", "jurisdiction": "ZA", "action": "allow", "messages": []},
        {"pack": "ghana/dpa", "regulation": "Ghana DPA 2012", "jurisdiction": "GH", "action": "allow", "messages": []},
    ],
}


# ── Appraisal mapping ─────────────────────────────────────────────────────────

class TestAppraisalMapping:
    def test_allow_maps_to_affirming(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["appraisal"]["status"] == "affirming"

    def test_deny_maps_to_contraindicated(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["appraisal"]["status"] == "contraindicated"

    def test_escalate_maps_to_warning(self):
        payload = comply54_to_trace_payload(ESCALATE_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["appraisal"]["status"] == "warning"

    def test_audit_maps_to_warning(self):
        payload = comply54_to_trace_payload(AUDIT_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["appraisal"]["status"] == "warning"


# ── Required TRACE EAT envelope fields ───────────────────────────────────────

class TestTraceEnvelope:
    def test_eat_profile_present(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"

    def test_iat_is_integer(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert isinstance(payload["iat"], int)
        assert payload["iat"] > 0

    def test_subject_contains_agent_id(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "payments-agent", "anthropic/claude-sonnet-4-6")
        assert "payments-agent" in payload["subject"]
        assert payload["subject"].startswith("spiffe://")

    def test_policy_bundle_hash_is_sha256(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["policy"]["bundle_hash"].startswith("sha256:")
        assert len(payload["policy"]["bundle_hash"]) == 71  # "sha256:" + 64 hex chars

    def test_policy_bundle_hash_is_deterministic(self):
        p1 = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        p2 = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert p1["policy"]["bundle_hash"] == p2["policy"]["bundle_hash"]

    def test_runtime_platform_is_software_only(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["runtime"]["platform"] == "software-only"

    def test_model_provider_parsed_correctly(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "openai/gpt-4o")
        assert payload["model"]["provider"] == "openai"
        assert payload["model"]["model_id"] == "gpt-4o"


# ── comply54 extension claims ─────────────────────────────────────────────────

class TestComply54Claims:
    def test_audit_id_preserved(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["comply54"]["audit_id"] == "test-audit-002"

    def test_overall_decision_preserved(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert payload["comply54"]["overall"] == "deny"

    def test_jurisdictions_extracted(self):
        payload = comply54_to_trace_payload(PAN_AFRICAN_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert "NG" in payload["comply54"]["jurisdictions"]
        assert "KE" in payload["comply54"]["jurisdictions"]
        assert "ZA" in payload["comply54"]["jurisdictions"]

    def test_packs_evaluated_sorted(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        packs = payload["comply54"]["packs_evaluated"]
        assert packs == sorted(packs)

    def test_violations_only_non_allow(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        for v in payload["comply54"]["violations"]:
            assert v["action"] != "allow"

    def test_allow_result_has_no_violations(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        assert len(payload["comply54"]["violations"]) == 0


# ── JWT signing ───────────────────────────────────────────────────────────────

class TestJWTSigning:
    def test_key_generation_returns_ed25519(self):
        key = load_or_generate_key()
        assert isinstance(key, Ed25519PrivateKey)

    def test_jwk_has_correct_fields(self):
        key = load_or_generate_key()
        jwk = private_key_to_jwk(key)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk

    def test_signed_jwt_is_decodable(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        key = load_or_generate_key()
        payload["cnf"] = {"jwk": private_key_to_jwk(key)}
        token = pyjwt.encode(payload, key, algorithm="EdDSA", headers={"alg": "EdDSA", "typ": "JWT"})
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"
        assert decoded["appraisal"]["status"] == "contraindicated"

    def test_signed_jwt_has_three_parts(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        key = load_or_generate_key()
        payload["cnf"] = {"jwk": private_key_to_jwk(key)}
        token = pyjwt.encode(payload, key, algorithm="EdDSA", headers={"alg": "EdDSA", "typ": "JWT"})
        assert len(token.split(".")) == 3


# ── TRACE schema conformance ──────────────────────────────────────────────────

SCHEMA_PATH = Path(__file__).parent.parent.parent.parent / "schema" / "trace-claim.json"


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _core(payload: dict) -> dict:
    """Strip private comply54 extension claims before schema validation.

    The TRACE schema is additionalProperties:false on the core envelope.
    Private claims under the 'comply54' namespace are carried as extension
    claims per RFC 7519 §4.3 and are validated separately, not against the
    core TRACE schema. See README §Extension Claims for details.
    """
    return {k: v for k, v in payload.items() if k != "comply54"}


class TestSchemaConformance:
    def test_allow_result_core_conforms_to_trace_schema(self):
        payload = comply54_to_trace_payload(ALLOW_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        jsonschema.validate(_core(payload), _load_schema())

    def test_deny_result_core_conforms_to_trace_schema(self):
        payload = comply54_to_trace_payload(DENY_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        jsonschema.validate(_core(payload), _load_schema())

    def test_escalate_result_core_conforms_to_trace_schema(self):
        payload = comply54_to_trace_payload(ESCALATE_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        jsonschema.validate(_core(payload), _load_schema())

    def test_audit_result_core_conforms_to_trace_schema(self):
        payload = comply54_to_trace_payload(AUDIT_RESULT, "agent-1", "anthropic/claude-sonnet-4-6")
        jsonschema.validate(_core(payload), _load_schema())

    def test_appraisal_status_is_valid_enum(self):
        schema = _load_schema()
        valid = schema["properties"]["appraisal"]["properties"]["status"]["enum"]
        assert "advisory" not in valid, "advisory is not a valid TRACE appraisal.status"
        assert set(valid) == {"affirming", "warning", "contraindicated", "none"}
