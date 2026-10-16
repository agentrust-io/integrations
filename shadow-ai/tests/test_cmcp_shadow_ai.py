"""Session attribution must not turn missing identity into a clean scan."""
import copy
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from cmcp_shadow_ai import CmcpAuditAdapter, SessionAgentBinding
from shadow_ai_discovery import IdentityUnavailableError, ShadowAIScanner


@pytest.fixture
def registry(tmp_path):
    path = tmp_path / "agents.json"
    path.write_text(json.dumps({"billing-agent": ["echo"]}))
    return path


def adapter(registry, *, source="gateway-a/boot-1", bindings=None):
    if bindings is None:
        bindings = [SessionAgentBinding("gateway-a/boot-1", "session-a", "billing-agent")]
    return CmcpAuditAdapter(registry, source_id=source, trusted_bindings=bindings)


def record(**changes):
    return {"session_id": "session-a", "tool_name": "echo", **changes}


def via(scanner, records, tmp_path, mode, strict=False):
    if mode == "records":
        method = scanner.scan_records if strict else scanner.scan_records_report
        return method(records)
    path = tmp_path / "audit.jsonl"
    # Preserve blank physical lines and CRLF accounting on the file path.
    path.write_bytes(("\r\n" + "\r\n\r\n".join(json.dumps(r) for r in records)).encode())
    method = scanner.scan_audit_log if strict else scanner.scan_audit_log_report
    return method(path)


@pytest.mark.parametrize("mode", ["records", "jsonl"])
def test_positive_and_negative_controls(registry, tmp_path, mode):
    bindings = [
        SessionAgentBinding("gateway-a/boot-1", "session-a", "billing-agent"),
        SessionAgentBinding("gateway-a/boot-1", "session-b", "rogue-agent"),
    ]
    scanner = adapter(registry, bindings=bindings)
    records = [record(), record(tool_name="delete_all"), record(session_id="session-b")]
    before = copy.deepcopy(records)
    report = via(scanner, records, tmp_path, mode)
    assert report.complete
    assert [(e.agent_id, e.reason) for e in report.findings] == [
        ("billing-agent", "undeclared_tool"), ("rogue-agent", "unregistered_agent"),
    ]
    assert via(scanner, records, tmp_path, mode, strict=True) == list(report.findings)
    assert records == before


@pytest.mark.parametrize("mode", ["records", "jsonl"])
@pytest.mark.parametrize("fields,reason,observed", [
    ({}, "session_missing", None),
    ({"session_id": None}, "session_null", None),
    ({"session_id": ""}, "session_blank", None),
    ({"session_id": " \t "}, "session_blank", None),
    ({"session_id": 424242}, "session_non_string", "number"),
    ({"session_id": True}, "session_non_string", "boolean"),
    ({"session_id": ["SENTINEL"]}, "session_non_string", "array"),
    ({"session_id": {"id": "SENTINEL"}}, "session_non_string", "object"),
    ({"session_id": "missing-session"}, "session_unmapped", None),
    ({"session_id": "SESSION-A"}, "session_unmapped", None),
    ({"session_id": " session-a "}, "session_unmapped", None),
])
def test_unavailable_sessions_keep_real_findings(registry, tmp_path, mode, fields, reason, observed):
    scanner = adapter(registry)
    records = [record(tool_name="delete_all"), {"tool_name": "echo", **fields}, record()]
    report = via(scanner, records, tmp_path, mode)
    assert not report.complete
    assert [e.reason for e in report.findings] == ["undeclared_tool"]
    diagnostic, = report.unavailable
    assert (diagnostic.reason, diagnostic.observed_type) == (reason, observed)
    assert (diagnostic.location_kind, diagnostic.location) == (
        ("index", 1) if mode == "records" else ("line", 4)
    )
    serialized = json.dumps(diagnostic.to_dict())
    assert "suggested_manifest_id" not in serialized
    assert "agent_id" not in serialized and "424242" not in serialized and "SENTINEL" not in serialized
    with pytest.raises(IdentityUnavailableError) as exc:
        via(scanner, records, tmp_path, mode, strict=True)
    assert exc.value.report == report
    assert reason in str(exc.value)
    assert "424242" not in str(exc.value) and "SENTINEL" not in str(exc.value)


@pytest.mark.parametrize("claim", ["rogue-agent", "", " ", None, 123, True, [], {}])
def test_record_identity_cannot_override_mapping(registry, claim):
    report = adapter(registry).scan_records_report([record(agent_id=claim)])
    assert report.findings == ()
    assert report.unavailable[0].reason == "agent_conflict"
    assert not report.complete


def test_record_identity_is_never_a_fallback(registry):
    report = adapter(registry, bindings=[]).scan_records_report([
        record(agent_id="billing-agent", source_id="gateway-a/boot-1"),
    ])
    assert not report.complete and not report.findings
    assert report.unavailable[0].reason == "session_unmapped"


def test_matching_record_claim_is_only_corroborating(registry):
    assert adapter(registry).scan_records_report([record(agent_id="billing-agent")]).complete


def test_source_namespace_is_caller_supplied(registry):
    bindings = [
        SessionAgentBinding("gateway-a/boot-1", "session-a", "billing-agent"),
        SessionAgentBinding("gateway-b/boot-1", "session-a", "rogue-agent"),
    ]
    scanner = adapter(registry, source="gateway-b/boot-1", bindings=bindings)
    report = scanner.scan_records_report([record(source_id="gateway-a/boot-1")])
    assert report.complete and report.findings[0].agent_id == "rogue-agent"
    assert adapter(registry, source="gateway-a/boot-2", bindings=bindings).scan_records_report([
        record(agent_id="billing-agent"),
    ]).unavailable[0].reason == "session_unmapped"


@pytest.mark.parametrize("other_agent", ["billing-agent", "rogue-agent"])
def test_duplicate_bindings_are_rejected_even_if_identical(registry, other_agent):
    bindings = [
        SessionAgentBinding("gateway-a/boot-1", "session-a", "billing-agent"),
        SessionAgentBinding("gateway-a/boot-1", "session-a", other_agent),
    ]
    with pytest.raises(ValueError, match="duplicate source/session"):
        adapter(registry, bindings=bindings)


@pytest.mark.parametrize("field", ["source_id", "session_id", "agent_id"])
@pytest.mark.parametrize("invalid", [None, "", " \t", 1, True, [], {}])
def test_invalid_binding_identifiers_fail_at_load(field, invalid):
    fields = dict(source_id="gateway-a/boot-1", session_id="session-a", agent_id="billing-agent")
    fields[field] = invalid
    with pytest.raises(ValueError, match=field):
        SessionAgentBinding(**fields)


def test_mapping_is_a_snapshot_and_binding_is_immutable(registry):
    binding = SessionAgentBinding("gateway-a/boot-1", "session-a", "billing-agent")
    bindings = [binding]
    scanner = adapter(registry, bindings=bindings)
    bindings.clear()
    assert scanner.scan_records_report([record()]).complete
    with pytest.raises(FrozenInstanceError):
        binding.agent_id = "rogue-agent"
    with pytest.raises(TypeError):
        adapter(registry, bindings=[{"session_id": "session-a", "agent_id": "billing-agent"}])


def test_exact_agent_ids_are_not_normalized(registry):
    bindings = [SessionAgentBinding("gateway-a/boot-1", "session-a", " billing-agent ")]
    report = adapter(registry, bindings=bindings).scan_records_report([record()])
    assert report.findings[0].agent_id == " billing-agent "
    assert report.findings[0].reason == "unregistered_agent"


def test_non_tool_calls_and_timestamp_contract_are_unchanged(registry):
    scanner = adapter(registry)
    assert scanner.scan_records_report([{}, {"tool_name": None}, {"tool_name": ""}]).complete
    report = scanner.scan_records_report([
        record(tool_name="delete_all", timestamp_utc="2026-10-15T00:00:00Z"),
        record(tool_name="delete_all", timestamp="verbatim", timestamp_utc="ignored"),
    ])
    assert [e.timestamp for e in report.findings] == ["", "verbatim"]
    assert not ShadowAIScanner(registry).scan_records_report([record()]).complete


def test_jsonl_unicode_separator_is_not_a_physical_line_break(registry, tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps(record(note="a\u2028b"), ensure_ascii=False), encoding="utf-8")
    assert adapter(registry).scan_audit_log_report(path).complete


@pytest.mark.parametrize("tool_name", ["  ", 123, ["echo"], {"name": "echo"}])
def test_malformed_tool_call_does_not_become_a_clean_scan(registry, tool_name):
    with pytest.raises(ValueError, match="invalid tool_name at index 0"):
        adapter(registry).scan_records_report([record(tool_name=tool_name)])
