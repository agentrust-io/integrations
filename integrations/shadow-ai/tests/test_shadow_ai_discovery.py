"""Tests for Shadow AI Discovery integration."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from shadow_ai_discovery import DiscoveryEvent, ShadowAIScanner


# ── fixtures ──────────────────────────────────────────────────────────────────

CATALOG_AGENTS = {
    "agents": [
        {"id": "billing-agent", "tools": ["get_invoice", "list_invoices"]},
        {"id": "support-agent", "tools": ["open_ticket", "close_ticket"]},
    ]
}

CATALOG_FLAT = {
    "billing-agent": ["get_invoice", "list_invoices"],
}


@pytest.fixture()
def catalog_file(tmp_path):
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(CATALOG_AGENTS))
    return p


@pytest.fixture()
def flat_catalog_file(tmp_path):
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps(CATALOG_FLAT))
    return p


@pytest.fixture()
def scanner(catalog_file):
    return ShadowAIScanner(catalog_file)


def make_log(tmp_path, records):
    p = tmp_path / "audit.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records))
    return p


# ── 1. registered agent, declared tool → no event ────────────────────────────

def test_clean_call_produces_no_event(scanner):
    records = [{"agent_id": "billing-agent", "tool_name": "get_invoice", "timestamp": "2026-06-25T10:00:00Z"}]
    assert scanner.scan_records(records) == []


# ── 2. unregistered agent → reason = unregistered_agent ──────────────────────

def test_unregistered_agent_detected(scanner):
    records = [{"agent_id": "rogue-agent", "tool_name": "delete_all", "timestamp": "2026-06-25T10:01:00Z"}]
    events = scanner.scan_records(records)
    assert len(events) == 1
    assert events[0].reason == "unregistered_agent"
    assert events[0].agent_id == "rogue-agent"


# ── 3. registered agent, undeclared tool → reason = undeclared_tool ───────────

def test_undeclared_tool_detected(scanner):
    records = [{"agent_id": "billing-agent", "tool_name": "delete_all", "timestamp": "2026-06-25T10:02:00Z"}]
    events = scanner.scan_records(records)
    assert len(events) == 1
    assert events[0].reason == "undeclared_tool"
    assert events[0].tool_name == "delete_all"


# ── 4. suggested_manifest_id sanitises the agent_id ──────────────────────────

def test_suggested_manifest_id_sanitized(scanner):
    records = [{"agent_id": "My Agent/v2 (prod)", "tool_name": "x", "timestamp": "t"}]
    events = scanner.scan_records(records)
    assert events[0].suggested_manifest_id == "my-agent-v2--prod"
    # must only contain lowercase alphanum and hyphens, no leading/trailing dash
    import re
    assert re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", events[0].suggested_manifest_id)


# ── 5. records without tool_name are skipped ──────────────────────────────────

def test_non_tool_call_records_skipped(scanner):
    records = [
        {"agent_id": "rogue-agent", "event": "session_start", "timestamp": "t"},
        {"agent_id": "rogue-agent", "tool_name": "bad_tool", "timestamp": "t"},
    ]
    events = scanner.scan_records(records)
    assert len(events) == 1  # only the tool_call record


# ── 6. scan_audit_log reads a JSONL file ─────────────────────────────────────

def test_scan_audit_log_file(scanner, tmp_path):
    records = [
        {"agent_id": "rogue-agent", "tool_name": "exfil", "timestamp": "2026-06-25T10:05:00Z"},
        {"agent_id": "billing-agent", "tool_name": "get_invoice", "timestamp": "2026-06-25T10:06:00Z"},
    ]
    log = make_log(tmp_path, records)
    events = scanner.scan_audit_log(log)
    assert len(events) == 1
    assert events[0].agent_id == "rogue-agent"


# ── 7. flat catalog format is parsed correctly ────────────────────────────────

def test_flat_catalog_format(flat_catalog_file):
    scanner = ShadowAIScanner(flat_catalog_file)
    assert scanner.is_registered("billing-agent")
    assert scanner.is_tool_declared("billing-agent", "get_invoice")
    assert not scanner.is_tool_declared("billing-agent", "delete_all")


# ── 8. multiple violations in one log ────────────────────────────────────────

def test_multiple_violations(scanner):
    records = [
        {"agent_id": "rogue-1", "tool_name": "tool_a", "timestamp": "t1"},
        {"agent_id": "rogue-2", "tool_name": "tool_b", "timestamp": "t2"},
        {"agent_id": "billing-agent", "tool_name": "hack", "timestamp": "t3"},
    ]
    events = scanner.scan_records(records)
    assert len(events) == 3
    reasons = {e.reason for e in events}
    assert "unregistered_agent" in reasons
    assert "undeclared_tool" in reasons


# ── 9. to_dict returns all required fields ────────────────────────────────────

def test_discovery_event_to_dict_fields():
    e = DiscoveryEvent("billing-agent", "bad_tool", "2026-06-25T00:00:00Z", "undeclared_tool")
    d = e.to_dict()
    for key in ("agent_id", "tool_name", "timestamp", "reason", "suggested_manifest_id"):
        assert key in d, f"Missing key: {key}"
    assert d["agent_id"] == "billing-agent"
    assert d["suggested_manifest_id"] == "billing-agent"


# ── 10. identity-unavailable records: report path and strict path ─────────────
#
# Sentinel values are distinctive so a leak of the raw value is detectable.

from shadow_ai_discovery import (  # noqa: E402
    IdentityUnavailable,
    IdentityUnavailableError,
    ScanReport,
)

UNAVAILABLE_CASES = [
    # (case id, record fields, expected reason, expected observed_type, sentinel or None)
    ("missing", {}, "missing", None, None),
    ("null", {"agent_id": None}, "null", None, None),
    ("empty", {"agent_id": ""}, "blank", None, None),
    ("whitespace", {"agent_id": " \t "}, "blank", None, None),
    ("integer", {"agent_id": 424242}, "non_string", "number", "424242"),
    ("float", {"agent_id": 31.4159}, "non_string", "number", "31.4159"),
    ("boolean", {"agent_id": True}, "non_string", "boolean", None),
    ("array", {"agent_id": ["SENTINEL-ARRAY"]}, "non_string", "array", "SENTINEL-ARRAY"),
    ("object", {"agent_id": {"id": "SENTINEL-OBJECT"}}, "non_string", "object", "SENTINEL-OBJECT"),
]


def report_via(scanner, tmp_path, records, via):
    """Run the report method for one input path; returns (report, location of record i)."""
    if via == "records":
        return scanner.scan_records_report(records), lambda i: ("index", i)
    log = make_log(tmp_path, records)
    return scanner.scan_audit_log_report(log), lambda i: ("line", i + 1)


def strict_via(scanner, tmp_path, records, via):
    if via == "records":
        return scanner.scan_records(records)
    return scanner.scan_audit_log(make_log(tmp_path, records))


@pytest.mark.parametrize("via", ["records", "audit_log"])
@pytest.mark.parametrize(
    "fields, reason, observed_type, sentinel",
    [case[1:] for case in UNAVAILABLE_CASES],
    ids=[case[0] for case in UNAVAILABLE_CASES],
)
def test_unavailable_identity_is_reported_not_fabricated(
    scanner, tmp_path, via, fields, reason, observed_type, sentinel
):
    record = {"tool_name": "delete_all", "timestamp": "2026-06-25T10:09:00Z", **fields}
    report, location = report_via(scanner, tmp_path, [record], via)

    kind, where = location(0)
    assert report.findings == ()
    assert report.unavailable == (
        IdentityUnavailable(kind, where, "delete_all", "2026-06-25T10:09:00Z", reason, observed_type),
    )
    assert report.complete is False

    serialized = json.dumps(report.to_dict())
    assert "unregistered_agent" not in serialized
    assert "suggested_manifest_id" not in serialized
    assert "unknown" not in serialized

    with pytest.raises(IdentityUnavailableError) as excinfo:
        strict_via(scanner, tmp_path, [record], via)
    assert isinstance(excinfo.value, ValueError)
    assert excinfo.value.report == report
    message = str(excinfo.value)
    assert f"{kind} {where} ({reason})" in message
    assert "unknown" not in message
    assert "suggested" not in message
    if sentinel is not None:
        # control: the sentinel really is in the input, so its absence below means something
        assert sentinel in json.dumps(record)
        assert sentinel not in message
        assert sentinel not in serialized


@pytest.mark.parametrize("via", ["records", "audit_log"])
@pytest.mark.parametrize(
    "agent_id, tool_name, expected_reason",
    [
        ("billing-agent", "get_invoice", None),
        ("billing-agent", "delete_all", "undeclared_tool"),
        ("rogue-agent", "delete_all", "unregistered_agent"),
        ("unknown", "delete_all", "unregistered_agent"),
        (" billing-agent ", "get_invoice", "unregistered_agent"),
    ],
    ids=["registered-declared", "registered-undeclared", "unregistered", "literal-unknown", "padded-verbatim"],
)
def test_supplied_identity_is_classified_against_registry(
    scanner, tmp_path, via, agent_id, tool_name, expected_reason
):
    """Positive controls: a usable agent_id is classified, never treated as unavailable."""
    record = {"agent_id": agent_id, "tool_name": tool_name, "timestamp": "t"}
    report, _ = report_via(scanner, tmp_path, [record], via)
    assert report.unavailable == ()
    assert report.complete is True
    expected = [] if expected_reason is None else [DiscoveryEvent(agent_id, tool_name, "t", expected_reason)]
    assert list(report.findings) == expected
    assert strict_via(scanner, tmp_path, [record], via) == expected
    for event in report.findings:
        assert event.agent_id == agent_id  # preserved verbatim, no strip or lowercasing


def test_literal_unknown_is_distinct_from_missing_identity(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"unknown": ["get_invoice"]}))
    scanner = ShadowAIScanner(catalog)

    supplied = {"agent_id": "unknown", "tool_name": "get_invoice", "timestamp": "t"}
    missing = {"tool_name": "get_invoice", "timestamp": "t"}

    assert scanner.scan_records([supplied]) == []  # "unknown" is a registered agent here
    report = scanner.scan_records_report([missing])
    assert report.findings == ()
    assert [d.reason for d in report.unavailable] == ["missing"]
    with pytest.raises(IdentityUnavailableError):
        scanner.scan_records([missing])


def test_blank_registry_key_cannot_match_blank_identity(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"": ["get_invoice"]}))
    report = ShadowAIScanner(catalog).scan_records_report(
        [{"agent_id": "", "tool_name": "get_invoice", "timestamp": "t"}]
    )
    assert report.findings == ()
    assert [d.reason for d in report.unavailable] == ["blank"]


# ── 11. mixed records ─────────────────────────────────────────────────────────

MIXED_RECORDS = [
    {"agent_id": "billing-agent", "tool_name": "get_invoice", "timestamp": "t0"},  # clean
    {"agent_id": "rogue-agent", "tool_name": "exfil", "timestamp": "t1"},  # unregistered
    {"event": "session_start", "timestamp": "t2"},  # non-tool-call, no identity either
    {"agent_id": None, "tool_name": "open_ticket", "timestamp": "t3"},  # identity unavailable
    {"agent_id": "support-agent", "tool_name": "delete_all", "timestamp": "t4"},  # undeclared
]

MIXED_FINDINGS = [
    DiscoveryEvent("rogue-agent", "exfil", "t1", "unregistered_agent"),
    DiscoveryEvent("support-agent", "delete_all", "t4", "undeclared_tool"),
]


def test_mixed_records_report(scanner):
    report = scanner.scan_records_report(MIXED_RECORDS)
    assert list(report.findings) == MIXED_FINDINGS
    assert report.unavailable == (IdentityUnavailable("index", 3, "open_ticket", "t3", "null"),)
    assert report.complete is False


def test_mixed_audit_log_report_uses_physical_line_numbers(scanner, tmp_path):
    # blank lines are counted as physical lines but skipped
    log = tmp_path / "audit.jsonl"
    lines = [json.dumps(MIXED_RECORDS[0]), "", json.dumps(MIXED_RECORDS[1]), "   ",
             json.dumps(MIXED_RECORDS[2]), json.dumps(MIXED_RECORDS[3]), json.dumps(MIXED_RECORDS[4])]
    log.write_text("\n".join(lines) + "\n")
    report = scanner.scan_audit_log_report(log)
    assert list(report.findings) == MIXED_FINDINGS
    assert report.unavailable == (IdentityUnavailable("line", 6, "open_ticket", "t3", "null"),)
    assert report.complete is False


@pytest.mark.parametrize("via", ["records", "audit_log"])
def test_strict_error_preserves_findings_before_and_after(scanner, tmp_path, via):
    with pytest.raises(IdentityUnavailableError) as excinfo:
        strict_via(scanner, tmp_path, MIXED_RECORDS, via)
    report = excinfo.value.report
    # one finding precedes the unavailable record, one follows it
    assert list(report.findings) == MIXED_FINDINGS
    assert [(d.location_kind, d.location) for d in report.unavailable] == [
        ("index", 3) if via == "records" else ("line", 4)
    ]


def test_both_input_paths_classify_identically(scanner, tmp_path):
    records = MIXED_RECORDS + [
        {"tool_name": "x", "timestamp": "t5"},
        {"agent_id": 7, "tool_name": "y", "timestamp": "t6"},
    ]
    in_memory = scanner.scan_records_report(records)
    from_log = scanner.scan_audit_log_report(make_log(tmp_path, records))
    assert in_memory.findings == from_log.findings
    assert [(d.reason, d.observed_type) for d in in_memory.unavailable] == [
        (d.reason, d.observed_type) for d in from_log.unavailable
    ]
    assert [d.location for d in in_memory.unavailable] == [3, 5, 6]
    assert [d.location for d in from_log.unavailable] == [4, 6, 7]


def test_non_tool_call_record_without_identity_is_skipped(scanner):
    no_tool = {"event": "session_start", "timestamp": "t"}
    assert scanner.scan_records_report([no_tool]) == ScanReport((), ())
    assert scanner.scan_records([no_tool]) == []
    # control: the same record becomes a tool call once it names a tool
    assert not scanner.scan_records_report([{**no_tool, "tool_name": "x"}]).complete


def test_error_message_lists_first_five_locations(scanner):
    records = [{"tool_name": "x", "timestamp": "t"} for _ in range(7)]
    with pytest.raises(IdentityUnavailableError) as excinfo:
        scanner.scan_records(records)
    message = str(excinfo.value)
    assert message.startswith("7 tool-call record(s) have no usable agent_id")
    assert "index 4 (missing)" in message
    assert "index 5" not in message
    assert message.endswith("and 2 more")
    assert len(excinfo.value.report.unavailable) == 7


# ── 12. unchanged failure behavior for malformed input ────────────────────────

@pytest.mark.parametrize("method", ["scan_audit_log", "scan_audit_log_report"])
def test_malformed_json_line_still_raises_decode_error(scanner, tmp_path, method):
    good = json.dumps({"agent_id": "rogue-agent", "tool_name": "exfil", "timestamp": "t"})
    log = tmp_path / "audit.jsonl"
    log.write_text(good + "\n")
    getattr(scanner, method)(log)  # control: the well-formed log scans
    log.write_text(good + "\n{not json\n")
    with pytest.raises(json.JSONDecodeError):
        getattr(scanner, method)(log)


@pytest.mark.parametrize("method", ["scan_records", "scan_records_report"])
def test_non_object_record_still_raises_attribute_error(scanner, method):
    with pytest.raises(AttributeError):
        getattr(scanner, method)([["not", "an", "object"]])


# ── 13. JSONL lines split only on real line breaks (U+2028 regression) ────────

U2028_RECORDS = [
    {"agent_id": "rogue-agent", "tool_name": "exfil", "timestamp": "t1", "note": "a\u2028b"},
    {"agent_id": "billing-agent", "tool_name": "get_invoice", "timestamp": "t2"},
    {"tool_name": "open_ticket", "timestamp": "t3"},
]
U2028_TEXT = "\n".join(json.dumps(r, ensure_ascii=False) for r in U2028_RECORDS) + "\n"


def test_u2028_inside_json_string_does_not_split_line(scanner, tmp_path, monkeypatch):
    # Deterministic line-splitting regression. The decoded text is handed to the
    # scanner directly, so this does not exercise how a real file is decoded.
    assert chr(0x2028) in U2028_TEXT
    assert U2028_TEXT.count("\n") == 3  # three physical lines
    # control: the previous splitter, str.splitlines(), breaks the first record apart
    old_pieces = U2028_TEXT.splitlines()
    assert len(old_pieces) == 4
    with pytest.raises(json.JSONDecodeError):
        json.loads(old_pieces[0])

    log = tmp_path / "audit.jsonl"
    log.write_text("")
    monkeypatch.setattr(Path, "read_text", lambda self, *args, **kwargs: U2028_TEXT)
    report = scanner.scan_audit_log_report(log)
    assert list(report.findings) == [DiscoveryEvent("rogue-agent", "exfil", "t1", "unregistered_agent")]
    assert report.unavailable == (IdentityUnavailable("line", 3, "open_ticket", "t3", "missing"),)


# ── 14. JSON serialization ────────────────────────────────────────────────────

def test_discovery_event_to_dict_exact():
    e = DiscoveryEvent("My Agent/v2 (prod)", "bad_tool", "2026-06-25T00:00:00Z", "unregistered_agent")
    assert e.to_dict() == {
        "agent_id": "My Agent/v2 (prod)",
        "tool_name": "bad_tool",
        "timestamp": "2026-06-25T00:00:00Z",
        "reason": "unregistered_agent",
        "suggested_manifest_id": "my-agent-v2--prod",
    }


def test_identity_unavailable_to_dict_exact():
    d = IdentityUnavailable("line", 12, "exfil", "t", "non_string", "number")
    assert d.to_dict() == {
        "location_kind": "line",
        "location": 12,
        "tool_name": "exfil",
        "timestamp": "t",
        "reason": "non_string",
        "observed_type": "number",
    }
    assert IdentityUnavailable("index", 0, "exfil", "t", "missing").to_dict()["observed_type"] is None


def test_scan_report_to_dict_round_trips_through_json(scanner):
    report = scanner.scan_records_report(MIXED_RECORDS)
    assert json.loads(json.dumps(report.to_dict())) == {
        "complete": False,
        "findings": [event.to_dict() for event in MIXED_FINDINGS],
        "unavailable": [
            {
                "location_kind": "index",
                "location": 3,
                "tool_name": "open_ticket",
                "timestamp": "t3",
                "reason": "null",
                "observed_type": None,
            }
        ],
    }
    assert ScanReport((), ()).to_dict() == {"complete": True, "findings": [], "unavailable": []}


# ── 15. timestamp is optional and copied without type validation ──────────────

NO_TIMESTAMP_RECORDS = [
    {"agent_id": "rogue-agent", "tool_name": "exfil"},  # unregistered
    {"agent_id": "billing-agent", "tool_name": "delete_all"},  # undeclared
    {"agent_id": "billing-agent", "tool_name": "get_invoice"},  # clean
]
NO_TIMESTAMP_FINDINGS = [
    DiscoveryEvent("rogue-agent", "exfil", "", "unregistered_agent"),
    DiscoveryEvent("billing-agent", "delete_all", "", "undeclared_tool"),
]


@pytest.mark.parametrize("via", ["records", "audit_log"])
def test_absent_timestamp_on_valid_records(scanner, tmp_path, via):
    assert strict_via(scanner, tmp_path, NO_TIMESTAMP_RECORDS, via) == NO_TIMESTAMP_FINDINGS
    report, _ = report_via(scanner, tmp_path, NO_TIMESTAMP_RECORDS, via)
    assert list(report.findings) == NO_TIMESTAMP_FINDINGS
    assert report.complete is True


@pytest.mark.parametrize("via", ["records", "audit_log"])
def test_absent_timestamp_on_identity_unavailable_record(scanner, tmp_path, via):
    records = NO_TIMESTAMP_RECORDS + [{"tool_name": "open_ticket"}]
    report, location = report_via(scanner, tmp_path, records, via)
    kind, where = location(3)
    assert list(report.findings) == NO_TIMESTAMP_FINDINGS
    assert report.unavailable == (IdentityUnavailable(kind, where, "open_ticket", "", "missing"),)
    with pytest.raises(IdentityUnavailableError) as excinfo:
        strict_via(scanner, tmp_path, records, via)
    assert excinfo.value.report == report


@pytest.mark.parametrize("via", ["records", "audit_log"])
def test_timestamp_is_copied_without_type_validation(scanner, tmp_path, via):
    # Documents current behavior; the scanner does not check or convert timestamp types.
    records = [
        {"agent_id": "rogue-agent", "tool_name": "exfil", "timestamp": 1719309900},
        {"tool_name": "open_ticket", "timestamp": 1719309901},
    ]
    report, _ = report_via(scanner, tmp_path, records, via)
    assert [event.timestamp for event in report.findings] == [1719309900]
    assert [item.timestamp for item in report.unavailable] == [1719309901]
