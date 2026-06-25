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
