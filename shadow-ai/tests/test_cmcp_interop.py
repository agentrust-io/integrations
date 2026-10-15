"""Producer/consumer controls against two explicitly pinned published audit APIs."""
import hashlib
import json
import os
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

if os.environ.get("SHADOW_AI_REQUIRE_CMCP") != "1":
    pytest.importorskip("cmcp_runtime.audit.chain", reason="run nox -s shadow_ai_cmcp for released producer tests")

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from cmcp_producer import write_audit
from cmcp_shadow_ai import CmcpAuditAdapter, SessionAgentBinding
from shadow_ai_discovery import IdentityUnavailableError, ShadowAIScanner


@pytest.fixture
def registry(tmp_path):
    path = tmp_path / "agents.json"
    path.write_text(json.dumps({"billing-agent": ["echo"]}))
    return path


def adapter(registry, *, include_c=True):
    bindings = [
        SessionAgentBinding("gateway-a/boot-1", "session-a", "billing-agent"),
        SessionAgentBinding("gateway-a/boot-1", "session-b", "rogue-agent"),
    ]
    if include_c:
        bindings.append(SessionAgentBinding("gateway-a/boot-1", "session-c", "billing-agent"))
    return CmcpAuditAdapter(registry, source_id="gateway-a/boot-1", trusted_bindings=bindings)


def assert_producer_contract(records):
    assert len(records) == 7
    assert all("agent_id" not in r and "timestamp" not in r for r in records)
    assert all("session_id" in r and "timestamp_utc" in r for r in records)
    previous = {}
    for record in records:
        body = {k: v for k, v in record.items() if k != "entry_hash"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        assert hashlib.sha256(canonical).hexdigest() == record["entry_hash"]
        assert record["prev_entry_hash"] == previous.get(record["session_id"], "genesis")
        previous[record["session_id"]] = record["entry_hash"]


def assert_classification(scanner, records):
    report = scanner.scan_records_report(records)
    assert report.complete
    assert [(f.agent_id, f.tool_name, f.reason) for f in report.findings] == [
        ("billing-agent", "delete_all", "undeclared_tool"),
        ("rogue-agent", "echo", "unregistered_agent"),
    ]
    # Timestamp normalization remains a separate change from identity mapping.
    assert all(f.timestamp == "" for f in report.findings)
    return report


def test_released_audit_api_and_sqlite_serialization(registry, tmp_path):
    assert version("cmcp-runtime") in {"0.2.0", "0.7.0"}
    path = tmp_path / "audit.jsonl"
    records = write_audit(path)
    assert_producer_contract(records)
    scanner = adapter(registry)
    report = assert_classification(scanner, records)
    assert scanner.scan_audit_log_report(path) == report
    assert not ShadowAIScanner(registry).scan_records_report(records).complete


def test_unmapped_real_session_keeps_findings_and_strict_methods_fail(registry, tmp_path):
    path = tmp_path / "audit.jsonl"
    records = write_audit(path)
    scanner = adapter(registry, include_c=False)
    report = scanner.scan_records_report(records)
    assert not report.complete and len(report.findings) == 2
    assert [(d.location_kind, d.location, d.reason) for d in report.unavailable] == [
        ("index", 6, "session_unmapped"),
    ]
    file_report = scanner.scan_audit_log_report(path)
    assert [(d.location_kind, d.location, d.reason) for d in file_report.unavailable] == [
        ("line", 7, "session_unmapped"),
    ]
    with pytest.raises(IdentityUnavailableError) as exc:
        scanner.scan_audit_log(path)
    assert exc.value.report == file_report


@pytest.mark.parametrize("release", ["0.2.0", "0.7.0"])
def test_checked_in_genuine_fixtures_and_catalog(registry, release):
    fixture = Path(__file__).parent / "fixtures" / ("cmcp-" + release)
    provenance = json.loads((fixture / "provenance.json").read_text())
    for name, digest in provenance["sha256"].items():
        assert hashlib.sha256((fixture / name).read_bytes()).hexdigest() == digest
    catalog = json.loads((fixture / "catalog.json").read_text())
    assert isinstance(catalog, list) and catalog[0]["tool_name"] == "echo"
    # The actual producer catalog cannot authorize an agent or replace bindings.
    with pytest.raises(ValueError, match="Unrecognized catalog format"):
        CmcpAuditAdapter(fixture / "catalog.json", source_id="gateway-a/boot-1", trusted_bindings=[])
    records = [json.loads(line) for line in (fixture / "audit.jsonl").read_text().splitlines()]
    assert_producer_contract(records)
    assert_classification(adapter(registry), records)
