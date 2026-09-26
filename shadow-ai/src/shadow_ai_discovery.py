"""
Shadow AI Discovery — detect unregistered agents and undeclared tool calls in
enriched audit records, against a separate agent-to-tools registry.

The registry is not a cMCP tool catalog, and cMCP audit records must first be
enriched with a usable ``agent_id``: the scanner never derives or invents one.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


@dataclass
class DiscoveryEvent:
    agent_id: str
    tool_name: str
    timestamp: str
    reason: str  # "unregistered_agent" | "undeclared_tool"
    suggested_manifest_id: str = field(init=False)

    def __post_init__(self) -> None:
        self.suggested_manifest_id = re.sub(r"[^a-z0-9-]", "-", self.agent_id.lower()).strip("-")

    def to_dict(self) -> dict[str, str]:
        return {
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "suggested_manifest_id": self.suggested_manifest_id,
        }


@dataclass(frozen=True)
class IdentityUnavailable:
    """
    A tool-call record that could not be classified because it carries no usable
    ``agent_id``. The rejected agent_id is not stored as an identity field: there
    is no agent_id or suggested_manifest_id. Other record fields (tool_name,
    timestamp) are copied as-is, without redaction.
    """

    location_kind: str  # "index" (0-based, in-memory records) | "line" (1-based, JSONL)
    location: int
    tool_name: str
    timestamp: str  # copied from the record without type validation; "" if absent
    reason: str  # "missing" | "null" | "blank" | "non_string"
    observed_type: str | None = None  # JSON type name, set only for "non_string"

    def to_dict(self) -> dict[str, Any]:
        return {
            "location_kind": self.location_kind,
            "location": self.location,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "observed_type": self.observed_type,
        }


@dataclass(frozen=True)
class ScanReport:
    """
    Findings plus the tool-call records that could not be classified.

    ``complete`` is True only when no successfully processed tool-call record was
    unclassifiable because of unavailable identity. It does not certify that the
    audit source itself is complete.
    """

    findings: tuple[DiscoveryEvent, ...]
    unavailable: tuple[IdentityUnavailable, ...]

    @property
    def complete(self) -> bool:
        return not self.unavailable

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "findings": [event.to_dict() for event in self.findings],
            "unavailable": [diagnostic.to_dict() for diagnostic in self.unavailable],
        }


class IdentityUnavailableError(ValueError):
    """
    Raised by ``scan_records`` and ``scan_audit_log`` when any tool-call record has
    no usable ``agent_id``, instead of returning an apparently complete list. The
    full report, including every valid finding, is available as ``report``.
    """

    def __init__(self, report: ScanReport) -> None:
        self.report = report
        shown = ", ".join(
            f"{d.location_kind} {d.location} ({d.reason})" for d in report.unavailable[:5]
        )
        more = len(report.unavailable) - 5
        if more > 0:
            shown += f", and {more} more"
        super().__init__(
            f"{len(report.unavailable)} tool-call record(s) have no usable agent_id, "
            f"so classification is incomplete: {shown}"
        )


def _identity_unavailable_reason(record: dict[str, Any]) -> str | None:
    """Return why ``record`` has no usable agent_id, or None if it has one."""
    if "agent_id" not in record:
        return "missing"
    agent_id = record["agent_id"]
    if agent_id is None:
        return "null"
    if not isinstance(agent_id, str):
        return "non_string"
    if not agent_id.strip():
        return "blank"
    return None


def _json_type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


class ShadowAIScanner:
    """
    Compares enriched audit records against an agent-to-tools registry and emits
    DiscoveryEvents for any agent or tool call the registry does not declare.
    """

    def __init__(self, catalog_path: str | Path) -> None:
        self._catalog: dict[str, set[str]] = {}
        self._load_catalog(Path(catalog_path))

    def _load_catalog(self, path: Path) -> None:
        raw: Any = json.loads(path.read_text())
        # catalog.json: {"agents": [{"id": "...", "tools": ["tool1", ...]}]}
        # also accept flat {"agent-id": ["tool1", ...]} map
        if isinstance(raw, dict) and "agents" in raw:
            for entry in raw["agents"]:
                self._catalog[entry["id"]] = set(entry.get("tools", []))
        elif isinstance(raw, dict):
            for agent_id, tools in raw.items():
                self._catalog[agent_id] = set(tools)
        else:
            raise ValueError(f"Unrecognized catalog format in {path}")

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._catalog

    def is_tool_declared(self, agent_id: str, tool_name: str) -> bool:
        if agent_id not in self._catalog:
            return False
        return tool_name in self._catalog[agent_id]

    def scan_audit_log(self, log_path: str | Path) -> list[DiscoveryEvent]:
        """
        Read an enriched audit log (newline-delimited JSON) and return one
        DiscoveryEvent per violation.  Each line must be a JSON object; a
        tool_call line needs at minimum: {"agent_id": "...", "tool_name": "..."}.
        An optional "timestamp" is copied as-is ("" if absent), without type
        validation.  Lines that are not tool_call events (tool_name absent or
        empty) are skipped.

        Raises IdentityUnavailableError if any tool_call line has no usable
        agent_id; use scan_audit_log_report() to keep the findings instead.
        """
        return self._strict(self.scan_audit_log_report(log_path))

    def scan_audit_log_report(self, log_path: str | Path) -> ScanReport:
        """Like scan_audit_log, but report unusable identities by physical line number."""
        return self._classify(self._read_jsonl(Path(log_path)), "line")

    def scan_records(self, records: list[dict[str, Any]]) -> list[DiscoveryEvent]:
        """
        Scan an in-memory list of audit records (same schema as scan_audit_log).

        Raises IdentityUnavailableError if any tool_call record has no usable
        agent_id; use scan_records_report() to keep the findings instead.
        """
        return self._strict(self.scan_records_report(records))

    def scan_records_report(self, records: list[dict[str, Any]]) -> ScanReport:
        """Like scan_records, but report unusable identities by 0-based list index."""
        return self._classify(enumerate(records), "index")

    @staticmethod
    def _read_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
        # read_text() applies universal newlines, so "\n" is the only line break
        # left. str.splitlines() would also split on characters such as U+2028
        # that JSON allows raw inside strings, breaking valid records apart.
        for number, line in enumerate(path.read_text().split("\n"), start=1):
            line = line.strip()
            if not line:
                continue
            yield number, json.loads(line)

    def _classify(
        self, located_records: Iterable[tuple[int, dict[str, Any]]], location_kind: str
    ) -> ScanReport:
        findings: list[DiscoveryEvent] = []
        unavailable: list[IdentityUnavailable] = []
        for location, record in located_records:
            tool_name = record.get("tool_name")
            if not tool_name:
                continue
            timestamp: str = record.get("timestamp", "")

            reason = _identity_unavailable_reason(record)
            if reason is not None:
                observed_type = _json_type_name(record["agent_id"]) if reason == "non_string" else None
                unavailable.append(
                    IdentityUnavailable(location_kind, location, tool_name, timestamp, reason, observed_type)
                )
                continue

            agent_id: str = record["agent_id"]
            if not self.is_registered(agent_id):
                findings.append(DiscoveryEvent(agent_id, tool_name, timestamp, "unregistered_agent"))
            elif not self.is_tool_declared(agent_id, tool_name):
                findings.append(DiscoveryEvent(agent_id, tool_name, timestamp, "undeclared_tool"))
        return ScanReport(tuple(findings), tuple(unavailable))

    @staticmethod
    def _strict(report: ScanReport) -> list[DiscoveryEvent]:
        if not report.complete:
            raise IdentityUnavailableError(report)
        return list(report.findings)
