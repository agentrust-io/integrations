"""
Shadow AI Discovery — detect unregistered agents and undeclared tool calls
against a cMCP catalog.json.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


class ShadowAIScanner:
    """
    Compares a cMCP audit log against a catalog.json and emits DiscoveryEvents
    for any agent or tool call not declared in the catalog.
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
        Read a cMCP audit log (newline-delimited JSON) and return one
        DiscoveryEvent per violation.  Each line must be a JSON object with
        at minimum: {"agent_id": "...", "tool_name": "...", "timestamp": "..."}.
        Lines that are not tool_call events (no tool_name key) are skipped.
        """
        events: list[DiscoveryEvent] = []
        for line in Path(log_path).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            record: dict[str, Any] = json.loads(line)
            tool_name = record.get("tool_name")
            if not tool_name:
                continue
            agent_id: str = record.get("agent_id", "unknown")
            timestamp: str = record.get("timestamp", "")

            if not self.is_registered(agent_id):
                events.append(DiscoveryEvent(agent_id, tool_name, timestamp, "unregistered_agent"))
            elif not self.is_tool_declared(agent_id, tool_name):
                events.append(DiscoveryEvent(agent_id, tool_name, timestamp, "undeclared_tool"))
        return events

    def scan_records(self, records: list[dict[str, Any]]) -> list[DiscoveryEvent]:
        """Scan an in-memory list of audit records (same schema as scan_audit_log)."""
        events: list[DiscoveryEvent] = []
        for record in records:
            tool_name = record.get("tool_name")
            if not tool_name:
                continue
            agent_id: str = record.get("agent_id", "unknown")
            timestamp: str = record.get("timestamp", "")

            if not self.is_registered(agent_id):
                events.append(DiscoveryEvent(agent_id, tool_name, timestamp, "unregistered_agent"))
            elif not self.is_tool_declared(agent_id, tool_name):
                events.append(DiscoveryEvent(agent_id, tool_name, timestamp, "undeclared_tool"))
        return events
