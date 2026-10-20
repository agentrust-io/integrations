"""Attribute cMCP audit records using operator-supplied session bindings.

Bindings and the audit source identifier are trusted policy inputs. This module
does not authenticate logs, attest a gateway, or derive identity from its catalog.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator

from shadow_ai_discovery import (
    IdentityUnavailable,
    ScanReport,
    ShadowAIScanner,
    _json_type_name,
)


def _require_identifier(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-blank string")


@dataclass(frozen=True)
class SessionAgentBinding:
    """One authenticated session's identity, supplied by an operator/control plane.

    Use a source_id that identifies the gateway and its session namespace/epoch.
    Do not construct these from audit fields or a tool catalog. Identifiers are
    exact strings, with no trimming, case folding or session-prefix matching.
    """

    source_id: str
    session_id: str
    agent_id: str

    def __post_init__(self) -> None:
        for field in ("source_id", "session_id", "agent_id"):
            _require_identifier(getattr(self, field), field)


class CmcpAuditAdapter(ShadowAIScanner):
    """The scanner's four scan methods, with explicit cMCP session attribution.

    source_id comes from the trusted caller's audit-source selection, never a
    record. trusted_bindings are a snapshot: subsequent caller mutations cannot
    rebind a session. Any duplicate source/session key is a configuration error.

    Input records stay unchanged. timestamp retains the scanner's existing
    behavior; timestamp_utc mapping/normalization is deliberately separate.
    """

    def __init__(
        self,
        catalog_path: str | Path,
        *,
        source_id: str,
        trusted_bindings: Iterable[SessionAgentBinding],
    ) -> None:
        _require_identifier(source_id, "source_id")
        bindings: dict[tuple[str, str], str] = {}
        for binding in trusted_bindings:
            if not isinstance(binding, SessionAgentBinding):
                raise TypeError("trusted_bindings must contain SessionAgentBinding objects")
            key = (binding.source_id, binding.session_id)
            if key in bindings:
                raise ValueError("duplicate source/session binding; attribution is ambiguous")
            bindings[key] = binding.agent_id
        self._source_id = source_id
        self._bindings = MappingProxyType(bindings)
        super().__init__(catalog_path)

    def _classify(
        self, located_records: Iterable[tuple[int, dict[str, Any]]], location_kind: str
    ) -> ScanReport:
        unavailable: list[IdentityUnavailable] = []

        def attributed() -> Iterator[tuple[int, dict[str, Any]]]:
            for location, record in located_records:
                tool_name = record.get("tool_name")
                if not tool_name:
                    continue
                if not isinstance(tool_name, str) or not tool_name.strip():
                    raise ValueError(f"invalid tool_name at {location_kind} {location}")
                reason, observed_type = self._session_reason(record)
                if reason is None:
                    agent_id = self._bindings[(self._source_id, record["session_id"])]
                    # An extra claim in a record cannot replace the trusted
                    # binding or conceal a conflicting identity assertion.
                    if "agent_id" in record and record["agent_id"] != agent_id:
                        reason = "agent_conflict"
                if reason is not None:
                    unavailable.append(IdentityUnavailable(
                        location_kind, location, tool_name, record.get("timestamp", ""),
                        reason, observed_type,
                    ))
                    continue
                yield location, {**record, "agent_id": agent_id}

        report = super()._classify(attributed(), location_kind)
        diagnostics = sorted((*unavailable, *report.unavailable), key=lambda item: item.location)
        return ScanReport(report.findings, tuple(diagnostics))

    def _session_reason(self, record: dict[str, Any]) -> tuple[str | None, str | None]:
        if "session_id" not in record:
            return "session_missing", None
        session_id = record["session_id"]
        if session_id is None:
            return "session_null", None
        if not isinstance(session_id, str):
            return "session_non_string", _json_type_name(session_id)
        if not session_id.strip():
            return "session_blank", None
        if (self._source_id, session_id) not in self._bindings:
            return "session_unmapped", None
        return None, None
