"""Produce real cMCP SQLite payloads using an installed, released audit API."""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.store import SqliteAuditStore


def write_audit(path: Path) -> list[dict]:
    """Exercise AuditChain and the exact payload serialization in SqliteAuditStore.

    No gateway, network, TEE or caller authentication is exercised here. Session
    identity comes from the separate operator bindings supplied by the tests.
    """
    if version("cmcp-runtime") not in {"0.2.0", "0.7.0"}:
        raise ValueError("fixture producer requires cmcp-runtime 0.2.0 or 0.7.0")
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "audit.db"
        store = SqliteAuditStore(database)
        try:
            for session in ("session-a", "session-b", "session-c"):
                chain = AuditChain(session, store=store)
                chain.append("tool_call", call_id=session + "/1", tool_name="echo", policy_decision="allow")
                if session == "session-a":
                    chain.append("tool_call", call_id=session + "/2", tool_name="delete_all", policy_decision="deny")
        finally:
            store.close()
        with sqlite3.connect(database) as connection:
            payloads = [row[0] for row in connection.execute("SELECT payload FROM audit_entries ORDER BY rowid")]
    path.write_text("\n".join(payloads) + "\n", encoding="utf-8")
    return [json.loads(payload) for payload in payloads]


if __name__ == "__main__":
    write_audit(Path(sys.argv[1]))
