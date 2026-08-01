"""Reading and writing engine state, and the paths it lives at.

Baseline scoping differs by design and is not unified here. Claude Code keeps one
baseline per machine; Codex keeps one per workspace, because a workspace can carry
its own instructions and skills and a single baseline would blend them. Both are
correct for their agent, so an engine supplies its own paths and this module only
handles the reading and writing.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .seal import attach_seal

__all__ = ["StatePaths", "atomic_write", "load_state", "save_state", "save_baseline"]


@dataclass(frozen=True)
class StatePaths:
    """Where one engine keeps its approved baseline and its latest snapshot."""

    baseline: Path
    latest: Path


def atomic_write(path: Path, content: str) -> None:
    """Write via a temporary file and replace, so a crash cannot truncate state.

    A half-written baseline is worse than a missing one: the engine would treat it
    as corrupt on every future session, and a user who sees a broken check often
    enough stops reading it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def save_state(path: Path, value: dict) -> None:
    atomic_write(path, json.dumps(value, indent=2))


def save_baseline(path: Path, snapshot: dict) -> dict:
    """Seal a snapshot and write it as the approved baseline. Returns what was written."""
    sealed = attach_seal(snapshot)
    save_state(path, sealed)
    return sealed


def load_state(path: Path) -> dict | None:
    """Load a state file, or None if it is absent, unreadable, or corrupt.

    A truncated baseline (crash mid-write, disk full, racing sessions) must not
    brick the hook on every future session. Treating corrupt state as absent lets
    the next run re-establish it instead of failing forever.
    """
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None
