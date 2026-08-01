"""Content fingerprinting shared by every AgenTrust capture engine.

Every engine answers the same question about a different agent: is this the
composition I approved, with nothing added and nothing subtracted? The parts that
differ between agents are *where to look* and *what to call things*. Hashing is
not one of them, so it lives here.

Standard library only. The engines are invoked by shell hooks at session start and
must run before any dependency is installed.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "EXCLUDE_DIRS",
    "EXCLUDE_SUFFIXES",
    "now_iso",
    "sha_bytes",
    "sha_file",
    "sha_mapping",
    "safe_sha_file",
    "tree_digest",
    "uuid7",
]

#: Directory names skipped when fingerprinting a component tree. These hold state
#: a component writes as it runs, so hashing them would report drift on ordinary
#: use, and a tool that cries wolf on every run trains its user to ignore it.
#:
#: Controlled here rather than by a file inside the component on purpose. A
#: per-component ignore file would let the thing being measured decide what gets
#: measured, so a hostile component could ship a rule covering its own payload.
#: Adding a name here is a reviewed change to this package.
EXCLUDE_DIRS = frozenset({
    "state", ".cache", "__pycache__", ".git", ".pytest_cache", "node_modules",
})

#: File suffixes skipped for the same reason: run artifacts, not behaviour.
EXCLUDE_SUFFIXES = frozenset({".log", ".tmp", ".pyc", ".pyo"})


def sha_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def safe_sha_file(path: Path) -> str | None:
    """Digest a file, or None if it is missing or unreadable.

    Used on the discovery path, where a file vanishing between listing and
    reading is ordinary rather than exceptional.
    """
    try:
        return sha_file(path)
    except OSError:
        return None


def sha_mapping(value: dict) -> str:
    """Digest a mapping by canonical JSON, so key order cannot change the result."""
    import json

    return sha_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def tree_digest(
    root: Path,
    *,
    exclude_dirs: frozenset[str] = EXCLUDE_DIRS,
    exclude_suffixes: frozenset[str] = EXCLUDE_SUFFIXES,
    pattern: str = "*",
) -> str | None:
    """Digest every behavioural file under ``root``, or None if nothing was read.

    Covers the whole tree rather than a single manifest file. A component is not
    just its manifest: these directories carry scripts, tools, templates and
    reference material that decide what the component actually does. Digesting one
    manifest let a payload be swapped into a sibling ``scripts/`` directory while
    the report said nothing added, nothing subtracted. That was a live bypass in
    two shipped engines before this function existed, which is the reason it is
    shared rather than reimplemented.

    Relative paths are bound into the digest alongside contents, so a rename or a
    move is drift. Traversal is sorted so the digest is stable across platforms.
    Symlinks are skipped so a link out of the tree cannot pull unrelated content
    into the fingerprint, and so a cycle cannot hang the hook.
    """
    digest = hashlib.sha256()
    try:
        paths = sorted(root.rglob(pattern))
    except OSError:
        return None
    saw_file = False
    for path in paths:
        if path.is_symlink():
            continue
        try:
            if not path.is_file():
                continue
            relative = path.relative_to(root)
        except (OSError, ValueError):
            continue
        if exclude_dirs & set(relative.parts[:-1]):
            continue
        if path.suffix in exclude_suffixes:
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        try:
            body = path.read_bytes()
        except OSError:
            # An unreadable file is itself worth recording: its path is already
            # bound in, so the file appearing or vanishing still moves the digest
            # instead of being silently skipped.
            digest.update(b"\0<unreadable>\0")
            saw_file = True
            continue
        digest.update(b"\0")
        digest.update(body)
        digest.update(b"\0")
        saw_file = True
    if not saw_file:
        return None
    return "sha256:" + digest.hexdigest()


def uuid7() -> str:
    """RFC 9562 UUID v7 (time-ordered), required by agent-manifest."""
    ms = int(time.time() * 1000)
    raw = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(raw)))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
