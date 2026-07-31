"""Shared core for AgenTrust agent-integrity capture engines.

Each engine answers one question about a different coding agent: is this the
composition I approved, with nothing added and nothing subtracted? What differs
between agents is where to look and what to call things. What must not differ is
how content is fingerprinted, how snapshots are compared, how a baseline is sealed,
and the rules that keep a report honest.

Those lived in three copies before this package existed, and the cost was not
theoretical: the same skill-fingerprinting bypass had to be found and fixed twice,
independently, and a reporting defect once. This package is the single source of
truth for the parts that are genuinely identical.

Standard library only, because the engines run from shell hooks at session start
and must work before anything is installed.
"""

from __future__ import annotations

from .compare import (
    Change,
    diff_hash,
    diff_maps,
    diff_scalar,
    diff_sets,
    observed_categories,
    scope_change,
)
from .hashing import (
    EXCLUDE_DIRS,
    EXCLUDE_SUFFIXES,
    now_iso,
    safe_sha_file,
    sha_bytes,
    sha_file,
    sha_mapping,
    tree_digest,
    uuid7,
)
from .report import (
    UNMEASURED,
    change_lines,
    clean_verdict,
    measured_or,
    seal_section,
    unmeasured_footnote,
)
from .seal import (
    INTEGRITY_BROKEN,
    INTEGRITY_OK,
    INTEGRITY_UNSEALED,
    SEAL_FIELD,
    attach_seal,
    check_seal,
    state_digest,
)
from .state import StatePaths, atomic_write, load_state, save_baseline, save_state

__version__ = "0.1.0"

__all__ = [
    "Change",
    "EXCLUDE_DIRS",
    "EXCLUDE_SUFFIXES",
    "INTEGRITY_BROKEN",
    "INTEGRITY_OK",
    "INTEGRITY_UNSEALED",
    "SEAL_FIELD",
    "StatePaths",
    "UNMEASURED",
    "__version__",
    "atomic_write",
    "attach_seal",
    "change_lines",
    "check_seal",
    "clean_verdict",
    "diff_hash",
    "diff_maps",
    "diff_scalar",
    "diff_sets",
    "load_state",
    "measured_or",
    "now_iso",
    "observed_categories",
    "safe_sha_file",
    "save_baseline",
    "save_state",
    "scope_change",
    "seal_section",
    "sha_bytes",
    "sha_file",
    "sha_mapping",
    "state_digest",
    "tree_digest",
    "unmeasured_footnote",
    "uuid7",
]
