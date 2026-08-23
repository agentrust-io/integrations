"""Comparison primitives, plus the two gates that keep a comparison honest.

Every engine's diff reduces to four shapes: a map of name to digest (components,
instruction files, policy files), a set of names (tools, MCP servers), a scalar
(model, permission mode), and a rollup hash. What differs between engines is which
categories exist and what they are called, so those stay with the engine and the
shapes live here.

Two gates matter more than the shapes.

**Observed gating.** A snapshot records which categories it actually measured. A
shell hook cannot enumerate a live tool roster, so comparing a hook snapshot
against a richer baseline would report the baseline's tools as removed. Only
categories that BOTH sides measured are compared.

**Scope gating.** When an engine widens what a fingerprint covers, old fingerprints
become incomparable. Without handling, an upgrade reports every affected component
as changed. That is an alarm the user knows is false, which is worse than no alarm
because it teaches them to dismiss the next one. So a scope mismatch is reported
once, as a re-approval prompt, and the affected categories are dropped from the
comparison rather than compared wrongly.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from .hashing import UNVERIFIABLE_PREFIX

__all__ = [
    "Change",
    "diff_hash",
    "diff_maps",
    "diff_scalar",
    "diff_sets",
    "observed_categories",
    "scope_change",
]

#: A single finding. ``change`` is one of added, removed, changed.
Change = dict


def _change(change: str, what: str, detail: str) -> Change:
    return {"change": change, "what": what, "detail": detail}


def diff_maps(base: Mapping[str, str], current: Mapping[str, str], what: str) -> list[Change]:
    """Compare two name-to-digest maps. Names are reported, digests are not.

    A digest in a report tells the reader nothing they can act on; the name of the
    component that moved does.
    """
    out: list[Change] = []
    for name in sorted(set(current) - set(base)):
        out.append(_change("added", what, name))
    for name in sorted(set(base) - set(current)):
        out.append(_change("removed", what, name))
    for name in sorted(set(base) & set(current)):
        if (
            base[name].startswith(UNVERIFIABLE_PREFIX)
            or current[name].startswith(UNVERIFIABLE_PREFIX)
        ):
            out.append(_change("changed", what, name + " (unverifiable symlink payload)"))
        elif base[name] != current[name]:
            out.append(_change("changed", what, name))
    return out


def diff_sets(base: Iterable[str], current: Iterable[str], what: str) -> list[Change]:
    """Compare two name sets, for categories with no per-item digest."""
    before, after = set(base), set(current)
    out: list[Change] = []
    for name in sorted(after - before):
        out.append(_change("added", what, name))
    for name in sorted(before - after):
        out.append(_change("removed", what, name))
    return out


def diff_scalar(before: object, after: object, what: str, *, unknown: str = "unknown") -> list[Change]:
    """Compare a single value, reporting the transition rather than just the fact."""
    if before == after:
        return []
    return [_change("changed", what, "%s -> %s" % (before or unknown, after or unknown))]


def diff_hash(before: str | None, after: str | None, what: str, detail: str) -> list[Change]:
    """Compare a rollup hash, where only the fact of change is available."""
    if before == after:
        return []
    return [_change("changed", what, detail)]


def observed_categories(
    base: Mapping[str, object],
    current: Mapping[str, object],
    default: Sequence[str] = (),
) -> set[str]:
    """Categories both snapshots measured, and therefore may be compared."""
    return set(base.get("observed", list(default))) & set(current.get("observed", list(default)))


def scope_change(
    base: Mapping[str, object],
    current_scope: int,
    *,
    affected: Sequence[str],
    reason: str,
) -> Change | None:
    """Report a widened measurement scope, or None when the scopes agree.

    ``affected`` names the categories the caller must drop from its comparison,
    and is included in the message so the reader knows what was not checked rather
    than assuming everything was.
    """
    base_scope = base.get("scope", 1)
    if base_scope == current_scope:
        return None
    dropped = ", ".join(affected) if affected else "none"
    return _change(
        "changed",
        "measurement scope",
        "widened from %s to %s; %s Not compared this run: %s. Re-approve once to "
        "compare on the new scope." % (base_scope, current_scope, reason, dropped),
    )
