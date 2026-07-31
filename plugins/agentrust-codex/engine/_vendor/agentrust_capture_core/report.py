"""Report vocabulary shared across engines.

The engines render different reports on purpose: they name different things and a
Codex user should not read Claude Code labels. What must not differ is the honesty
rules, because those drifted once already and each engine had to be fixed
separately.

Two rules live here.

**An unmeasured category is not an empty one.** A shell hook cannot see a live tool
roster or the model, so those arrive only from a caller-supplied live context.
Rendering them as ``0 tools`` or ``model: unknown`` states a measurement that was
never taken, and a reader who cannot tell "we did not check" from "we checked and
found nothing" will treat an absence as a pass.

**A partial check is not a clean bill of health.** "Nothing added, nothing
subtracted" is only true of what was compared, so it is qualified whenever coverage
is incomplete.
"""

from __future__ import annotations

from collections.abc import Sequence

from .seal import INTEGRITY_BROKEN, INTEGRITY_OK, INTEGRITY_UNSEALED

__all__ = [
    "UNMEASURED",
    "clean_verdict",
    "measured_or",
    "seal_section",
    "unmeasured_footnote",
]

#: Shown wherever a category was not measured.
UNMEASURED = "not measured this run"


def measured_or(value: object, measured: bool, hint: str | None = None) -> str:
    """Render ``value`` when it was measured, and say so plainly when it was not."""
    if measured:
        return str(value)
    return "%s  (%s)" % (UNMEASURED, hint) if hint else UNMEASURED


def unmeasured_footnote(complete: bool) -> list[str]:
    """The line that stops an absent measurement reading as a verified absence."""
    if complete:
        return []
    return [
        '  Categories marked "%s" are NOT part of this comparison.' % UNMEASURED,
        "  They are unchecked, not verified as empty.",
        "",
    ]


def clean_verdict(complete: bool, phrasing: str = "nothing added, nothing subtracted") -> str:
    """A no-changes verdict, qualified when coverage was partial."""
    scope = "" if complete else " in the categories checked"
    return "  >> Verified: %s%s." % (phrasing, scope)


def seal_section(integrity: str, digest: str | None = None) -> list[str]:
    """The baseline-integrity block, stated before any drift result.

    Ordering is the point. If the baseline was altered, a reassuring "nothing
    changed" underneath it is worse than no result at all, so a caller renders this
    above its drift section.
    """
    lines = ["  IS THE BASELINE ITSELF INTACT?", "  " + "-" * 62]
    if integrity == INTEGRITY_BROKEN:
        lines += [
            "  !! the baseline FAILED its integrity check. It was modified outside",
            "     this tool, so the comparison below is unreliable. Re-approve only",
            "     once you are satisfied the current setup is what you intend.",
        ]
    elif integrity == INTEGRITY_UNSEALED:
        lines.append("  ~  baseline carries no digest (written by an older version). "
                     "Re-approve to seal it.")
    elif integrity == INTEGRITY_OK:
        lines.append("  >> baseline digest verified.")
    if digest:
        lines.append("     digest: %s" % digest)
    lines += [
        "     A digest stored beside the content catches corruption and a",
        "     hand-edit, not an attacker who owns this directory and can",
        "     recompute it. Compare the digest above against the one you",
        "     recorded off-box: that is what catches a silent re-baseline.",
        "",
    ]
    return lines


def change_lines(changes: Sequence[dict]) -> list[str]:
    """Render findings with a stable symbol per kind."""
    symbol = {"added": "+", "removed": "-", "changed": "~"}
    return [
        "  %s %s %s: %s" % (symbol.get(c["change"], "?"), c["change"].upper(),
                            c["what"], c["detail"])
        for c in changes
    ]
