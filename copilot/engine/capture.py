"""AgenTrust agent-integrity check for GitHub Copilot.

Copilot's composition lives in the repository, not in a home directory. Its
instructions, its skills and its MCP configuration are all files that arrive by
pull request. That changes what the right control is.

The other engines in this repo watch a developer's machine and warn at session
start, after the fact, one developer at a time. Here the composition is reviewed
code, so drift can be caught at the moment it enters the codebase: one baseline
committed beside the files it describes, and a required status check that fails a
pull request which changes what Copilot reads without updating the baseline in the
same change.

That also means this engine does not seal its baseline. The other engines do,
because a local baseline can be rewritten with nothing to show for it. A committed
baseline gets provenance from git: every change to it appears in a diff, carries an
author, and passes through review. Adding a digest on top would be ceremony.

What Copilot reads, verified against GitHub's documentation:

  instructions   .github/copilot-instructions.md          repository-wide
                 .github/instructions/**/*.instructions.md  path-scoped, applyTo
                 AGENTS.md anywhere in the tree           nearest wins
                 CLAUDE.md, GEMINI.md at the root         alternatives to AGENTS.md
  skills         .github/skills/<name>/SKILL.md           plus supporting files
                 .claude/skills/<name>/SKILL.md
                 .agents/skills/<name>/SKILL.md
  mcp            copilot/mcp-config.json, .vscode/mcp.json

Standard library only, so the action needs no install step.

Subcommands:
  snapshot   print the current composition as JSON
  verify     compare against the baseline; exit 1 on drift
  approve    write the current composition as the approved baseline
  comment    render the pull-request comment body for a verify result
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# agentrust-capture-core is a declared dependency, not an optional one. A clear
# failure beats a vague one: the hook's own guard would otherwise report "integrity
# check skipped" and leave the user guessing, so say exactly what is missing.
try:
    import agentrust_capture_core as core
except ImportError as _exc:  # pragma: no cover - install-time failure path
    raise SystemExit(
        "AgenTrust needs agentrust-capture-core, which is not installed.\n"
        "Install it with:  pip install agentrust-capture-core\n"
        "Drift detection cannot run without it."
    ) from _exc

VERSION = "0.1.0"

#: Version of WHAT this engine measures. See the other engines for why this
#: exists: widening coverage must not be reported as drift that happened.
MEASUREMENT_SCOPE = 1

#: Where the approved baseline lives, relative to the repository root. In the
#: repository on purpose: it is reviewed like code, and git carries its provenance.
BASELINE_PATH = Path(".agentrust") / "copilot-baseline.json"

#: Single files Copilot reads as instructions, relative to the repository root.
INSTRUCTION_FILES = (
    ".github/copilot-instructions.md",
    "CLAUDE.md",
    "GEMINI.md",
)

#: Globs for instruction files that may appear in many places. AGENTS.md is
#: matched anywhere in the tree because Copilot resolves the nearest one, so a
#: file added in a subdirectory by a pull request changes what the agent reads
#: there without touching anything at the root.
INSTRUCTION_GLOBS = (
    ".github/instructions/**/*.instructions.md",
    "**/AGENTS.md",
)

#: Directories holding one subdirectory per skill.
SKILL_ROOTS = (
    ".github/skills",
    ".claude/skills",
    ".agents/skills",
)

#: MCP server configuration Copilot may read from the repository.
MCP_FILES = (
    "copilot/mcp-config.json",
    ".vscode/mcp.json",
)

#: Directories never walked when looking for instruction files. Without this,
#: a vendored dependency carrying its own AGENTS.md would be reported as part of
#: this repository's agent composition.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
})

CATEGORIES = ("instructions", "skills", "mcp")


def _is_skipped(relative: Path) -> bool:
    return bool(SKIP_DIRS & set(relative.parts))


def _instructions(root: Path) -> dict:
    """Digest each instruction file Copilot would read, keyed by repo-relative path."""
    found: dict = {}
    for name in INSTRUCTION_FILES:
        path = root / name
        digest = core.safe_sha_file(path) if path.is_file() else None
        if digest:
            found[name] = digest
    for pattern in INSTRUCTION_GLOBS:
        try:
            matches = sorted(root.glob(pattern))
        except OSError:
            continue
        for path in matches:
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root)
            if _is_skipped(relative):
                continue
            digest = core.safe_sha_file(path)
            if digest:
                found[relative.as_posix()] = digest
    return dict(sorted(found.items()))


def _skills(root: Path) -> dict:
    """Digest each skill directory, keyed by ``<root>:<name>``.

    The whole directory, not just SKILL.md. A skill's scripts and reference files
    decide what it does, and digesting the manifest alone was a live bypass in two
    other engines in this repo before the shared core existed.
    """
    found: dict = {}
    for skill_root in SKILL_ROOTS:
        base = root / skill_root
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            if not (entry / "SKILL.md").is_file():
                continue  # a directory without a manifest is not a skill
            digest = core.tree_digest(entry)
            if digest:
                found["%s:%s" % (skill_root, entry.name)] = digest
    return dict(sorted(found.items()))


def _mcp(root: Path) -> dict:
    """Digest MCP configuration files, keyed by repo-relative path."""
    found: dict = {}
    for name in MCP_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            digest = core.safe_sha_file(path)
            if digest:
                found[name] = digest
    return dict(sorted(found.items()))


def snapshot(root: Path) -> dict:
    return {
        "captured_at": core.now_iso(),
        "scope": MEASUREMENT_SCOPE,
        "observed": list(CATEGORIES),
        "instructions": _instructions(root),
        "skills": _skills(root),
        "mcp": _mcp(root),
    }


def load_baseline(root: Path) -> dict | None:
    """The approved baseline, or None when the repository has not adopted one."""
    return core.load_state(root / BASELINE_PATH)


def diff(base: dict, current: dict) -> list:
    common = core.observed_categories(base, current, CATEGORIES)
    changes: list = []
    scope = core.scope_change(base, MEASUREMENT_SCOPE, affected=["skills"],
                              reason="skill digests changed shape.")
    if scope is not None:
        changes.append(scope)
        common.discard("skills")
    if "instructions" in common:
        changes += core.diff_maps(base.get("instructions", {}),
                                 current.get("instructions", {}), "instruction file")
    if "skills" in common:
        changes += core.diff_maps(base.get("skills", {}), current.get("skills", {}), "skill")
    if "mcp" in common:
        changes += core.diff_maps(base.get("mcp", {}), current.get("mcp", {}),
                                 "MCP config")
    return changes


def comment_body(changes: list, baseline_rel: str) -> str:
    """The pull-request comment. Names files, because a digest is not actionable."""
    if not changes:
        return (
            "### Copilot agent composition unchanged\n\n"
            "Nothing added, nothing subtracted in the instructions, skills and MCP "
            "configuration this repository gives Copilot.\n"
        )
    lines = [
        "### This pull request changes what Copilot reads",
        "",
        "These files decide how the coding agent behaves in this repository, so a "
        "change here is a change to the agent, not only to the code.",
        "",
        "| Change | What | File |",
        "|---|---|---|",
    ]
    symbol = {"added": "added", "removed": "removed", "changed": "changed"}
    for change in changes:
        lines.append("| %s | %s | `%s` |" % (symbol.get(change["change"], change["change"]),
                                             change["what"], change["detail"]))
    lines += [
        "",
        "If these changes are intended, update the baseline in this same pull request "
        "so the two are reviewed together:",
        "",
        "```bash",
        "python copilot/engine/capture.py approve",
        "```",
        "",
        "That rewrites `%s`. Review it as you would any other change to how this "
        "repository behaves." % baseline_rel,
        "",
    ]
    return "\n".join(lines)


def _root(args) -> Path:
    return Path(args.root).resolve()


def cmd_snapshot(args) -> int:
    print(json.dumps(snapshot(_root(args)), indent=2))
    return 0


def cmd_approve(args) -> int:
    root = _root(args)
    path = root / BASELINE_PATH
    core.save_state(path, snapshot(root))
    print("approved baseline written: %s" % BASELINE_PATH.as_posix())
    print("Commit it in the same change as the files it describes.")
    return 0


def cmd_verify(args) -> int:
    """Exit 1 on drift, so the action fails the check without extra glue."""
    root = _root(args)
    base = load_baseline(root)
    current = snapshot(root)
    if base is None:
        print("No approved baseline at %s." % BASELINE_PATH.as_posix())
        print("Create one with: python copilot/engine/capture.py approve")
        # Not a failure. A repository adopting this should not have its first pull
        # request blocked by the absence of a file it has not been told to create.
        return 0
    changes = diff(base, current)
    print(comment_body(changes, BASELINE_PATH.as_posix()))
    if args.comment_file:
        Path(args.comment_file).write_text(
            comment_body(changes, BASELINE_PATH.as_posix()), encoding="utf-8"
        )
    return 1 if changes else 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentrust-copilot", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("snapshot", "verify", "approve"):
        child = sub.add_parser(name)
        child.add_argument("--root", default=".", help="repository root (default: .)")
        child.add_argument("--comment-file", default=None,
                          help="verify: also write the comment body here")
    args = parser.parse_args(argv)
    return {"snapshot": cmd_snapshot, "verify": cmd_verify, "approve": cmd_approve}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
