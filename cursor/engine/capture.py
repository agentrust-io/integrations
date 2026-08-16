"""AgenTrust agent-integrity check for Cursor.

Cursor's composition lives in the repository, the same shape #68 established for
Copilot: rules, skills and MCP configuration are all files that arrive by pull
request, so this is a status check rather than a local warning.

  Does this pull request change what Cursor reads, without saying so?

What Cursor reads, verified against cursor.com/docs (Customize > Rules and
Customize > MCP):

  rules   .cursor/rules/**/*.mdc          nested folders are an intended
                                           organisational pattern, per the
                                           docs' own example
                                           (.cursor/rules/frontend/components.mdc),
                                           so this globs recursively rather
                                           than one level. A plain .md file
                                           here is ignored by Cursor itself
                                           (wrong extension), and so is not
                                           measured.
          AGENTS.md                       project root and subdirectories,
                                           "a simple alternative to
                                           .cursor/rules"; the docs changelog
                                           separately lists "Nested AGENTS.md
                                           support", so this is matched
                                           anywhere in the tree, the same
                                           reasoning Copilot's own engine
                                           gives for the same file
          .cursorrules                    NOT in current official docs.
                                           The docs enumerate exactly four
                                           rule types (Project, User, Team,
                                           AGENTS.md) and this is not one of
                                           them. A community forum thread
                                           claims a past deprecation with no
                                           staff confirmation, and its
                                           absence from current docs is
                                           consistent with that, though
                                           neither proves Cursor has actually
                                           stopped reading it. Still
                                           measured, since a false positive
                                           here (tracking a file Cursor no
                                           longer reads) is harmless, while
                                           dropping it would be a silent miss
                                           if it turns out to still work.

  skills  .cursor/skills/<name>/SKILL.md  anywhere in the tree
          .agents/skills/<name>/SKILL.md  anywhere in the tree
          .claude/skills/<name>/SKILL.md  anywhere in the tree, compatibility
          .codex/skills/<name>/SKILL.md   anywhere in the tree, compatibility

                                           Unlike rules, Cursor's documentation
                                           describes this as intentional:
                                           a skills root "anywhere inside your
                                           repository is picked up, so
                                           monorepos can colocate skills with
                                           the package they apply to", and a
                                           root itself is walked recursively
                                           for category subfolders such as
                                           .cursor/skills/shipping/deploy/.
                                           So this looks for a skills root at
                                           any depth, then for SKILL.md at any
                                           depth beneath each root found.

  mcp     .cursor/mcp.json                "Project Configuration: Create
                                           .cursor/mcp.json in your project
                                           for project-specific tools."

                                           ~/.cursor/mcp.json is the docs'
                                           own "Global Configuration", a
                                           home-directory file, not a
                                           repository surface, and is deliberately
                                           not measured here for the same reason
                                           Copilot's ~/.copilot/mcp-config.json
                                           is not: nothing there arrives by pull
                                           request, and a check that implied
                                           otherwise would be worse than one
                                           that says nothing.

Standard library only, so the action needs no install step beyond the shared core.

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

try:
    import agentrust_capture_core as core
except ImportError as _exc:  # pragma: no cover - install-time failure path
    raise SystemExit(
        "AgenTrust needs agentrust-capture-core, which is not installed.\n"
        "Install it with:  pip install agentrust-capture-core\n"
        "Drift detection cannot run without it."
    ) from _exc

VERSION = "0.1.0"

#: Version of WHAT this engine measures. See copilot/engine/capture.py for why
#: this exists: widening coverage must not be reported as drift that happened.
MEASUREMENT_SCOPE = 1

#: Where the approved baseline lives, relative to the repository root.
BASELINE_PATH = Path(".agentrust") / "cursor-baseline.json"

#: Single files Cursor reads as rules, relative to the repository root.
RULE_FILES = (".cursorrules",)

#: Globs for rule files. .cursor/rules is walked recursively: cursor.com/docs
#: shows nested folders (.cursor/rules/frontend/components.mdc) as an intended
#: organisational pattern, not an edge case. AGENTS.md is matched anywhere in
#: the tree for the same reason Copilot's own engine matches it: the docs
#: describe subdirectory support explicitly, and a nearest-file resolution.
RULE_GLOBS = (".cursor/rules/**/*.mdc", "**/AGENTS.md")

#: Directory names that hold one subdirectory per skill, matched at any depth
#: in the tree so a monorepo package can colocate its own skills root.
SKILL_ROOT_NAMES = (
    ".cursor/skills",
    ".agents/skills",
    ".claude/skills",
    ".codex/skills",
)

#: MCP server configuration Cursor reads from the repository.
MCP_FILES = (".cursor/mcp.json",)

#: Directories never walked when looking for rules or skills. Without this, a
#: vendored dependency carrying its own rules or skills would be reported as
#: part of this repository's agent composition.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
})

CATEGORIES = ("rules", "skills", "mcp")


def _is_skipped(relative: Path) -> bool:
    return bool(SKIP_DIRS & set(relative.parts))


def _rules(root: Path) -> dict:
    """Digest each rule file Cursor would read, keyed by repo-relative path."""
    found: dict = {}
    for name in RULE_FILES:
        path = root / name
        digest = core.safe_sha_file(path) if path.is_file() else None
        if digest:
            found[name] = digest
    for pattern in RULE_GLOBS:
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

    Unlike Copilot's fixed, root-only skill directories, a Cursor skills root
    can appear anywhere in the tree and can nest a SKILL.md at any depth
    beneath it, so both the root and the SKILL.md search are recursive.
    """
    found: dict = {}
    for root_name in SKILL_ROOT_NAMES:
        try:
            skill_roots = sorted(root.glob("**/%s" % root_name))
        except OSError:
            continue
        for skill_root in skill_roots:
            if skill_root.is_symlink() or not skill_root.is_dir():
                continue
            relative_root = skill_root.relative_to(root)
            if _is_skipped(relative_root):
                continue
            try:
                manifests = sorted(skill_root.rglob("SKILL.md"))
            except OSError:
                continue
            for manifest in manifests:
                if manifest.is_symlink() or not manifest.is_file():
                    continue
                skill_dir = manifest.parent
                if skill_dir.is_symlink():
                    continue
                relative_skill = skill_dir.relative_to(skill_root)
                if _is_skipped(relative_skill):
                    continue
                digest = core.tree_digest(skill_dir)
                if digest:
                    key = "%s:%s" % (relative_root.as_posix(), relative_skill.as_posix())
                    found[key] = digest
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
        "rules": _rules(root),
        "skills": _skills(root),
        "mcp": _mcp(root),
    }


def load_baseline(root: Path) -> dict | None:
    """The approved baseline, or None when the repository has not adopted one."""
    return core.load_state(root / BASELINE_PATH)


def diff(base: dict, current: dict) -> list:
    common = core.observed_categories(base, current, CATEGORIES)
    changes: list = []
    if "rules" in common:
        changes += core.diff_maps(base.get("rules", {}), current.get("rules", {}), "rule file")
    if "skills" in common:
        changes += core.diff_maps(base.get("skills", {}), current.get("skills", {}), "skill")
    if "mcp" in common:
        changes += core.diff_maps(base.get("mcp", {}), current.get("mcp", {}), "MCP config")
    return changes


def comment_body(changes: list, baseline_rel: str) -> str:
    """The pull-request comment. Names files, because a digest is not actionable."""
    if not changes:
        return (
            "### Cursor agent composition unchanged\n\n"
            "Nothing added, nothing subtracted in the rules, skills and MCP "
            "configuration this repository gives Cursor.\n"
        )
    lines = [
        "### This pull request changes what Cursor reads",
        "",
        "These files decide how the agent behaves in this repository, so a "
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
        "python cursor/engine/capture.py approve",
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
        print("Create one with: python cursor/engine/capture.py approve")
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
    parser = argparse.ArgumentParser(prog="agentrust-cursor", description=__doc__)
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
