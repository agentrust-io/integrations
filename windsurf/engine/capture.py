"""AgenTrust agent-integrity check for Windsurf.

Windsurf's composition lives in the repository, the same shape #68 established
for Copilot: rules and skills are files that arrive by pull request, so this is
a status check rather than a local warning.

  Does this pull request change what Windsurf reads, without saying so?

What Windsurf reads, verified against docs.windsurf.com, which as of this
writing redirects to docs.devin.ai: Cognition, which makes the standalone Devin
agent, now also owns Windsurf, and the rebrand has already reached the rules
surface, though not (yet, as verified) the skills surface. That split matters:
assuming both surfaces moved together would have been wrong.

  rules   .devin/rules/*.md        preferred since the rebrand
          .windsurf/rules/*.md     fallback, explicitly "kept for backward
                                    compatibility", not deprecated
          .windsurfrules           legacy single file at the workspace root,
                                    still read

                                    The first two are discovered anywhere in the
                                    tree: Windsurf's docs describe rules as
                                    discovered "in the current workspace
                                    directory, any sub-directories, and parent
                                    directories up to the git root", which for a
                                    static, whole-repository check means any
                                    matching path is a real surface, not only
                                    one at a fixed location.

  skills  .windsurf/skills/<name>/SKILL.md   workspace, still under the
                                              pre-rebrand name as of this
                                              writing; unlike rules, the skills
                                              documentation makes no mention of
                                              a .devin/skills/ equivalent
          .agents/skills/<name>/SKILL.md     cross-agent compatibility
          .claude/skills/<name>/SKILL.md     compatibility, gated behind a
                                              Windsurf setting the repository
                                              cannot see; measured anyway, on
                                              the same reasoning Copilot
                                              measures it unconditionally: what
                                              a vendor could read if a developer
                                              enables it is still worth knowing
                                              changed

  mcp     none. Cascade's MCP configuration lives at
          ~/.codeium/windsurf/mcp_config.json, a home-directory file with no
          project-level or repository-committed equivalent documented anywhere.
          Unlike Copilot, which measures three repository MCP paths and
          excludes only the home-directory one, there is no repository MCP
          surface here to measure at all, so this engine has no "mcp" category.

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
BASELINE_PATH = Path(".agentrust") / "windsurf-baseline.json"

#: Single files Windsurf reads as rules, relative to the repository root.
RULE_FILES = (".windsurfrules",)

#: Globs for rule files, matched anywhere in the tree: see the module
#: docstring for why (Windsurf's own docs describe discovery from sub- and
#: parent directories, not a fixed workspace-root-only location).
RULE_GLOBS = (
    ".devin/rules/*.md",
    ".windsurf/rules/*.md",
)

#: Directories holding one subdirectory per skill, each a fixed root rather
#: than matched anywhere: unlike Cursor, Windsurf's documentation does not
#: describe monorepo-anywhere skill roots.
SKILL_ROOTS = (
    ".windsurf/skills",
    ".agents/skills",
    ".claude/skills",
)

#: Directories never walked when looking for rules or skills. Without this, a
#: vendored dependency carrying its own rules or skills would be reported as
#: part of this repository's agent composition.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
})

CATEGORIES = ("rules", "skills")


def _is_skipped(relative: Path) -> bool:
    return bool(SKIP_DIRS & set(relative.parts))


def _rules(root: Path) -> dict:
    """Digest each rule file Windsurf would read, keyed by repo-relative path."""
    found: dict = {}
    for name in RULE_FILES:
        path = root / name
        digest = core.safe_sha_file(path) if path.is_file() else None
        if digest:
            found[name] = digest
    for pattern in RULE_GLOBS:
        try:
            matches = sorted(root.glob("**/%s" % pattern))
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

    Fixed roots at the repository root, one level of subdirectories, matching
    Copilot's shape rather than Cursor's anywhere-in-tree one: Windsurf's own
    documentation gives no indication that a skills root may live below the
    repository root.
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


def snapshot(root: Path) -> dict:
    return {
        "captured_at": core.now_iso(),
        "scope": MEASUREMENT_SCOPE,
        "observed": list(CATEGORIES),
        "rules": _rules(root),
        "skills": _skills(root),
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
    return changes


def comment_body(changes: list, baseline_rel: str) -> str:
    """The pull-request comment. Names files, because a digest is not actionable."""
    if not changes:
        return (
            "### Windsurf agent composition unchanged\n\n"
            "Nothing added, nothing subtracted in the rules and skills this "
            "repository gives Windsurf.\n"
        )
    lines = [
        "### This pull request changes what Windsurf reads",
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
        "python windsurf/engine/capture.py approve",
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
        print("Create one with: python windsurf/engine/capture.py approve")
        return 0
    changes = diff(base, current)
    print(comment_body(changes, BASELINE_PATH.as_posix()))
    if args.comment_file:
        Path(args.comment_file).write_text(
            comment_body(changes, BASELINE_PATH.as_posix()), encoding="utf-8"
        )
    return 1 if changes else 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentrust-windsurf", description=__doc__)
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
