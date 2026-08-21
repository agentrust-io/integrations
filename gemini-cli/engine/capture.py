"""AgenTrust agent-integrity check for Gemini CLI.

Gemini CLI's composition lives in the repository, the same shape #68
established for Copilot: context files, skills and MCP configuration are files
that arrive by pull request, so this is a status check rather than a local
warning.

  Does this pull request change what Gemini CLI reads, without saying so?

What Gemini CLI reads, verified against the project's own documentation at
google-gemini.github.io/gemini-cli (GitHub Pages under the official
google-gemini organisation, mirroring github.com/google-gemini/gemini-cli):

  context  GEMINI.md            anywhere in the tree

                                 Gemini CLI's own docs describe a hierarchy:
                                 the current working directory and its parent
                                 directories up to the project root, plus
                                 subdirectories below the working directory,
                                 respecting .gitignore and .geminiignore. For a
                                 static, whole-repository check that means any
                                 matching file is a real surface, the same
                                 reasoning Copilot's README gives for AGENTS.md
                                 anywhere in the tree, so this globs
                                 recursively rather than checking the root only.

                                 Deliberately not measured: settings.json's
                                 context.fileName can rename the file Gemini
                                 CLI actually looks for. Detecting an arbitrary
                                 configured name would mean parsing settings.json
                                 first to know what to even look for, which is
                                 real complexity for what is, today, a rarely
                                 used override, so this measures the documented
                                 default name and says so rather than silently
                                 covering less than it appears to.

  skills   .gemini/skills/<name>/SKILL.md   workspace, at the repository root
           .agents/skills/<name>/SKILL.md   cross-agent compatibility, same
                                             root

                                 Gemini CLI's own docs describe workspace
                                 skills as living "within your current
                                 directory", with no mention of the
                                 monorepo-anywhere behaviour Cursor documents
                                 for its own skills root, so these stay fixed
                                 at the repository root rather than matched
                                 anywhere in the tree.

  mcp      .gemini/settings.json            repository root, whole file

                                 MCP servers are configured under an
                                 mcpServers key inside settings.json, the same
                                 file that carries context.fileName and other,
                                 unrelated settings. This is digested whole
                                 rather than parsed for the one key that
                                 matters, the same choice Copilot's engine
                                 makes for devcontainer.json and for the same
                                 reason: a parser that mishandles the file
                                 quietly reports nothing changed about a file
                                 it failed to read, so an unrelated settings
                                 edit showing up as MCP-adjacent drift is the
                                 direction worth being wrong in. ~/.gemini/settings.json
                                 is the home-directory equivalent and is out of
                                 scope for the same reason Copilot excludes
                                 ~/.copilot/mcp-config.json: nothing there
                                 arrives by pull request.

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
BASELINE_PATH = Path(".agentrust") / "gemini-cli-baseline.json"

#: Glob for context files, matched anywhere in the tree: see the module
#: docstring for why (Gemini CLI's own docs describe a hierarchy of parent and
#: child directories, not a fixed root-only location).
CONTEXT_GLOBS = ("**/GEMINI.md",)

#: Directories holding one subdirectory per skill, fixed at the repository
#: root: Gemini CLI's docs describe workspace skills as living within the
#: current directory, with no monorepo-anywhere equivalent to Cursor's.
SKILL_ROOTS = (
    ".gemini/skills",
    ".agents/skills",
)

#: MCP server configuration Gemini CLI reads from the repository. A single,
#: whole-file digest: see the module docstring for why this is not parsed for
#: just the mcpServers key.
MCP_FILES = (".gemini/settings.json",)

#: Directories never walked when looking for context files or skills. Without
#: this, a vendored dependency carrying its own GEMINI.md would be reported as
#: part of this repository's agent composition.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
})

CATEGORIES = ("context", "skills", "mcp")


def _is_skipped(relative: Path) -> bool:
    return bool(SKIP_DIRS & set(relative.parts))


def _context(root: Path) -> dict:
    """Digest each context file Gemini CLI would read, keyed by repo-relative path."""
    found: dict = {}
    for pattern in CONTEXT_GLOBS:
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
    """Digest each skill directory, keyed by ``<root>:<name>``."""
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
        "context": _context(root),
        "skills": _skills(root),
        "mcp": _mcp(root),
    }


def load_baseline(root: Path) -> dict | None:
    """The approved baseline, or None when the repository has not adopted one."""
    return core.load_state(root / BASELINE_PATH)


def diff(base: dict, current: dict) -> list:
    common = core.observed_categories(base, current, CATEGORIES)
    changes: list = []
    if "context" in common:
        changes += core.diff_maps(base.get("context", {}), current.get("context", {}),
                                 "context file")
    if "skills" in common:
        changes += core.diff_maps(base.get("skills", {}), current.get("skills", {}), "skill")
    if "mcp" in common:
        changes += core.diff_maps(base.get("mcp", {}), current.get("mcp", {}), "MCP config")
    return changes


def comment_body(changes: list, baseline_rel: str) -> str:
    """The pull-request comment. Names files, because a digest is not actionable."""
    if not changes:
        return (
            "### Gemini CLI agent composition unchanged\n\n"
            "Nothing added, nothing subtracted in the context files, skills and "
            "MCP configuration this repository gives Gemini CLI.\n"
        )
    lines = [
        "### This pull request changes what Gemini CLI reads",
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
        "python gemini-cli/engine/capture.py approve",
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
        print("Create one with: python gemini-cli/engine/capture.py approve")
        return 0
    changes = diff(base, current)
    print(comment_body(changes, BASELINE_PATH.as_posix()))
    if args.comment_file:
        Path(args.comment_file).write_text(
            comment_body(changes, BASELINE_PATH.as_posix()), encoding="utf-8"
        )
    return 1 if changes else 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentrust-gemini-cli", description=__doc__)
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
