# AgenTrust for GitHub Copilot

**Review changes to your coding agent the way you review changes to your code.**

Copilot is not just a model. In this repository it is a model plus the instructions
you wrote it, the skills you gave it, and the MCP servers you connected. Those files
decide what the agent will do to your codebase, and every one of them arrives by
pull request.

So this integration is not a local warning. It is a status check:

> **Does this pull request change what Copilot reads, without saying so?**

## Why this differs from the other integrations here

The Claude Code and Codex integrations watch a developer's machine and warn at
session start, after the fact, one developer at a time. They have to, because that
composition lives in a home directory.

Copilot's composition lives in the repository. That is a better place to defend:

- **One baseline, shared.** Committed at `.agentrust/copilot-baseline.json`, not one
  per laptop.
- **Reviewed like code.** A change to the agent's instructions shows up in a diff
  with an author, and can require a reviewer.
- **Enforceable.** As a required status check, a pull request that changes the
  agent's behaviour without updating the baseline does not merge.
- **Caught on entry.** At the moment it enters the codebase, rather than on some
  developer's next session.

It also means **this integration does not seal its baseline**, unlike the others.
They do, because a local baseline can be rewritten with nothing to show for it. A
committed baseline gets provenance from git. Adding a digest on top would be
ceremony.

## Quickstart

```yaml
# .github/workflows/copilot-integrity.yml
name: Copilot integrity
on: pull_request

permissions:
  contents: read
  pull-requests: write   # only needed for the comment

jobs:
  integrity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: agentrust-io/integrations/copilot@main
```

Then create the baseline and commit it:

```bash
python copilot/engine/capture.py approve
git add .agentrust/copilot-baseline.json
```

Adopting this on a busy repository? Start with `fail-on-drift: false`. You get the
comment and the summary without blocking anyone, and you can flip it on once the
baseline is settled.

## What it measures

Verified against GitHub's documentation for what Copilot actually reads.

| Category | Paths |
|---|---|
| Instructions | `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, **`AGENTS.md` anywhere in the tree**, root `CLAUDE.md` and `GEMINI.md` |
| Skills | `.github/skills/<name>/`, `.claude/skills/<name>/`, `.agents/skills/<name>/` |
| MCP | `copilot/mcp-config.json`, `.vscode/mcp.json` |

Two of those deserve a note.

**`AGENTS.md` is matched anywhere**, because Copilot resolves the nearest one. A
file added three directories down changes how the agent behaves in that subtree
without touching anything at the root, and that is exactly the change worth
catching. Vendored directories (`node_modules`, `vendor`, `.venv` and friends) are
skipped, so a dependency shipping its own `AGENTS.md` is not counted as yours.

**Skills are digested across the whole directory**, not just `SKILL.md`. A skill's
`scripts/` decide what it does. Digesting the manifest alone was a live bypass in
two other engines in this repo, so the shared core covers the tree.

## What it does not do

- **It does not read your model or your tool roster.** Those are session facts, not
  repository files. This integration measures what the repository gives Copilot.
- **It does not evaluate whether an instruction is good.** It tells you one changed
  and who changed it. Judgement is the reviewer's.
- **It does not cover organisation-level or personal instructions.** Those are set
  outside the repository and are invisible to a check that runs inside it. If your
  organisation sets Copilot instructions centrally, this check does not see them.
- **It is not a sandbox.** It reports composition, it does not constrain execution.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `root` | `.` | Repository root to inspect |
| `comment` | `true` | One comment per pull request, edited in place rather than appended per push |
| `fail-on-drift` | `true` | Set `false` to report without blocking |
| `github-token` | `${{ github.token }}` | Only used to post the comment |

## Commands

```bash
python copilot/engine/capture.py snapshot   # print the composition as JSON
python copilot/engine/capture.py verify     # diff against the baseline, exit 1 on drift
python copilot/engine/capture.py approve    # write the baseline
```

No install step. The engine and its vendored copy of
[`agentrust-capture-core`](../packages/agentrust-capture-core) are standard library
only.

## License

Apache-2.0.
