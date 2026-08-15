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
| Instructions and custom agents | `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `.github/agents/**/*.agent.md`, **`AGENTS.md` anywhere in the tree**, root `CLAUDE.md` and `GEMINI.md` |
| Skills | `.github/skills/<name>/`, `.claude/skills/<name>/`, `.agents/skills/<name>/` |
| MCP | `.mcp.json`, `.github/mcp.json`, `.vscode/mcp.json`, `.devcontainer/devcontainer.json`, `.devcontainer.json`, `.devcontainer/*/devcontainer.json` |

Four of those deserve a note.

**`AGENTS.md` is matched anywhere**, because Copilot resolves the nearest one. A
file added three directories down changes how the agent behaves in that subtree
without touching anything at the root, and that is exactly the change worth
catching. Vendored directories (`node_modules`, `vendor`, `.venv` and friends) are
skipped, so a dependency shipping its own `AGENTS.md` is not counted as yours.

**Skills are digested across the whole directory**, not just `SKILL.md`. A skill's
`scripts/` decide what it does. Digesting the manifest alone was a live bypass in
two other engines in this repo, so the shared core covers the tree.

**MCP configuration depends on the Copilot surface**, and only some of it is a
repository file. VS Code reads `.vscode/mcp.json`. Copilot CLI reads `.mcp.json`
per checkout and `.github/mcp.json` as the committed shared form, on top of the
user-level `~/.copilot/mcp-config.json` on the developer's own machine. All the
repository ones are measured; the home-directory one is what the Claude Code and
Codex engines here watch instead. Copilot cloud-agent MCP servers are entered as
JSON in the repository's GitHub settings and live in no file, so a file-based
check cannot see them at all. A custom cloud agent may embed `mcp-servers` in
`.github/agents/*.agent.md`, and those profiles are measured in full with the
instruction surface. There is no `copilot/mcp-config.json` path in any of this.

**Dev container definitions are digested whole**, not parsed for the one key that
matters. `devcontainer.json` carries MCP servers under `customizations.vscode.mcp`,
but the file is JSONC, and a parser that mishandles a comment or a trailing comma
would report "nothing changed" about a file it failed to read. So an unrelated
devcontainer edit shows up as an MCP config change. That is a false positive a
reviewer settles by reading the diff, and it is the direction worth being wrong in.

## What it does not do

- **It does not read your model or your tool roster.** Those are session facts, not
  repository files. This integration measures what the repository gives Copilot.
- **It does not evaluate whether an instruction is good.** It tells you one changed
  and who changed it. Judgement is the reviewer's.
- **It does not cover organisation-level or personal instructions.** Those are set
  outside the repository and are invisible to a check that runs inside it. If your
  organisation sets Copilot instructions centrally, this check does not see them.
- **It does not cover MCP servers configured outside the repository**, and there are
  two such places. `~/.copilot/mcp-config.json` is a developer's own machine, which
  is what the Claude Code and Codex engines here watch instead. The coding agent's
  MCP configuration is entered as JSON in repository settings on github.com, so it
  never appears in a diff and no check running inside the repository can see it.
  Both are real gaps in coverage. Neither is something this check can close, and
  saying so is better than a green tick that means less than a reader assumes.
- **It is not a sandbox.** It reports composition, it does not constrain execution.
- **It emits no signed record**, unlike the other integrations here, and that is a
  spec question rather than a missing feature. See
  [agent-manifest#256](https://github.com/agentrust-io/agent-manifest/issues/256).

  A TRACE record is the wrong artifact: TRACE describes an execution, and this check
  describes a composition. Agent Manifest is the right one, and every level requires
  `artifacts.model_identity`. A repository cannot know the model. Copilot chooses it
  at session time from the user's plan and settings, so the same repository serves
  every model with an identical contributed composition.

  `provider: github, model_id: copilot` would describe a product rather than a
  model, and `model_id: unknown` would assert a binding to a thing called "unknown".
  Either is the sort of unverifiable claim this repository's contributing rules
  exclude, so the check ships without a record until the spec can express a
  composition whose model is unknowable when it is authored. Notably the verifier
  vocabulary already has `NOT_BOUND` for every artifact, and no conformant manifest
  can currently produce it.

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

One dependency: [`agentrust-capture-core`](../packages/agentrust-capture-core),
which has none of its own. The action installs it before running the check.

## License

Apache-2.0.
