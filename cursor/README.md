# AgenTrust for Cursor

**Review changes to your coding agent the way you review changes to your code.**

Cursor is not just a model. In this repository it is a model plus the rules you
wrote it, the skills you gave it, and the MCP servers you connected. Those files
decide what the agent will do to your codebase, and every one of them arrives by
pull request.

So this integration is not a local warning. It is a status check, the same shape
[#68](https://github.com/agentrust-io/integrations/issues/68) established for
Copilot:

> **Does this pull request change what Cursor reads, without saying so?**

## Quickstart

```yaml
# .github/workflows/cursor-integrity.yml
name: Cursor integrity
on: pull_request

permissions:
  contents: read
  pull-requests: write   # only needed for the comment

jobs:
  integrity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: agentrust-io/integrations/cursor@main
```

Then create the baseline and commit it:

```bash
python cursor/engine/capture.py approve
git add .agentrust/cursor-baseline.json
```

Adopting this on a busy repository? Start with `fail-on-drift: false`. You get the
comment and the summary without blocking anyone, and you can flip it on once the
baseline is settled.

## What it measures

Verified against cursor.com/docs (Customize > Rules, Customize > Skills,
Customize > MCP).

| Category | Paths |
|---|---|
| Rules | `.cursor/rules/**/*.mdc` (**nested folders included**, see below), `AGENTS.md` (**anywhere in the tree**), `.cursorrules` (legacy, see below) |
| Skills | `.cursor/skills/<name>/`, `.agents/skills/<name>/`, `.claude/skills/<name>/`, `.codex/skills/<name>/` (**anywhere in the tree**, see below) |
| MCP | `.cursor/mcp.json` |

Three of those deserve a note.

**`.cursor/rules` is walked recursively, and includes `AGENTS.md`.** The docs'
own example organises rules in folders, `.cursor/rules/frontend/components.mdc`,
presented as a normal pattern rather than an edge case, so this globs
recursively rather than one level. A plain `.md` file in `.cursor/rules` is
ignored by Cursor itself for having the wrong extension, and is not measured
either. `AGENTS.md` is one of exactly four documented rule types ("a simple
alternative to `.cursor/rules`"), read from the project root and
subdirectories, with "Nested AGENTS.md support" listed as a shipped
improvement, so it is matched anywhere in the tree, the same reasoning
Copilot's own engine gives for the same file.

**`.cursorrules` does not appear in current official docs at all.** The docs
list four rule types, Project Rules, User Rules, Team Rules and `AGENTS.md`,
and `.cursorrules` isn't one of them. Whether Cursor still reads it is
unconfirmed either way. Still measured: dropping it risks a silent miss if it
does, and tracking it costs nothing if it does not.

**Skill roots are measured anywhere in the tree, on purpose, the opposite
adjustment from the old `.cursor/rules` assumption this replaced.** Confirmed
directly: "Cursor walks the skills root recursively and picks up any
`SKILL.md` it finds", and separately, a `.cursor/skills/` (or
`.agents/skills/`, `.claude/skills/`, `.codex/skills/`) folder "anywhere
inside your repository is picked up, so monorepos can colocate skills with
the package they apply to", for example `apps/web/.cursor/skills/`. Both
behaviours are documented, not inferred. The category folder itself carries
no meaning to Cursor beyond organisation, for example
`.cursor/skills/shipping/land-it/`, with the skill's identity coming from the
folder that holds `SKILL.md`, so this engine keeps the category in its own
key for precision even though Cursor itself does not use it for identity.
Both of Cursor's Claude- and Codex-compatible skill roots are measured for
the same reason Copilot measures them: whichever directories Cursor actually
reads are this repository's Cursor composition, regardless of which vendor's
name is on the directory.

## What it does not do

- **It does not measure `~/.cursor/mcp.json`.** That is a home-directory file,
  configured per developer, and it never arrives by pull request. A check that
  implied otherwise would be worse than one that says nothing, the same reasoning
  Copilot's README gives for `~/.copilot/mcp-config.json`.
- **It does not evaluate whether a rule is good.** It tells you one changed and
  who changed it. Judgement is the reviewer's.
- **It does not cover Cursor's User Rules or Team Rules.** User Rules are a
  developer's own global settings; Team Rules are managed from the Cursor
  dashboard and apply org-wide. Neither is a file in this repository, so
  neither arrives by pull request and neither is visible to a check that runs
  inside it.
- **It does not cover Cursor's built-in skills** (`/automate`, `/babysit`,
  `/review`, and the rest of the shipped set). Those ship with the product
  itself, not as files in any repository, so there is nothing here for a
  file-based check to see.
- **It is not a sandbox.** It reports composition, it does not constrain
  execution.
- **It emits no signed record.** Same reasoning as Copilot: a repository cannot
  know which model a given Cursor session used, since that is chosen at session
  time from the developer's own settings, not fixed by anything in the
  repository. See [agent-manifest#256](https://github.com/agentrust-io/agent-manifest/issues/256).

## Inputs

| Input | Default | Notes |
|---|---|---|
| `root` | `.` | Repository root to inspect |
| `comment` | `true` | One comment per pull request, edited in place rather than appended per push |
| `fail-on-drift` | `true` | Set `false` to report without blocking |
| `github-token` | `${{ github.token }}` | Only used to post the comment |

## Commands

```bash
python cursor/engine/capture.py snapshot   # print the composition as JSON
python cursor/engine/capture.py verify     # diff against the baseline, exit 1 on drift
python cursor/engine/capture.py approve    # write the baseline
```

One dependency: [`agentrust-capture-core`](../packages/agentrust-capture-core),
which has none of its own. The action installs it before running the check.

## License

Apache-2.0.
