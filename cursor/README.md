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

cursor.com itself could not be reached directly during this research (every
fetch attempt was refused), so this is verified against Cursor's own community
forum plus multiple independent guides that converge on the same specifics.
Two of these paths turned out to be shaped differently from what a naive
reading of the issue's original table would suggest.

| Category | Paths |
|---|---|
| Rules | `.cursorrules` (repository root), `.cursor/rules/*.mdc` (**one level only**, see below) |
| Skills | `.cursor/skills/<name>/`, `.agents/skills/<name>/`, `.claude/skills/<name>/`, `.codex/skills/<name>/` (**anywhere in the tree**, see below) |
| MCP | `.cursor/mcp.json` |

Two of those deserve a note, because they were the two places where trusting a
table instead of checking would have gotten this wrong.

**`.cursor/rules/*.mdc` is measured one level deep, not recursively.** Cursor's
own community forum documents `.cursor/rules/x.mdc` working and
`.cursor/rules/sub/x.mdc` not being reliably read. Globbing recursively would
create a false negative, a rule reported unchanged forever that Cursor never
actually loads, rather than a false positive, and that is the wrong direction to
be wrong in for a drift check. `.cursorrules` at the repository root is measured
too: it is legacy, and a forum thread claims a future deprecation, but no
Cursor staff response confirms that anywhere in the thread, so this measures
what is read today rather than repeating an unconfirmed claim about the future.

**Skill roots are measured anywhere in the tree, on purpose, the opposite
adjustment from rules.** Cursor's docs describe this as intentional: a
`.cursor/skills/` (or `.agents/skills/`, `.claude/skills/`, `.codex/skills/`)
folder anywhere inside the repository is picked up, so a monorepo package can
colocate its own skills with the code it applies to, for example
`apps/web/.cursor/skills/`. A root is also walked recursively beneath itself for
category subfolders, for example
`.cursor/skills/shipping/deploy-staging/`, with the skill's name coming from the
folder that holds `SKILL.md`, not the category folder above it. Both of Cursor's
Claude- and Codex-compatible skill roots are measured for the same reason
Copilot measures them: whichever directories Cursor actually reads are this
repository's Cursor composition, regardless of which vendor's name is on the
directory.

## What it does not do

- **It does not measure `~/.cursor/mcp.json`.** That is a home-directory file,
  configured per developer, and it never arrives by pull request. A check that
  implied otherwise would be worse than one that says nothing, the same reasoning
  Copilot's README gives for `~/.copilot/mcp-config.json`.
- **It does not evaluate whether a rule is good.** It tells you one changed and
  who changed it. Judgement is the reviewer's.
- **It does not cover Cursor's global rules or skills**, set outside the
  repository in a developer's own Cursor settings. Those are invisible to a check
  that runs inside the repository.
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
