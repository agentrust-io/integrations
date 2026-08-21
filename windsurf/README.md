# AgenTrust for Windsurf

**Review changes to your coding agent the way you review changes to your code.**

Windsurf is not just a model. In this repository it is a model plus the rules
you wrote it and the skills you gave it. Those files decide what the agent will
do to your codebase, and every one of them arrives by pull request.

So this integration is not a local warning. It is a status check, the same
shape [#68](https://github.com/agentrust-io/integrations/issues/68) established
for Copilot:

> **Does this pull request change what Windsurf reads, without saying so?**

## Quickstart

```yaml
# .github/workflows/windsurf-integrity.yml
name: Windsurf integrity
on: pull_request

permissions:
  contents: read
  pull-requests: write   # only needed for the comment

jobs:
  integrity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: agentrust-io/integrations/windsurf@main
```

Then create the baseline and commit it:

```bash
python windsurf/engine/capture.py approve
git add .agentrust/windsurf-baseline.json
```

Adopting this on a busy repository? Start with `fail-on-drift: false`. You get the
comment and the summary without blocking anyone, and you can flip it on once the
baseline is settled.

## What it measures

Verified against `docs.windsurf.com`, which as of this writing redirects to
`docs.devin.ai`. Cognition, which makes the standalone Devin agent, now also
owns Windsurf, and the rebrand has already reached one surface here but not
the other. Assuming both moved together would have been wrong, and checking
each one separately is what caught it.

| Category | Paths |
|---|---|
| Rules | `.devin/rules/*.md` (preferred), `.windsurf/rules/*.md` (fallback, not deprecated), `.windsurfrules` (legacy, workspace root) |
| Skills | `.windsurf/skills/<name>/`, `.agents/skills/<name>/`, `.claude/skills/<name>/` |

**Rules moved to `.devin/`, skills did not, as verified today.** Windsurf's
documentation is explicit that `.devin/rules/` is now preferred, with
`.windsurf/rules/` "kept as a fallback for backward compatibility", so both are
measured, plus the legacy single-file `.windsurfrules` at the workspace root.
The skills documentation, checked separately, gives no `.devin/skills/`
equivalent as of this writing, only `.windsurf/skills/`, so that is what is
measured. If Cognition finishes migrating skills the same way, this will need
its own path addition the same way #78 added Windsurf's rules split, not an
assumption that it happened because rules did.

**Rules are measured anywhere in the tree; skills are measured only at the
repository root.** Windsurf's rules documentation describes discovery from
sub-directories and parent directories up to the git root, not a fixed
location, so this check globs recursively. The skills documentation gives no
equivalent statement, and unlike Cursor's explicit monorepo-anywhere skill
roots, there is nothing here to justify matching below the root, so skill
roots stay fixed.

**`.claude/skills/` is measured even though it is opt-in.** Reading it depends
on a Windsurf setting this check cannot see from inside a repository. It is
measured anyway, the same reasoning Copilot uses for its own optional
surfaces: what a vendor could read if a developer enables it is still worth
knowing changed.

## What it does not do

- **It has no MCP category at all**, unlike the Copilot and Cursor checks in
  this repository. Cascade's MCP configuration lives at
  `~/.codeium/windsurf/mcp_config.json`, a home-directory file. Nothing in
  Windsurf's documentation describes a project-level or repository-committed
  MCP config, so there is no repository surface here to measure, not a gap in
  what this check happens to cover.
- **It does not evaluate whether a rule is good.** It tells you one changed and
  who changed it. Judgement is the reviewer's.
- **It does not cover Windsurf's global rules or skills**, set outside the
  repository in a developer's own Windsurf settings, or the OS-level
  system/enterprise skill directories some Windsurf deployments read. Neither
  arrives by pull request.
- **It is not a sandbox.** It reports composition, it does not constrain
  execution.
- **It emits no signed record.** Same reasoning as Copilot: a repository cannot
  know which model a given Windsurf session used. See
  [agent-manifest#256](https://github.com/agentrust-io/agent-manifest/issues/256).

## Inputs

| Input | Default | Notes |
|---|---|---|
| `root` | `.` | Repository root to inspect |
| `comment` | `true` | One comment per pull request, edited in place rather than appended per push |
| `fail-on-drift` | `true` | Set `false` to report without blocking |
| `github-token` | `${{ github.token }}` | Only used to post the comment |

## Commands

```bash
python windsurf/engine/capture.py snapshot   # print the composition as JSON
python windsurf/engine/capture.py verify     # diff against the baseline, exit 1 on drift
python windsurf/engine/capture.py approve    # write the baseline
```

One dependency: [`agentrust-capture-core`](../packages/agentrust-capture-core),
which has none of its own. The action installs it before running the check.

## License

Apache-2.0.
