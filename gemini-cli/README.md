# AgenTrust for Gemini CLI

**Review changes to your coding agent the way you review changes to your code.**

Gemini CLI is not just a model. In this repository it is a model plus the
context you gave it, the skills you gave it, and the MCP servers you
connected. Those files decide what the agent will do to your codebase, and
every one of them arrives by pull request.

So this integration is not a local warning. It is a status check, the same
shape [#68](https://github.com/agentrust-io/integrations/issues/68)
established for Copilot:

> **Does this pull request change what Gemini CLI reads, without saying so?**

## Quickstart

```yaml
# .github/workflows/gemini-cli-integrity.yml
name: Gemini CLI integrity
on: pull_request

permissions:
  contents: read
  pull-requests: write   # only needed for the comment

jobs:
  integrity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: agentrust-io/integrations/gemini-cli@main
```

Then create the baseline and commit it:

```bash
python gemini-cli/engine/capture.py approve
git add .agentrust/gemini-cli-baseline.json
```

Adopting this on a busy repository? Start with `fail-on-drift: false`. You get the
comment and the summary without blocking anyone, and you can flip it on once the
baseline is settled.

## What it measures

Verified against Gemini CLI's own documentation.

| Category | Paths |
|---|---|
| Context | `GEMINI.md` (**anywhere in the tree**) |
| Skills | `.gemini/skills/<name>/`, `.agents/skills/<name>/` (repository root only) |
| MCP | `.gemini/settings.json` (whole file) |

**`GEMINI.md` is matched anywhere**, because Gemini CLI's own docs describe a
hierarchy: the working directory and its parents up to the project root, plus
subdirectories below it. A file added three directories down changes how the
agent behaves in that subtree without touching anything at the root, and that
is exactly the change worth catching. Vendored directories (`node_modules`,
`vendor`, `.venv` and friends) are skipped, so a dependency shipping its own
`GEMINI.md` is not counted as yours.

**Skills stay fixed at the repository root**, the opposite choice from
`GEMINI.md`. Gemini CLI's docs describe workspace skills as living within the
current directory, with no equivalent to Cursor's documented
monorepo-anywhere skill roots, so matching below the root here would not
reflect anything Gemini CLI actually does.

**`.gemini/settings.json` is digested whole**, not parsed for the one
`mcpServers` key that matters. The same file carries unrelated settings,
including the `context.fileName` override mentioned below, and a parser that
mishandles the file would quietly report nothing changed about a file it
failed to read. So an unrelated settings edit shows up as MCP-adjacent drift.
That is a false positive a reviewer resolves by reading the diff, the same
tradeoff Copilot's engine makes for `devcontainer.json`, and the direction
worth being wrong in.

## What it does not do

- **It does not follow `context.fileName`.** Gemini CLI's `settings.json` can
  rename the file it looks for away from `GEMINI.md`. Detecting an arbitrary
  configured name would mean parsing `settings.json` first to know what to
  even look for, real complexity for what is, today, a rarely used override.
  This measures the documented default name and says so, rather than silently
  covering less than a green check implies.
- **It does not measure `~/.gemini/GEMINI.md` or `~/.gemini/settings.json`.**
  Both are home-directory files, configured per developer, and neither ever
  arrives by pull request. A check that implied otherwise would be worse than
  one that says nothing, the same reasoning Copilot's README gives for
  `~/.copilot/mcp-config.json`.
- **It does not evaluate whether a context file is good.** It tells you one
  changed and who changed it. Judgement is the reviewer's.
- **It is not a sandbox.** It reports composition, it does not constrain
  execution.
- **It emits no signed record.** Same reasoning as Copilot: a repository
  cannot know which model backs a given Gemini CLI session, since that is a
  session-time choice, not fixed by anything in the repository. See
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
python gemini-cli/engine/capture.py snapshot   # print the composition as JSON
python gemini-cli/engine/capture.py verify     # diff against the baseline, exit 1 on drift
python gemini-cli/engine/capture.py approve    # write the baseline
```

One dependency: [`agentrust-capture-core`](../packages/agentrust-capture-core),
which has none of its own. The action installs it before running the check.

## License

Apache-2.0.
