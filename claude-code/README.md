# AgenTrust for Claude Code

**Know your coding agent hasn't changed behind your back.**

Claude Code is not just a model. It is a model plus everything you have wired
around it: skills in `~/.claude/skills`, an allow/deny permission policy, MCP
servers, your `CLAUDE.md` and memory, and the tools it can call. That whole
composition decides what your agent can do to your machine and your code. Any of
it can change without you noticing.

This plugin answers one question at the start of every session:

> **Is the agent I'm running the one I approved: nothing added, nothing subtracted?**

## Why this matters

You approved a setup you trust. Then, quietly, things drift:

- A skill you installed ships an update that now runs `curl` to an address you
  never saw.
- A dependency's postinstall drops a `SKILL.md` into `~/.claude/skills`.
- A permission gets widened from `Bash(git:*)` to `Bash(*)` during some debugging
  session and never gets narrowed back.
- An MCP server you added for one task is still connected weeks later.
- Your `CLAUDE.md` picks up an instruction you didn't write.

None of these announce themselves. Each one changes what your agent will do on
your next run. This plugin fingerprints the whole composition, stores an approved
baseline, and tells you at session start the moment any of it moves. It is the
difference between "I think my agent is what I set up" and "I can prove it, and
I'd know within one session if it wasn't."

## Quickstart (about 60 seconds)

```bash
# 1. add the marketplace and install the plugin (hooks + commands)
/plugin marketplace add agentrust-io/integrations
/plugin install agentrust-claude-code
```

That's the whole install for drift detection. The SessionStart hook is
dependency-free (Python standard library only), so it never blocks a session.

On your **first** session after install, it records your baseline and tells you:

```
AgenTrust: baseline established for this Claude agent (7 skills, 2 MCP on disk).
Future sessions are checked against it. Run /manifest approve to re-baseline.
```

The baseline lives at `~/.claude/agentrust/baseline.json`. From then on, every
session is checked against it.

Signed records (`/trace` and `/manifest approve --sign`) are the only feature
that needs crypto packages. Install them when you want them:

```bash
pip install -r claude-code/requirements.txt
```

## The everyday loop

You mostly do nothing. You install it, and it stays quiet until something
changes. When it does, one line shows up at session start:

```
AgenTrust WARNING: 1 change(s) to your agent since baseline: added skill
pypi-helper. Run /manifest verify for detail, or /manifest approve to accept.
```

Two responses, both one command:

**If the change is a surprise**, look at it. `/manifest verify` re-reads your
setup right now and lays out exactly what moved:

```
  NOTHING ADDED, NOTHING SUBTRACTED?  (vs approved baseline)
  --------------------------------------------------------------
  ~ CHANGED permissions: policy_bundle
  + ADDED skill: exfil
  >> 2 change(s) since baseline. Review above.
```

Now you decide with the facts in front of you: remove the rogue skill, narrow the
permission, or accept it.

**If you made the change on purpose** (installed a skill you wanted, added an MCP
server for real work), tell the plugin this is the new normal:

```
/manifest approve
```

That promotes your current setup to the approved baseline. The warnings stop
until something moves again.

## Commands

| Command | What it does | Needs crypto packages? |
|---|---|---|
| SessionStart hook | Snapshot the agent from disk, diff against your approved baseline, warn in-session on drift | No |
| `/manifest verify` | Re-snapshot now and show the full diff, including the live tool and MCP roster the agent reports this session | No |
| `/manifest approve` | Make the current composition the approved baseline | No (add `--sign` for records) |
| `/manifest show` | Show the current composition without touching the baseline | No |
| `/trace` | Build and sign the Agent Manifest and TRACE record for this session, explained in plain English | Yes |

`/manifest verify` always re-reads your setup fresh, so it catches drift that
happens partway through a session, not just at startup.

## What it captures, and what it does not

It records **fingerprints, never raw content, never secrets:**

- **skills**: each `~/.claude/skills/*/SKILL.md`
- **permissions**: `~/.claude/settings.json` (the allow/deny policy)
- **instruction layer**: your `CLAUDE.md` and memory tree
- **tools and MCP servers**: the roster the agent reports, by name only
- **model**: provider, id, version

It never reads `~/.claude/.credentials.json`. It records skill, tool, and MCP
**names** only, never tokens, never environment values, never file contents.
A changed fingerprint tells you *that* something changed and *which category*,
which is what you need to go look.

## Signed records: Agent Manifest and TRACE

When you run `/trace` (or `/manifest approve --sign`), the plugin writes two
signed JSON records:

- an **Agent Manifest**: what your agent *is*, the full composition above, each
  part fingerprinted and Ed25519-signed
  ([agent-manifest](https://github.com/agentrust-io/agent-manifest)).
- a **TRACE Trust Record**: what your agent *did* this run, signed and checkable
  against the public conformance suite
  ([trace-spec](https://github.com/agentrust-io/trace-spec)).

These are shareable proof a third party can verify without trusting your machine.
Confirm a record with:

```bash
trace-tests verify --record trace.json --level 0
# or, if the console script is not on PATH:
python -m trace_tests.cli verify --record trace.json --level 0
```

## Known limits (read before relying on it)

This plugin is honest about what it is. On a normal developer machine:

- **Software-only, Level 0.** A dev box has no hardware TEE, so the TRACE record
  is software integrity, not silicon-rooted attestation. It is labelled Level 0,
  never presented as hardware-attested.
- **The instruction layer is a proxy.** The `system_prompt` fingerprint covers
  your `CLAUDE.md` and memory tree, not Claude Code's internal system prompt,
  which is not on disk.
- **`policy_language` is modelled as `composite`.** The agent-manifest
  `policy_language` enum (`cedar` / `rego` / `yaml-agt` / `composite`) has no
  value for host-native permission systems like Claude Code's `settings.json`.
  A spec value for host-native permissions is proposed upstream.
- **The hook sees disk, commands see the session.** A shell hook cannot enumerate
  the live tool roster, so the SessionStart check compares skills, permissions,
  and the instruction layer. The full tool and MCP diff runs in `/manifest
  verify`, where the agent supplies the live roster.

## Layout

```
claude-code/
  .claude-plugin/plugin.json   plugin manifest
  hooks/hooks.json             SessionStart -> engine/capture.py hook
  commands/manifest.md         /manifest verify | approve | show
  commands/trace.md            /trace report
  engine/capture.py            capture engine (stdlib hook + signing report)
  tests/test_capture.py        stdlib-only tests
  integration.yaml             agentrust-io integration manifest
  requirements.txt             crypto deps for signing only
```

## License

Apache-2.0. Part of the [agentrust-io](https://github.com/agentrust-io)
open agent-governance toolchain.
