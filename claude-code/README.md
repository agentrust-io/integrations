# AgenTrust for Claude Code

Agent-integrity for the coding agent you already use. This plugin captures, every
session:

- an **Agent Manifest** — what your Claude agent *is*: skills, tools, MCP servers,
  model, permission policy, and instruction layer, each fingerprinted and signed
  ([agent-manifest](https://github.com/agentrust-io/agent-manifest)).
- a **TRACE Trust Record** — what your agent *did* this run, signed and
  conformance-checkable ([trace](https://github.com/agentrust-io/trace-spec)).

and answers the one question that matters on a developer box:

> **Is the agent I'm running the one I approved — nothing added, nothing subtracted?**

A rogue skill dropped into `~/.claude/skills`, a widened permission, an edited
`CLAUDE.md`, or an unexpected MCP server all change a fingerprint, and the next
SessionStart tells you.

## What it does

| Surface | What runs | Needs crypto packages? |
|---|---|---|
| **SessionStart hook** | snapshot the agent from disk, diff against your approved baseline, warn in-session on drift | No (stdlib only) |
| `/manifest verify` | full diff including the live tool/MCP roster the agent reports | No |
| `/manifest approve` | make the current composition the approved baseline | No (add `--sign` for records) |
| `/trace` | build + sign the Agent Manifest and TRACE record, explain them in plain English | Yes |

The hook is deliberately dependency-free so it never blocks session start. Signing
runs only when you ask for records.

## Install

```bash
# 1. plugin (hooks + commands)
/plugin marketplace add agentrust-io/integrations
/plugin install agentrust-claude-code

# 2. only for signed records (/trace, /manifest approve --sign)
pip install -r claude-code/requirements.txt
```

First SessionStart establishes your baseline at `~/.claude/agentrust/baseline.json`.
Every later session is checked against it. Run `/manifest approve` whenever you
intentionally change your setup.

## What it captures (and what it does not)

Captured, by fingerprint — never raw content, never secrets:

- **skills** — each `~/.claude/skills/*/SKILL.md`
- **permissions** — `~/.claude/settings.json` (the allow/deny policy)
- **instruction layer** — your `CLAUDE.md` / memory tree
- **tools + MCP servers** — the roster the agent reports at report time
- **model** — provider, id, version

It never reads `~/.claude/.credentials.json`, and records skill / tool / MCP
**names** only, never tokens or environment values.

## Known gaps (read before relying on it)

- **Software-only, Level 0.** A normal dev box has no TEE, so the TRACE record is
  software-only integrity, not hardware-rooted attestation. Labelled as such.
- **Instruction layer is a proxy.** The `system_prompt` fingerprint covers your
  `CLAUDE.md` and memory, not Claude Code's internal system prompt, which is not
  on disk.
- **`policy_language` mismatch.** agent-manifest's `policy_language` enum
  (`cedar`/`rego`/`yaml-agt`/`composite`) has no value for host-native agent
  permission systems like Claude Code's `settings.json`. Modelled as `composite`;
  a spec value for host-native permissions is proposed upstream.
- **Hook visibility.** A shell hook cannot enumerate the live tool roster, so the
  SessionStart check compares skills, permissions, and the instruction layer.
  The full tool/MCP diff runs in `/manifest verify`, where the agent supplies the
  live roster.

## Layout

```
claude-code/
  .claude-plugin/plugin.json   plugin manifest
  hooks/hooks.json             SessionStart -> engine/capture.py hook
  commands/manifest.md         /manifest capture | verify | approve
  commands/trace.md            /trace report
  engine/capture.py            capture engine (stdlib hook + signing report)
  tests/test_capture.py        stdlib-only tests
  integration.yaml             agentrust-io integration manifest
  requirements.txt             crypto deps for signing only
```
