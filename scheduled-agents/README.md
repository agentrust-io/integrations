# AgenTrust for Claude Code scheduled agents

A coding-agent session is something you drive. You see every tool call and
approve it. A **scheduled agent** is not. It runs on a cron, headless, and keeps
running long after you set it up.

"Set it and forget it" assumes the agent's behaviour next week is the agent's
behaviour today. It rarely is. The routine's allowed tools get widened during a
debug session and never narrowed back. Its schedule changes. A new hook drops
into `settings.json` and now a command runs on every session start. None of it
announces itself.

This plugin fingerprints the things that run **without you watching** and warns
you the moment any of them drifts from a baseline you approved:

- **routines** — declared scheduled-agent specs: schedule, allowed tools, MCP
  servers, prompt, model.
- **hooks** — the commands in `~/.claude/settings.json` that auto-run on events
  (`SessionStart`, `PreToolUse`, …).

## Install

```
# from this directory, or point Claude Code at the marketplace.json at the repo root
/plugin install agentrust-scheduled-agents
```

The `SessionStart` hook is dependency-free (Python standard library only), so it
never blocks a session. On first run it records a baseline. After that it stays
quiet until something moves, then prints one line:

```
AgenTrust WARNING: 2 change(s) to what runs without you watching since baseline:
added routine tool babysit-prs: Bash(curl:*); changed routine schedule babysit-prs: */30 * * * * -> * * * * *.
Run /schedule-manifest verify for detail, or /schedule-manifest approve to accept.
```

Then:

- `/schedule-manifest verify` — show exactly what changed, in plain English.
- `/schedule-manifest approve` — accept the current surface as the new baseline.
- `/schedule-manifest show` — display the surface without touching the baseline.
- `/schedule-trace` — write a signed, third-party-verifiable TRACE record.

## Declaring a routine

Claude Code does not expose its cloud routines on disk, so you **declare** each
scheduled agent's approved shape as a spec file. Drop one JSON file per routine
into `~/.claude/agentrust/routines/` (or set `AGENTRUST_ROUTINES_DIR`). A copy of
[`routines/babysit-prs.example.json`](routines/babysit-prs.example.json) to start
from:

```json
{
  "name": "babysit-prs",
  "schedule": "*/30 * * * *",
  "prompt": "Check my open PRs and fix failing CI. Do not merge.",
  "allowed_tools": ["Bash(gh:*)", "Read", "Grep", "Edit"],
  "mcp_servers": ["github"],
  "model": "claude-opus-4-8"
}
```

`prompt_file` (a path, absolute or relative to the routines dir) may be used
instead of an inline `prompt`. Commit these specs to version control: the
approved file is the source of truth, and drift is any later change to it.

## What it records, and what it does not

It records **names and fingerprints only** — routine, tool, MCP, and hook-command
names, and SHA-256 hashes of prompts and settings. It never stores secrets, never
reads your credentials file, and never records a hook command's output.

## Honest scope

- This baselines the **declared** routine specs and the **on-disk** hooks, and
  detects drift in those declarations. It does not introspect a live cloud
  routine's runtime behaviour — no software running on a normal dev box can prove
  that.
- On a normal dev box this is **software integrity, Level 0**, never presented as
  hardware-attested. `/schedule-trace` records `runtime.platform: software-only`
  and `slsa_level: 0` accordingly.
- v1 reads the **global** `~/.claude/settings.json` hooks block. Project-scoped
  hooks are on the roadmap.

## Verifying a TRACE record elsewhere

`trace.json` is signed with a persistent Ed25519 key; its public half is written
to `verification_key.json`. Anyone can verify it without trusting your machine:

```python
import json, agentrust_trace
rec = json.load(open("trace.json"))
vk = json.load(open("verification_key.json"))
agentrust_trace.verify_record(rec, vk["jwk"])  # raises if invalid
```

or against the public conformance suite:

```
trace-tests verify --record trace.json --level 0
```

## Tests

```
python -m pytest tests -q
```

The drift-detection tests use the standard library alone. The signing tests skip
cleanly when `agentrust-trace` is not installed.

## License

Apache-2.0.
