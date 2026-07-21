---
description: Check, approve, or show the integrity baseline of your Claude Code scheduled agents
argument-hint: "[verify | approve | show]"
---

You are running the AgenTrust scheduled-agent integrity command. It answers one
question: are the things that run WITHOUT the user watching -- their scheduled
routines and the hooks that auto-run on events -- the ones they approved, with
nothing added and nothing subtracted since their baseline?

The engine is at `${CLAUDE_PLUGIN_ROOT}/engine/capture.py`. It fingerprints:

- routine specs in `~/.claude/agentrust/routines/*.json` (override with
  `AGENTRUST_ROUTINES_DIR`): each routine's schedule, allowed tools, MCP servers,
  prompt, and model.
- the `hooks` block in `~/.claude/settings.json`: the commands that auto-run on
  SessionStart, PreToolUse, and other events.

It diffs the current surface against the approved baseline at
`~/.claude/agentrust/scheduled/baseline.json`. Everything is read from disk, so
no live session context is needed.

Dispatch on `$ARGUMENTS`:

- `verify` (default): run
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" verify`.
  Verify always re-reads the surface fresh, so it reflects any routine edited or
  hook widened since session start. Show the result and explain each change in
  plain language, then ask whether to approve it.
- `approve`: run
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" approve`. Use this when the
  user confirms the changes are intentional. Add `--sign --out .` to also write a
  signed TRACE record (needs `pip install -r "${CLAUDE_PLUGIN_ROOT}/requirements.txt"`).
- `show`: run
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" snapshot` to display the
  current surface without touching the baseline.

Report the result in plain English. Name what changed (a routine added, a tool
widened, a schedule moved, a new auto-run hook) and what the user should do about
each. Be honest about scope: this baselines the DECLARED routine specs and the
on-disk hooks, and detects drift in those declarations. It does not introspect a
live cloud routine's runtime behaviour, and on a normal dev box it is
software-only (Level 0) integrity, not hardware attestation.
