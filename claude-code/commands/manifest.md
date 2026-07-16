---
description: Check, approve, or show the integrity baseline of your Claude Code agent
argument-hint: "[verify | approve | show]"
---

You are running the AgenTrust agent-integrity command. It answers one question
for the user: is the agent they are running the one they approved, with nothing
added and nothing subtracted since their baseline?

The engine is at `${CLAUDE_PLUGIN_ROOT}/engine/capture.py`. It captures the
agent's composition (skills, tools, MCP servers, model, permissions, instruction
layer) and diffs it against the approved baseline at
`~/.claude/agentrust/baseline.json`.

The shell hook cannot see the live tool roster, so YOU enrich it. Before running,
write the current session's real facts to a temp `live.json`. Use real values you
actually observe this session, never invented ones:

```json
{
  "model_id": "<the model you are running>",
  "model_provider": "anthropic",
  "model_version": "<version>",
  "builtin_tools": ["<your actual built-in tool names>"],
  "mcp_servers": ["<the MCP servers actually connected this session>"]
}
```

Then dispatch on `$ARGUMENTS`:

- `verify` (default): run
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" verify --live-context live.json`.
  Verify always re-reads the setup fresh and merges your `live.json`, so it
  reflects the agent's state right now, including drift introduced partway
  through this session. Show the result and explain any change in plain language,
  then ask whether to approve it.
- `approve`: run
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" approve --live-context live.json --sign --out .`
  to make the current composition the new approved baseline and write signed
  records. Use this when the user confirms the changes are intentional.
- `show`: run
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" snapshot --live-context live.json`
  to display the current composition without touching the baseline.

Report the result in plain English. Name the categories that changed (a skill, a
permission, an MCP server, the instruction layer) and what the user should do
about each. Never claim hardware attestation: on a normal dev box this is
software-only (Level 0) integrity, not silicon-rooted proof.
