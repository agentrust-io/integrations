---
description: Capture, verify, or approve the integrity baseline of your Claude Code agent
argument-hint: "[verify | approve | show]"
---

You are running the AgenTrust agent-integrity command. The engine is at
`${CLAUDE_PLUGIN_ROOT}/engine/capture.py`. It captures the agent's composition
(skills, tools, MCP servers, model, permissions, instruction layer) and diffs it
against the user's approved baseline at `~/.claude/agentrust/baseline.json`.

The shell hook cannot see the live tool roster, so YOU enrich it. Before running,
write the current session's real facts to a temp `live.json`:

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
  `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" verify --live-context live.json`
  and show the "nothing added, nothing subtracted" result. Explain any change in
  plain language and ask whether to approve it.
- `approve`: run `... approve --live-context live.json --sign --out .` to make the
  current composition the new approved baseline and write signed records.
- `show`: run `... snapshot --live-context live.json` to display the current
  composition without touching the baseline.

Report the result in plain English. Never claim hardware attestation: on a normal
dev box this is software-only (Level 0) integrity, not silicon-rooted proof.
