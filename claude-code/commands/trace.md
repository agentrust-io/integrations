---
description: Generate a signed TRACE + Agent Manifest report for this Claude Code session
argument-hint: ""
---

You are running the AgenTrust report command. Generate a signed record of THIS
session and explain it in plain English. Engine:
`${CLAUDE_PLUGIN_ROOT}/engine/capture.py`.

Steps:

1. Ensure the packages are installed (once):
   `pip install agent-manifest agentrust-trace "agentrust-trace-tests>=0.2"`.
2. Write this session's real facts to `live.json` (do NOT invent values):
   `model_id`, `model_provider`, `model_version`, `builtin_tools` (your actual
   built-in tools), `mcp_servers` (the MCP servers actually connected now).
3. Run
   `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" report --live-context live.json --out .`
4. Optionally confirm the TRACE record passes the suite:
   `trace-tests verify --record trace.json --level 0` (or
   `python -m trace_tests.cli verify ...` if the script is not on PATH).

Then explain the report the user actually cares about:
- what the agent IS (skills, tools, MCP, model, permissions), each fingerprinted,
- what it DID this run (TRACE record, software-only / Level 0 on a dev box),
- whether anything changed since their approved baseline.

Be honest about scope: no TEE on a normal laptop means Level 0, not hardware
attestation. The "instruction layer" fingerprint covers CLAUDE.md and memory,
not Claude Code's internal system prompt (which is not on disk).
