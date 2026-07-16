---
description: Generate a signed TRACE + Agent Manifest report for this Claude Code session
argument-hint: ""
---

You are running the AgenTrust report command. Generate a signed record of THIS
session and explain it in plain English. Engine:
`${CLAUDE_PLUGIN_ROOT}/engine/capture.py`.

Steps:

1. Ensure the signing packages are installed (once). Prefer the pinned set:
   `pip install -r "${CLAUDE_PLUGIN_ROOT}/requirements.txt"`.
2. Write this session's real facts to `live.json`. Use values you actually
   observe, never invented ones: `model_id`, `model_provider`, `model_version`,
   `builtin_tools` (your actual built-in tools), `mcp_servers` (the MCP servers
   actually connected now).
3. Run
   `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" report --live-context live.json --out .`
   This writes `manifest.json`, `trace.json`, and `verification_key.json` (the
   public key a third party uses to verify the manifest). The manifest is signed
   with the persistent key at `~/.claude/agentrust/signing_key.json`; the private
   half never leaves the machine.
4. Optionally confirm the TRACE record passes the suite:
   `trace-tests verify --record trace.json --level 0` (or
   `python -m trace_tests.cli verify --record trace.json --level 0` if the
   console script is not on PATH).

Then explain the report the user actually cares about:

- what the agent IS: skills, tools, MCP, model, permissions, each fingerprinted.
- what it DID this run: the TRACE record, software-only and Level 0 on a dev box.
- whether anything changed since their approved baseline.
- that the records are shareable: `manifest.json` verifies on any machine with
  `verification_key.json`, and `trace.json` passes the public conformance suite.

Be honest about scope. No TEE on a normal laptop means Level 0, not hardware
attestation. The instruction-layer fingerprint covers `CLAUDE.md` and memory, not
Claude Code's internal system prompt, which is not on disk.
