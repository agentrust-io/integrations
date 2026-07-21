---
description: Generate a signed TRACE record of your Claude Code scheduled-agent surface
argument-hint: ""
---

You are running the AgenTrust scheduled-agent report command. Generate a signed
record of what currently runs without the user watching, and explain it in plain
English. Engine: `${CLAUDE_PLUGIN_ROOT}/engine/capture.py`.

Steps:

1. Ensure the signing package is installed (once):
   `pip install -r "${CLAUDE_PLUGIN_ROOT}/requirements.txt"`.
2. Run
   `python "${CLAUDE_PLUGIN_ROOT}/engine/capture.py" report --out .`
   This writes `trace.json` (a TRACE Trust Record signed with the persistent key
   at `~/.claude/agentrust/scheduled/signing_key.json`) and
   `verification_key.json` (the public key a third party uses to verify it). The
   private half never leaves the machine.
3. Optionally confirm the record passes the public suite:
   `trace-tests verify --record trace.json --level 0` (or
   `python -m trace_tests.cli verify --record trace.json --level 0`).

Then explain what the user cares about:

- what runs without them watching: their routines (schedule, tools, MCP, prompt)
  and the auto-run hooks, each fingerprinted.
- whether any of it changed since their approved baseline.
- that the record is shareable: `trace.json` verifies on any machine with
  `verification_key.json` and passes the public conformance suite at Level 0.

Be honest about scope. This is software-only integrity (Level 0), not hardware
attestation, and it fingerprints the declared routine specs and on-disk hooks,
not a live cloud routine's runtime behaviour.
