# Changelog

All notable changes to the AgenTrust for Claude Code plugin.

## 0.2.0

First launch-ready release. Since 0.1.0 the plugin can actually be installed, the
SessionStart hook is hardened against real-world config, and signed records are
independently verifiable.

### Added
- **Persistent signing key.** The Agent Manifest is signed with one Ed25519 key
  kept at `~/.claude/agentrust/signing_key.json` (generated once, reused every
  run, private half never leaves the machine), so every record carries the same
  identity.
- **Published verification key.** Each `/trace` run writes `verification_key.json`
  (`{key_id, public_key_b64url}`) so a third party can verify `manifest.json` on
  another machine. The manifest is now genuinely tamper-evident: any change to a
  signed field fails verification.
- Repo-root `.claude-plugin/marketplace.json` so
  `/plugin marketplace add agentrust-io/integrations` and
  `/plugin install agentrust-claude-code` work.
- CI runs the plugin test suite: a stdlib-only job (proving the hook needs no
  crypto packages) and a signing job across Python 3.11 / 3.12 / 3.13.

### Fixed
- **`/manifest verify` missed mid-session drift.** It reused a cached snapshot
  instead of re-reading the agent, so a skill dropped in or a permission widened
  after session start was reported as unchanged. It now always re-snapshots.
- **SessionStart hook could crash the session.** Malformed `settings.json`, a
  non-dict `permissions` block, a misshaped `~/.claude.json`, a `skills` path
  that is a file, and a corrupted `baseline.json` all threw an uncaught
  traceback. Each now degrades gracefully; a corrupt baseline self-heals on the
  next run. The hook always emits valid SessionStart output and exits 0.
- Missing crypto packages now print a `pip install -r requirements.txt` hint
  instead of a raw `ModuleNotFoundError`.

### Changed
- Docs lead with why agent-composition drift matters, a 60-second quickstart, and
  the everyday warning to verify to approve loop.
- Tested and required dependency floors moved to the 0.3.0 line
  (`agent-manifest`, `agentrust-trace`).

## 0.1.0

Initial release: per-session Agent Manifest + TRACE record, SessionStart drift
check against an approved baseline, `/manifest` and `/trace` commands.
