# Changelog

All notable changes to the AgenTrust for Codex plugin.

## Unreleased

### Fixed
- **Tool names that share a slug no longer share a `tool_id`.** `foo` and `FOO`
  both became `codex.mcp.foo`, which the SDK refuses, so the manifest failed its
  own verification. Colliding ids now gain a short hash of the full name; every
  other id is unchanged.
- **A catalog no verifier would accept is refused instead of hashed.** The
  catalog root now refuses what the SDK's builder refuses: a repeated or
  NUL-carrying `tool_id`, a digest that is not sha256 hex, more than 1,000,000
  tools.
- **The TRACE record is signed with the persisted key published in
  `verification_key.json`, not a throwaway one.** Before, nobody could verify
  `trace.json` except against the key inside it, and the agent had a new TRACE
  identity every session. The Claude Code plugin fixed the same bug earlier.
- **The manifest's `tool_manifest.catalog_hash` no longer contradicts its own
  tool list.** It was a SHA-256 over the tool names, while agent-manifest spec
  3.2.3 defines it as the RFC 9162 Merkle root over the listed tools, which a
  verifier recomputes. Every manifest therefore verified as `MISMATCH`, and the
  tests checked only `signature_verified`, so it went unnoticed. The root now
  follows the spec and is checked against the SDK's own construction.
- **`verification_key.json` now names the issuer its key signs for.** A verifier
  needs that under agent-manifest spec 5.3.3, and agent-manifest 0.16 reports a
  manifest checked without it as `UNVERIFIABLE`.

### Breaking
- Drift detection now requires the separately published
  `agentrust-capture-core` package; the previous vendored fallback was removed.
  Existing installations must run `pip install agentrust-capture-core` before
  their next session. Codex plugin metadata cannot currently declare or install
  Python package dependencies.
