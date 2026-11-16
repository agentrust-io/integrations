# Changelog

All notable changes to the AgenTrust for Codex plugin.

## Unreleased

### Fixed
- **`verification_key.json` now names the issuer its key signs for.** A verifier
  needs that under agent-manifest spec 5.3.3, and agent-manifest 0.16 reports a
  manifest checked without it as `UNVERIFIABLE`.

### Breaking
- Drift detection now requires the separately published
  `agentrust-capture-core` package; the previous vendored fallback was removed.
  Existing installations must run `pip install agentrust-capture-core` before
  their next session. Codex plugin metadata cannot currently declare or install
  Python package dependencies.
