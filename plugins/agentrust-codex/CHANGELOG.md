# Changelog

All notable changes to the AgenTrust for Codex plugin.

## Unreleased

### Breaking
- Drift detection now requires the separately published
  `agentrust-capture-core` package; the previous vendored fallback was removed.
  Existing installations must run `pip install agentrust-capture-core` before
  their next session. Codex plugin metadata cannot currently declare or install
  Python package dependencies.
