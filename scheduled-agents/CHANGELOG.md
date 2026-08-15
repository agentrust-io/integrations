# Changelog

All notable changes to the AgenTrust scheduled-agents plugin.

## Unreleased

### Breaking
- Drift detection now requires the separately published
  `agentrust-capture-core` package; the previous vendored fallback was removed.
  Existing installations must run `pip install agentrust-capture-core` before
  their next session. The Claude Code marketplace manifest cannot declare or
  install Python package dependencies.
