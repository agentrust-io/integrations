# Changelog

All notable changes to the AgenTrust Copilot drift check.

## Unreleased

### Breaking
- Drift detection now requires the separately published
  `agentrust-capture-core` package; the previous vendored fallback was removed.
  Existing installations and workflows must run
  `pip install agentrust-capture-core` before invoking the check. GitHub Actions
  workflow metadata does not install Python package dependencies automatically.
