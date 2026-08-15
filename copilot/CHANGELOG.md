# Changelog

All notable changes to the AgenTrust Copilot drift check.

## Unreleased

### Added
- **This repository now runs the check on itself, enforcing.** `.agentrust/copilot-baseline.json`
  is committed and `copilot-integrity.yml` gates every pull request with
  `fail-on-drift: true`. The baseline is empty because this repository has none of
  the surfaces yet, so the first thing it can fire on is someone adding one, which
  is the event the check exists for.

### Fixed
- **The MCP path list was wrong.** It measured `copilot/mcp-config.json`, which no
  tool reads. The real Copilot CLI user config is `~/.copilot/mcp-config.json`, in
  the home directory, so the repository path was never a surface at all and the
  category was silently empty on every repository that had one. Removed in #116.

  Now measured, each confirmed against vendor documentation: `.mcp.json` and
  `.github/mcp.json` (Copilot CLI), `.vscode/mcp.json` (VS Code), and the three
  documented `devcontainer.json` locations, which carry MCP servers under
  `customizations.vscode.mcp`.

  `MEASUREMENT_SCOPE` moves to 2. An existing baseline gets one "re-approve once"
  notice and its MCP category is not compared that run, so a path that was always
  present is not reported as a server someone just added.

### Breaking
- Drift detection now requires the separately published
  `agentrust-capture-core` package; the previous vendored fallback was removed.
  Existing installations and workflows must run
  `pip install agentrust-capture-core` before invoking the check. GitHub Actions
  workflow metadata does not install Python package dependencies automatically.
