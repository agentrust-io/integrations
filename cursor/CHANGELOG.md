# Changelog

All notable changes to the AgenTrust Cursor drift check.

## Unreleased

### Added
- Initial release. Measures Cursor rules (`.cursorrules`, one level of
  `.cursor/rules/*.mdc`), skills (`.cursor/skills/`, `.agents/skills/`,
  `.claude/skills/`, `.codex/skills/`, anywhere in the tree), and MCP
  configuration (`.cursor/mcp.json`), each verified against Cursor's
  documentation and community forum rather than assumed from a general
  path table. See #78.
