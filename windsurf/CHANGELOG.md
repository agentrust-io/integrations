# Changelog

All notable changes to the AgenTrust Windsurf drift check.

## Unreleased

### Added
- Initial release. Measures Windsurf rules (`.devin/rules/*.md` preferred,
  `.windsurf/rules/*.md` fallback, `.windsurfrules` legacy, all anywhere in
  the tree) and skills (`.windsurf/skills/`, `.agents/skills/`,
  `.claude/skills/`, repository root only). No MCP category: Cascade's MCP
  configuration is home-directory only, with no repository-resident
  equivalent documented anywhere. Both surfaces checked independently against
  current vendor documentation rather than assumed to have moved together
  through the Windsurf-to-Devin rebrand. See #78.
