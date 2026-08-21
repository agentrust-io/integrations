# Changelog

All notable changes to the AgenTrust Cursor drift check.

## Unreleased

### Added
- Initial release. Measures Cursor rules (`.cursor/rules/**/*.mdc` including
  nested folders, `AGENTS.md` anywhere in the tree, `.cursorrules` legacy),
  skills (`.cursor/skills/`, `.agents/skills/`, `.claude/skills/`,
  `.codex/skills/`, anywhere in the tree, category subfolders included), and
  MCP configuration (`.cursor/mcp.json`), verified against cursor.com/docs
  (Customize > Rules, Customize > Skills, Customize > MCP) rather than
  assumed from a general path table. See #78.
