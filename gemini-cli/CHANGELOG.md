# Changelog

All notable changes to the AgenTrust Gemini CLI drift check.

## Unreleased

### Added
- Initial release. Measures Gemini CLI context files (`GEMINI.md`, anywhere in
  the tree), skills (`.gemini/skills/`, `.agents/skills/`, repository root
  only), and MCP configuration (`.gemini/settings.json`, digested whole).
  `context.fileName` renaming and the home-directory equivalents are
  deliberately out of scope; see README.md for why. See #78.
