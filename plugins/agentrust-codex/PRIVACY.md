# Privacy

The AgenTrust for Codex plugin processes agent configuration on your machine.
It sends no telemetry, analytics, snapshots, baselines, signing keys, or
records to agentrust-io.

## Files it processes

The plugin reads selected Codex configuration and instruction files to compute
SHA-256 hashes:

- `AGENTS.md`, `AGENTS.override.md`, and the Codex memory summary
- skill definitions, plugin manifests, plugin hooks, and plugin scripts
- `config.toml`, `hooks.json`, `requirements.toml`, and rule files

It parses config files only to extract plugin names, MCP server names, approval
policy, sandbox mode, and enabled state. It does not store raw file contents or
other config values.

The SessionStart hook supplies the active model, permission mode, workspace,
and session ID. The plugin stores a hash of the workspace path and session ID.
It derives a pseudonymous local agent identifier from a hash of the username
and hostname.

The plugin does not open Codex `auth.json`, transcript files, tool inputs,
tool outputs, or environment secrets.

## Local data

The plugin writes baselines, latest snapshots, and its signing key below
`$CODEX_HOME/agentrust`, which defaults to `~/.codex/agentrust`. It requests
owner-only permissions for private state and signed report files. Signed
reports go to the output directory you choose.

The plugin makes no network request during SessionStart, snapshot, verify, or
approve. A signed-report request can run the included bootstrap, which installs
the exact released packages in `requirements.txt` from PyPI into a dedicated
local virtual environment.

Removing the plugin does not delete `$CODEX_HOME/agentrust`. This preserves
your baseline and signing identity if you reinstall it. You control removal of
that local state.

Questions and corrections:
https://github.com/agentrust-io/integrations/issues
