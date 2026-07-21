# Privacy

The AgenTrust scheduled-agents plugin collects and transmits no personal data.

It runs locally as a Claude Code plugin. It processes only your local routine specs and Claude configuration, entirely on your machine, and sends no telemetry, analytics, or usage data to agentrust-io, OPAQUE, or any third party. There is no account, login, or tracking, and no cookies or background network calls.

It records names and fingerprints only (routine, tool, MCP, and hook-command names, and SHA-256 hashes of prompts and settings). It never stores secrets, never reads your credentials file, and never records a hook command's output. The drift baseline and any TRACE record are written to files on your machine; nothing is sent anywhere. Signing uses a local key whose private half never leaves the machine.

Uninstalling removes it completely. Questions or corrections: https://github.com/agentrust-io/integrations/issues
