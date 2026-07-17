# AgenTrust for Codex

A Codex plugin that fingerprints the agent configuration in each workspace,
warns when that composition changes, and creates signed Agent Manifest and
TRACE Level 0 records on request.

## Install

You need a Codex release with plugin and hook support. Drift detection supports
Python 3.9 or newer. Signed-record generation requires Python 3.11 or newer.

```bash
codex plugin marketplace add agentrust-io/integrations
codex plugin add agentrust-codex@agentrust
```

Start a new Codex session after installation. Open `/hooks`, review the
AgenTrust SessionStart hook, and trust it. Codex skips plugin hooks until you
trust their current definition.

The first trusted session records a baseline for the current Git workspace.
Later sessions stay quiet when the fingerprints match. Drift produces a
warning that names each changed category.

## Use it

The plugin packages the `agentrust-codex:agent-integrity` skill. Ask Codex:

```text
Use $agentrust-codex:agent-integrity to verify this Codex agent.
```

```text
Use $agentrust-codex:agent-integrity to approve the current baseline.
```

```text
Use $agentrust-codex:agent-integrity to generate signed records in ./agentrust-records.
```

Approval replaces the workspace baseline. The skill requires an explicit
approval request and leaves unexpected drift unapproved.

Signed-record generation, invoked with Python 3.11 or newer, creates a pinned
Python environment under
`$CODEX_HOME/agentrust/signing-venv` when needed. The plugin installs released
versions of `agent-manifest`, `agentrust-trace`, and
`agentrust-trace-tests` in that environment.

## Fingerprinted composition

The engine hashes these local inputs:

- the active user and workspace `AGENTS.md` or `AGENTS.override.md` files,
  plus the Codex memory summary when present
- user, workspace, and enabled-plugin skill definitions
- Codex config, hooks, requirements, and rule files
- installed enabled plugins and configured MCP server names
- the active model and permission mode supplied by the SessionStart hook

Snapshots store logical names and SHA-256 hashes. They do not store raw prompt
text, config values, tool inputs, tool outputs, transcripts, auth data, or
environment secrets.

Each Git root gets its own baseline:

```text
$CODEX_HOME/agentrust/workspaces/<workspace-path-hash>/baseline.json
```

The plugin hashes the absolute Git-root path to select that directory but does
not store the path. It hashes the Codex session ID before storing it. It also
uses a pseudonymous hash for the local agent identity.

## Signed records

The report command writes:

- `manifest.json`, an Ed25519-signed Agent Manifest
- `trace.json`, a signed TRACE Level 0 session-context record
- `verification_key.json`, the public key for independent signature checks

The plugin keeps one manifest signing key at
`$CODEX_HOME/agentrust/signing_key.json`. It writes the key with owner-only
permissions where the operating system supports them. A corrupt key stops
signing so the plugin cannot replace an existing identity without notice.

Check TRACE conformance from a source checkout:

```bash
python3 -m venv .venv-agentrust-codex
.venv-agentrust-codex/bin/pip install -r plugins/agentrust-codex/requirements.txt
.venv-agentrust-codex/bin/python plugins/agentrust-codex/engine/capture.py \
  report --model gpt-test --out ./agentrust-records
.venv-agentrust-codex/bin/trace-tests verify \
  --record ./agentrust-records/trace.json --level 0
```

Use the real active model slug for a real record. The `gpt-test` value above
exists only to make a local smoke-test command reproducible.

## Limits

- TRACE Level 0 represents software integrity. It provides no TEE or
  hardware-attestation claim.
- The instruction fingerprint covers visible `AGENTS.md` layers and the
  local memory summary, not Codex's internal system prompt.
- A third party can verify the manifest signature with
  `verification_key.json`. Verifying each artifact binding requires runtime
  hashes measured outside the signed manifest.
- SessionStart exposes the model and permission mode but no complete built-in
  tool roster. The tool catalog covers configured MCP servers, installed
  enabled plugins, and any tools supplied through the engine's explicit CLI
  option.
- The engine fingerprints workspace `.codex` files it can see on disk. It
  cannot prove that Codex trusted and loaded each project layer.
- Codex may update the memory summary as you work. Such an update changes the
  instruction fingerprint and requires review or approval.

## Test

```bash
python3 -m pytest plugins/agentrust-codex/tests -q
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/agentrust-codex
```

The full test suite verifies workspace isolation, drift detection, hook failure
safety, corrupt-state handling, persistent signing identity, independent
manifest signature verification, tamper detection, and TRACE Level 0
conformance.

## Privacy

Read [PRIVACY.md](PRIVACY.md). The plugin processes configuration on the local
machine and sends no telemetry. The signing-environment bootstrap accesses PyPI
only after a signed-report request.

## License

Apache-2.0.
