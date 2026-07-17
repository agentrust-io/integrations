---
name: agent-integrity
description: Verify or approve a workspace-scoped Codex agent baseline, inspect configuration drift, or generate signed Agent Manifest and TRACE Level 0 session records.
---

# AgenTrust agent integrity

Use the capture engine shipped with this plugin. Resolve
`../../engine/capture.py` from this SKILL.md to an absolute path before
running it. Resolve `../../scripts/signing-python.py` the same way.

The engine stores only names and hashes. Do not inspect `auth.json`, transcript
files, tool inputs, tool outputs, environment secrets, or raw configuration
values for this workflow.

## Select the operation

- Verify is the default. Run it when the user asks whether the Codex agent
  changed, requests an integrity check, or names no operation.
- Snapshot shows the current fingerprints without comparing or changing the
  baseline.
- Approve replaces the baseline. Run it only when the user asked to establish,
  accept, approve, or rebaseline the current composition. A verification result
  alone does not authorize approval.
- Report creates signed Agent Manifest and TRACE records. The report does not
  alter the approved baseline.

Use the current working directory as the workspace unless the user names
another one. The engine scopes baselines by a hash of the Git root, so checks in
different repositories do not overwrite each other.

## Run the engine

Use `python3` on macOS or Linux and `py -3` on Windows.

Verify:

```text
python3 <engine-path> verify --cwd <workspace>
```

Snapshot:

```text
python3 <engine-path> snapshot --cwd <workspace>
```

Approve after explicit user authorization:

```text
python3 <engine-path> approve --cwd <workspace>
```

For a signed report, run the signing environment bootstrap with Python 3.11 or
newer. It creates a venv under `$CODEX_HOME/agentrust/signing-venv` and installs
the exact released versions from this plugin's `requirements.txt`. This is the
only step in the workflow that accesses PyPI.

```text
python3 <signing-bootstrap-path>
<printed-python-path> <engine-path> report --cwd <workspace> --out <output-directory>
```

If the SessionStart hook did not capture the active model, add
`--model <active-model-slug>` only when the model slug is present in the
current Codex session. Never guess it.

## Interpret results

Name each added, removed, or changed instruction, skill, plugin, policy file,
policy setting, MCP server, model, or permission mode. Tell the user whether
the change matches their stated intent.

Never approve unexpected drift. Leave the existing baseline intact and point
to the changed category.

For signed output, report these checks:

- `manifest.json` carries an Ed25519 signature and
  `verification_key.json` contains the public verification key. State that
  this verifies signature integrity. Artifact-binding verification needs
  separately measured runtime hashes.
- `trace.json` is a TRACE Level 0 software-integrity record. Level 0 does not
  claim a TEE, hardware attestation, or a complete action log.

The engine fingerprints the on-disk instruction and policy layers it can see.
It does not prove that Codex loaded each project file, expose Codex's internal
system prompt, or enumerate every built-in tool from a SessionStart hook.
