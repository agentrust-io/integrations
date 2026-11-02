# Provenza Agent Manifest issuer

[Provenza](https://github.com/kironovlaziz-del/provenza) is a self-hosted AI and agent governance server. It issues an Agent Manifest (specification v0.2) for every agent it governs, and this directory verifies such a manifest offline with the released `agent-manifest` SDK.

## What it does

Provenza builds the manifest from what it governs, signs it with the organization's audit key, and hands it out on the agent's page (**Agent Manifest**) or at `GET /api/v1/agents/{id}/manifest` (JSON: the payload, the COSE envelope, the signing keys) and `GET /api/v1/agents/{id}/manifest.cose`.

| Manifest field | What Provenza binds |
|---|---|
| envelope | `COSE_Sign` with two signers, Ed25519 and ML-DSA-65 (hybrid), `crypto_profile: standard` |
| `profile` | `composition-only`: Provenza is the policy gate, not the agent |
| `agent_id` | the SPIFFE ID the agent attested with, else `spiffe://<server>/org/<org>/agent/<id>` |
| `issuer` | `spiffe://<server>/org/<org>/provenza` |
| `artifacts.tool_manifest` | the approved MCP tools Provenza serves the agent: per tool, the hash of `{input_schema, output_schema}` and of the description (RFC 8785, as cMCP projects its catalog), and the Merkle `catalog_hash`. `rug_pull_policy: require-reapproval` (a definition changed upstream is withheld until re-approved), `allow_dynamic_registration: false` |
| `artifacts.decision_trace` | `merkle-log`: the root of the organization's latest signed audit checkpoint, its size and window, the checkpoint key's fingerprint |
| `hitl_record.required` | `true` when the agent's policies hold actions for a person's approval |
| `previous_manifest_id` | the manifest it replaces; a new one is issued when the tools, the approval requirement or the signing key change, or near expiry (90 days) |

## What it does not claim

- **Not a complete manifest.** System prompt, model identity, RAG corpus, memory, supply chain and delegation chain are declared in `unbound_artifacts`: Provenza does not observe them. The SDK's verdict is `INCOMPLETE`, never `VALID`.
- **No policy bundle.** The specification names Cedar, Rego and AGT YAML; Provenza's policy format is none of them, so `policy_bundle` stays unbound.
- **A partial tool catalog is never bound.** When an agent is registered for tools that Provenza does not serve as approved MCP tools, `tool_manifest` is unbound rather than listing only some tools.
- **No hardware attestation, no transparency log.** The keys are software keys held by the Provenza server (`audit_key_sealed: false`); no `attestation` block, no `transparency_log_entry`. Conformance levels do not apply to a composition-only manifest.
- **No HITL approvals attached.** Provenza signs approvals per held action; the manifest states only whether approvals are required.

## Usage

```bash
pip install agent-manifest==0.15.0
python src/verify_provenza_manifest.py agent-7-manifest.cose --ed25519 <base64> --ml-dsa <base64>
```

`--ed25519` and `--ml-dsa` are the organization's audit public keys as Provenza lists them (`GET /api/v1/audit/keys`, standard base64); `--keys` takes a `{kid hex: base64url key}` JSON instead, as `GET /api/v1/agents/{id}/manifest` returns it. Obtain the keys from a source you trust independently of the manifest file. The `manifest verify` CLI of agent-manifest 0.15.0 takes a single Ed25519 key, so it cannot check both signers of a hybrid envelope; the script calls the SDK directly.

The script checks both COSE signatures (`verify_cose_manifest`), recomputes the tool catalog root (`build_catalog_tree`) and prints the verification engine's verdict (`verify_manifest`). It exits 0 when the signatures verify and the verdict is `VALID` or `INCOMPLETE`.

## Reproduction

```bash
python -m venv .venv && . .venv/bin/activate
pip install agent-manifest==0.15.0 pytest
python src/verify_provenza_manifest.py tests/agent-1-manifest.cose --keys tests/trusted_keys.json
python -m pytest tests -q
```

`tests/agent-1-manifest.cose` was issued by Provenza for an agent with one approved MCP tool (`files.read`); `tests/trusted_keys.json` holds the two public keys that signed it. Expected output: `signatures_verified: true`, `signers: 2`, `catalog_hash_matches: true`, `verdict: INCOMPLETE` (`EXPIRED` after 2027-01-31). The tests also show that a changed payload and an unknown key fail.

To issue one yourself: install Provenza ([self-hosting guide](https://github.com/kironovlaziz-del/provenza/blob/main/docs/self-hosting.md)), register an agent, approve an MCP server's tool for it, and press **Agent Manifest** on the agent's page.

## Source and licence

Provenza and this directory are Apache-2.0. The issuer is `backend/app/services/agent_manifest.py` in the Provenza repository.
