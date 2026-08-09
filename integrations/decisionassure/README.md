# DecisionAssure → TRACE

Converts a [DecisionAssure](https://github.com/a1k7/DecisionAssure-Runtime-Governance) runtime governance trace into a TRACE v0.2 Trust Record.

## What the record claims, and what it does not

DecisionAssure is a software governance engine. It attests nothing in hardware, and the record says so in fields a consumer can key on rather than in prose:

| Field | Value |
|---|---|
| `origin.kind` | `third-party-control-plane` |
| `origin.producer` | `decisionassure/1.2` |
| `runtime.platform` | `software-only` |
| `appraisal.status` | `none` |

**The engine's own ALLOW/DENY is not mapped to `appraisal.status`.** That field records whether anybody appraised the *evidence*, and a control plane reporting its own decision has not. The decision is part of the execution being described, so it travels hashed in `tool_transcript` with the rest of the trace instead of being promoted to a verdict.

## Run it

```bash
pip install agentrust-trace-adapters

python da_to_trace.py trace.json \
  --subject spiffe://example.org/agent/da-1 \
  --policy-bundle policy.json \
  --workload-digest sha256:<64 hex> \
  --jwk pubkey.jwk > record.json
```

Three arguments come from the operator rather than from the DecisionAssure trace, because the trace does not carry them:

- `--policy-bundle` — the policy bytes that were in force. `policy.bundle_hash` is a digest of the bundle, not of its name, its version, or the decision it produced. If nobody can produce those bytes, this record cannot honestly carry the field and should not be built.
- `--subject` — the SPIFFE or DID identity of the workload. An adapter may not mint an identity under a domain nobody controls.
- `--workload-digest` — `build_provenance.digest`, required by the schema, with nothing truthful to default it to.

The adapter exits `2` with an explanation rather than emitting a record it would have to invent a field for.

## What changed, 2026-08-08

The previous version produced records that failed `TrustRecord` validation on **seven** counts:

```
model.weights_digest      'sha256:placeholder-no-model'
runtime.platform          'software-simulated'          (not in the platform enum)
runtime.measurement       'sha384:000...000'
tool_transcript.hash      't1'                          (a trace id, not a hash)
build_provenance.digest   'sha256:placeholder'
```

Five are the same mistake: a required-shaped field with nothing real behind it, so a placeholder went in. `policy.bundle_hash` was a digest of `"{trace_id}:{decision}"`, which is a valid-looking hash of something that is not a policy bundle, and the README claimed it as a passing check.

The directory also sat at the repository root rather than under `integrations/`, so the manifest schema check never ran against it, and its `integration.yaml` used a shape the schema does not define. Both fixed.

It now builds on [`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters), which raises rather than fabricating, and the output is validated against the real `TrustRecord` model in CI.

## Conformance

**Level 0.** No hardware attestation, and the record does not claim any. Verify with:

```bash
pip install agentrust-trace-tests
trace-tests verify --record record.json --level 0
```
