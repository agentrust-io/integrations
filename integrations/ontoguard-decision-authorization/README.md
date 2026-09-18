# OntoGuard Decision Authorization integration with TRACE

Thin interoperability adapter. It consumes a *signed* OntoGuard Decision
Authorization result and, only after an *independent* execution receipt binds
to that exact result, emits a TRACE v0.2 Level 0 Trust Record.

This adapter contains no OntoGuard core authorization or semantic-governance implementation.

## What this integration does

```
exact signed OntoGuard authorization result bytes
        ↓
verify Ed25519 signature + recompute result digest
        ↓
independent execution receipt
        ↓
verify receipt names the same handoff, digest, binding, and ALLOW action
        ↓
if BLOCK, ESCALATE, or ALLOW without a valid receipt:
    emit no TRACE record
if ALLOW + independently proven execution:
    emit TRACE v0.2
    subject = SPIFFE or DID string
    references[0].rel = authorized-intent
    references[0].id = handoff hash
    references[0].digest = recomputed result digest
```

| State | TRACE record |
|---|---|
| `BLOCK_NO_EXECUTION` | none |
| `ESCALATE_NO_EXECUTION` | none |
| `ALLOW_NO_EXECUTION_YET` | none |
| `ALLOW_EXECUTION_PROVEN` | Level 0 software-only record |

`ALLOW` never proves that an action ran. A BLOCK or ESCALATE paired with
`executed=true` is rejected, not silently reclassified.

## What this integration does not claim

- Not production L5 or non-bypassable route topology.
- Not hardware attestation, TEE, or confidential computing.
- Not published TRACE conformance until `trace-tests verify --level 0` runs
  against a signed record in CI.
- Not an OntoGuard semantic engine. Authorization remains in OntoGuard.
- Per TRACE spec 3.1.2, a Trust Record is issued per execution and a
  reference cannot carry a pre-execution commitment.
- `appraisal.status=none`. Local TRACE signing is not an independent appraisal.
- Community tier on first submission.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[test]"

pytest -q

export TRACE_PRIVATE_KEY_PEM="$(openssl genpkey -algorithm ED25519)"
python examples/emit_record.py --out /tmp/ontoguard-trust-record.json

trace-tests verify \
  --record /tmp/ontoguard-trust-record.json \
  --level 0
```

A captured historical controlled-execution proof plus a live executor
harness live in `examples/controlled-execution-proof-2026-09-17/`.

```bash
python examples/controlled-execution-proof-2026-09-17/verify_proof.py
python examples/controlled-execution-proof-2026-09-17/controlled_executor.py
```

The historical ALLOW authorization is frozen evidence and expires
2026-09-24. The live harness does **not** reuse that object. It mints a
TEST-ONLY authorization at runtime, verifies it before any commit, then
reruns $250k (commit) and $260k (refuse) through this adapter. That
runtime authorization is harness-only and is not a live OntoGuard
Decision API result.

Level 1 is unsupported (`runtime.platform=software-only`) and must fail
`TR-RTE-001`.

## Field provenance (executed path only)

| TRACE field | Source |
|---|---|
| `eat_profile` | TRACE v0.2 constant |
| `subject` | Execution-receipt SPIFFE or DID **string** |
| `model` | Execution receipt |
| `runtime` | Fixed Level 0 software-only values |
| `policy` | Execution receipt (policy in force at run time) |
| `build_provenance` | Execution receipt (executed workload) |
| `origin.kind` | `third-party-control-plane` |
| `origin.producer` | Execution receipt `execution_producer` |
| `origin.source_event_id` | Execution receipt `execution_event_id` |
| `references[0].rel` | registered `authorized-intent` |
| `references[0].id` | OntoGuard `handoff_hash` from signed result |
| `references[0].digest` | SHA-256 recomputed over exact signed result bytes |
| `appraisal` | `none` |
| TRACE `cnf.jwk` / `signature` | `agentrust_trace.sign_record` |

## Responsibility boundary

- OntoGuard: authorization result and signature over the exact result bytes.
- Executing runtime: independent execution receipt after the action runs.
- This adapter: verify both objects, refuse TRACE when either is missing or
  mismatched, project an executed event into TRACE v0.2.
- Downstream enforcement: consume the current handoff before commit.

## License

Apache-2.0, matching `agentrust-io/integrations`. OntoGuard core
authorization technology is separate and is not part of this adapter.
