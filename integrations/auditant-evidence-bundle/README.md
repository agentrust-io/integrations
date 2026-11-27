# Auditant evidence bundle to TRACE

Auditant records an AI agent's model calls, tool calls and policy decisions in a hash chain and exports them as an evidence bundle ([`GET /v1/export`](https://auditant.co/docs/api#get-v1-export), bundle format 1.0.0). `auditant_trace.py` re-checks a bundle offline and, only if it verifies, emits a TRACE v0.2 **log-import** Trust Record at **Level 0** (software-only).

The checks, in order. Any failure means no record is written:

1. **Chain.** `seq` increments by one, each `prevHash` equals the previous `eventHash`, and each `eventHash` equals `sha256` over the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) form of the event without its `eventHash`.
2. **Checkpoints.** The [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body (origin, tree size, base64 head hash) re-serialises from the checkpoint fields, its ECDSA P-256 / SHA-256 signature verifies under the bundle's key for that `keyId`, and the signed head equals the recomputed head at that tree size.
3. **Anchoring.** A verified checkpoint covers the last event in the bundle.

## What it does not claim

- No hardware attestation. `runtime.platform` is `software-only`; Level 1 fails `TR-RTE-001`, `TR-RTE-004` and `TR-APR-005` by design.
- A bundle carries its own public keys. A valid checkpoint signature shows the bundle is consistent with those keys, not who holds them. Pass `--pin-key KEYID=PEMFILE` with a key obtained out of band to require it.
- RFC 3161 timestamp tokens on checkpoints are not checked.
- `policy.bundle_hash` is the digest of the policy identifiers the log names (`policyId`, `policyVersion`, `engine` from `policy_decision` events). The export carries no policy text.
- `policy.enforcement_mode` has no default and is never upgraded: pass what the deployment did for the whole window (`enforce` when tool calls were held by policy before they ran, `advisory` when decisions were only recorded, `declared` when no policy was evaluated).
- `build_provenance` is `slsa_level: 0` with the all-zero digest: Auditant does not record the agent's image digest, so there is no provenance claim.
- `appraisal.status` is `none`. Building a record is not an appraisal.

## Field mapping

| TRACE field | Value |
|---|---|
| `subject` | `spiffe://auditant.dev/<logId>`, the checkpoint origin namespace |
| `model` | the one provider and model the bundle's `model_call` events name; with several, pass `--model-provider` and `--model-id` |
| `runtime.measurement` | `sha256` of the signed checkpoint body that anchors the chain (not a hardware measurement) |
| `tool_transcript.hash` | `sha256` of the exact bundle bytes |
| `tool_transcript.call_count` | number of `tool_call` events |
| `origin` | `kind: log-import`, `producer: auditant-trace/0.1.0`, `source_event_id`: the anchored head hash |

## Run it

Against released packages, with a demo bundle (synthetic events, throwaway signing key):

```bash
pip install "agentrust-trace==0.11.0" "agentrust-trace-tests==0.6.2" "pytest==9.1.1"
pip install --no-deps -e integrations/auditant-evidence-bundle
python -m pytest integrations/auditant-evidence-bundle/tests -q
python integrations/auditant-evidence-bundle/examples/emit_record.py --out auditant.trace.json
trace-tests verify --record auditant.trace.json --level 0
```

On a real export:

```bash
auditant-trace bundle.json --out bundle.trace.json \
  --enforcement-mode advisory --data-class confidential \
  --pin-key auditant-1a2b3c4d5e6f=operator-checkpoint-key.pem \
  --signing-key trace-signing-key.pem
```

Without `--signing-key`, `TRACE_PRIVATE_KEY_PEM` is used, else an ephemeral Ed25519 key with a warning.

## What is verified

A reviewer can reproduce:

1. The tests (14): a clean demo bundle verifies; an edited, deleted, reordered or truncated event, a forged checkpoint signature, a missing key, an unknown bundle format and an unpinned key each produce no record.
2. `trace-tests verify --level 0`: `Result: PASS (15 checks, 4 skipped)`, Ed25519 signature verified, with `agentrust-trace` 0.11.0 and `agentrust-trace-tests` 0.6.2. `trace-tests report --max-level 2` gives highest level passed 0.
3. `tool_transcript.hash` equals `sha256:` of `demo-bundle.json` (`shasum -a 256 demo-bundle.json`).

## Conformance CI

`.github/workflows/auditant-evidence-bundle-conformance.yml` installs the pinned released packages, runs the tests, emits a record, asserts the level report (0 passes, 1 and 2 fail) and enforces Level 0.
