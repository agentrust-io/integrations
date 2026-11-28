# Auditant evidence bundle to TRACE

Auditant records an AI agent's model calls, tool calls and policy decisions in a hash chain and exports them as an evidence bundle ([`GET /v1/export`](https://auditant.co/docs/api#get-v1-export), bundle format 1.0.0). `auditant_trace.py` re-checks a bundle offline and, only if it verifies, emits a TRACE v0.2 **log-import** Trust Record at **Level 0** (software-only). The record is assembled by [`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters/) `build_record`, so it carries no placeholder values.

## The checks

Every check fails closed: one failure anywhere and no record is written.

1. **Structure.** Each field a check reads is present with the right type. Integers are integers (a JSON `true` is not a tree size), digests are `sha256:` plus 64 hex characters, and a JSON object may not repeat a key. Malformed input is reported as `BundleNotVerified`, never raised as another exception.
2. **Chain.** `seq` increments by one, each `prevHash` equals the previous `eventHash` (the first links to `startHead` when the export starts mid-log, and to the all-zero genesis hash when it starts at `seq` 0), and each `eventHash` equals `sha256` over the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) form of the event without its `eventHash`.
3. **Checkpoints.** Every checkpoint in the bundle must verify, not only the one that anchors it: its key is listed in the bundle (and pinned, when `--pin-key` is given), its origin is this log's, its fields re-serialise to the signed body, its signature is canonical base64 and verifies, and if its tree size falls inside the exported window its head equals the recomputed chain head at that size. A checkpoint that ends outside the window gets every check except the head, which the bundle cannot recompute, and does not count for anchoring.
4. **Anchoring, at both ends.** A verified checkpoint covers the last event, and the head the bundle starts from is either the genesis hash or signed by a verified checkpoint. Without the second half, an export with its first events deleted would pass for a shorter one.

A record is built only from a **whole log** (first `seq` 0). A ranged export can verify, but TRACE has no field that says a record covers part of a log, so a record from one would read as the whole of it, with a transcript, model and policy facts that silently omit everything before the excerpt.

## What an Auditant checkpoint is, and is not

The signed body uses the line layout of a [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) (origin, tree size, base64 hash), but the hash line is the head of a **linear hash chain**, the `eventHash` of the last event, **not an RFC 6962 Merkle tree root**, and the signature is a bare ECDSA P-256 / SHA-256 signature over the body, not a C2SP signed note. So it is not a C2SP checkpoint: there are no inclusion or consistency proofs, and C2SP witnesses and tools do not apply. Checking a bundle means walking every event, which this adapter does.

## What it does not claim

- No hardware attestation. `runtime.platform` is `software-only`; Level 1 fails `TR-RTE-001`, `TR-RTE-004` and `TR-APR-005` by design.
- A bundle carries its own public keys, so a valid checkpoint signature shows the bundle agrees with itself, not who made it. Pass `--pin-key KEYID=PEMFILE` with a key obtained out of band to require it; then every checkpoint must be signed by a pinned key.
- RFC 3161 timestamp tokens on checkpoints are not checked.
- The bundle does not carry the agent's workload identity, the policy bundle's bytes or the agent's artifact digest. The operator supplies all three, and nothing is derived from the log ID or from policy names.
- `appraisal.status` is `none`. Building a record is not an appraisal.

## Field mapping

| TRACE field | Value |
|---|---|
| `subject` | `--subject`: the agent workload's SPIFFE URI or DID, from the operator. The bundle's `actor.id` is an Auditant-scoped name, not an identity |
| `model` | the one provider and model the bundle's `model_call` events name in `cost.provider` / `cost.model`. With several, `--model-provider` and `--model-id` choose, and a choice must match a `model_call` event: a value given for one half is never replaced by inference. A `model_call` event that names no model is refused |
| `policy.bundle_hash` | `sha256` of `--policy-bundle`, the bytes of the policy the deployment runs |
| `policy.enforcement_mode` | `--enforcement-mode`, no default: `enforce` when tool calls were held by policy before they ran, `advisory` when decisions were only recorded, `declared` when no policy was evaluated. A bundle holding `policy_decision` events shows a policy was evaluated, so `declared` is refused for it |
| `tool_transcript.hash` | `sha256` over the RFC 8785 form of the bundle's `tool_call` events, in order, each exactly as exported (`eventHash` included); omitted when there are none |
| `tool_transcript.call_count` | number of `tool_call` events |
| `origin` | `kind: log-import`; `producer`: `--producer`, default `https://auditant.co` (a self-hosted deployment passes its own URL); `source_event_id`: the `eventId` of the last event, the one the anchoring checkpoint covers |
| `runtime.measurement` | `build_record`'s software commitment over producer, subject and policy hash; with `platform: software-only` it is not a hardware measurement |
| `build_provenance.digest` | `--workload-digest`: the agent's image or artifact digest, from the operator (`slsa_level: 0`) |
| `cnf.jwk` | the public half of the key the record is signed with |

## Run it

Against released packages, on a fixture made by Auditant's own exporter:

```bash
pip install "agentrust-trace==0.11.0" "agentrust-trace-adapters==0.2.0" "agentrust-trace-tests==0.6.2" "pytest==9.1.1"
pip install --no-deps -e integrations/auditant-evidence-bundle
python -m pytest integrations/auditant-evidence-bundle/tests -q
python integrations/auditant-evidence-bundle/examples/emit_record.py --out auditant.trace.json
trace-tests verify --record auditant.trace.json --level 0
```

On a real export:

```bash
auditant-trace bundle.json --out bundle.trace.json \
  --subject spiffe://example.org/agent/support-bot \
  --policy-bundle policy.cedar \
  --enforcement-mode advisory \
  --workload-digest sha256:<64 hex> \
  --data-class confidential \
  --pin-key auditant-1a2b3c4d5e6f=operator-checkpoint-key.pem \
  --signing-key trace-signing-key.pem
```

Without `--signing-key`, `TRACE_PRIVATE_KEY_PEM` is used, else an ephemeral Ed25519 key with a warning.

## What is verified

The fixtures in [`fixtures/`](fixtures/) were made by Auditant's own TypeScript core and passed its own verifier, so the tests check this adapter against an independent producer, not against bundles it wrote itself. A reviewer can reproduce:

1. The tests (66):
   - whole and ranged exports verify, and only a whole log yields a record;
   - deleting the first events is caught, a ranged export needs a signed start, and a `startHead` at tree size 0 must be the genesis hash;
   - each TRACE field carries the meaning in the table above;
   - model choices are checked against the events;
   - an edited, deleted, reordered or truncated event, a broken start link and a missing key each produce no record;
   - a failed checkpoint fails the bundle even when another checkpoint anchors it, and so does a checkpoint under an unlisted key, one for another log, or one that contradicts the chain;
   - an unpinned key fails when keys are pinned;
   - non-canonical base64 (unused bits, missing padding, a newline, the URL-safe alphabet) is refused, in the signature and in a signed body;
   - a boolean or float where an integer belongs, missing keys (an `eventId` included), wrong types, duplicate keys, deeply nested input, non-JSON bytes and non-object JSON are refused as `BundleNotVerified`;
   - the CLI writes nothing for a bundle that fails and exits 2 with a message on a missing file or a malformed `--pin-key`.
2. `trace-tests verify --level 0`: `Result: PASS (15 checks, 4 skipped)`, with `agentrust-trace` 0.11.0 and `agentrust-trace-tests` 0.6.2. `trace-tests report --max-level 2` gives highest level passed 0.
3. `tool_transcript.hash` equals `sha256` of the RFC 8785 form of `fixtures/auditant-full.json`'s `tool_call` events.

## Conformance CI

`.github/workflows/auditant-evidence-bundle-conformance.yml` installs the pinned released packages, runs the tests, emits a record from the fixture, asserts the level report (0 passes, 1 and 2 fail), recomputes the transcript hash from the fixture, and enforces Level 0.
