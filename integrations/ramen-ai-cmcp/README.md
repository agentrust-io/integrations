# ramen-ai cMCP Adapter integration with cMCP + TRACE

Intercepts tool calls at the [cMCP](https://github.com/agentrust-io/cmcp)
boundary, evaluates their semantic intent against configured compliance policies
via the [ramen-ai](https://ramenai.dev) API, and maps the resulting V5
Ed25519-signed receipt onto a TRACE Trust Record (EAT profile
`tag:agentrust.io,2026:trace-v0.1`).

Source: [ramen-ai-dev/ramen-ai-integrations — plugins/cmcp-python](https://github.com/ramen-ai-dev/ramen-ai-integrations/tree/master/plugins/cmcp-python)

## Run it

Against released packages (`agentrust-trace` 0.3.0, `cmcp-runtime` 0.3.0):

```bash
pip install agentrust-trace agentrust-trace-tests cmcp-runtime
pip install -e "integrations/ramen-ai-cmcp[test]"
pytest integrations/ramen-ai-cmcp/tests -q
python integrations/ramen-ai-cmcp/examples/emit_record.py --out trust-record.jwt
trace-tests verify --record trust-record.jwt --level 0
```

## What is verified

- `ramen_ai_trace.build_trace_record` maps a committed V5 fixture receipt onto
  TRACE fields: `policy.bundle_hash` (`sha256:<payload_hash>`), `runtime.measurement`
  (receipt UUID), `subject` (`spiffe://ramenai.dev/evaluation/<receipt_id>`),
  `appraisal.status` (`affirming` / `denying`).
- `agentrust_trace.sign_record` signs the record with an ephemeral Ed25519 key
  and `agentrust_trace.verify_record(..., allow_embedded_key=True)` verifies the
  round-trip; `tests/` includes a tamper probe that must fail verification.
- `trace-tests verify --level 0` passes on the emitted record (8 checks).

## What it does NOT claim

See rules 2 and 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **Level 0 carries a TR-SIG-005 UNVERIFIED finding.** The `agentrust-trace-tests`
  loader rejects any plain record carrying a top-level `signature` field
  (anti-downgrade), so the gradable record is the unsigned payload. The signed
  form is written alongside it (`<out>.signed.json`) and verifies with
  `agentrust_trace.verify_record`.
- The ephemeral signing key proves the sign/verify path works; it does **not**
  chain to a trusted issuer.
- `runtime.platform` is `software-only`. No TEE, hardware root of trust, or
  attested-execution claim is made.
- The ramen-ai evaluation API requires `RAMEN_API_KEY` and `OPENAI_API_KEY`
  (BYOK on Starter/Professional tiers). The conformance workflow does not call
  the live API — it maps a committed fixture receipt offline.
- V5 receipts bind policy UUIDs but not rule content (policies are mutable under
  the same UUID). See `v5-conformance.md §6` in the ramen-ai-integrations repo.

## Conformance CI

The repository-root workflow
[`.github/workflows/ramen-ai-cmcp-conformance.yml`](../../.github/workflows/ramen-ai-cmcp-conformance.yml)
(path-scoped to this directory) installs the released agentrust-io packages,
runs the mapping tests, emits a record, and runs `trace-tests verify --level 0`
across Python 3.11–3.14. A clean matrix run is the basis for the Verified tier.
