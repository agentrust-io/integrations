# ramen-ai cMCP Adapter integration with cMCP + TRACE

The canonical [ramen-ai cMCP adapter](https://github.com/ramen-ai-dev/ramen-ai-integrations/tree/master/plugins/cmcp-python)
intercepts tool calls at the [cMCP](https://github.com/agentrust-io/cmcp)
boundary and obtains V5 Ed25519 receipts from the ramen-ai API. This vendored
review artifact verifies those receipts and exports natively signed TRACE v0.2
Trust Records; it does not vendor or independently test the cMCP interception
runtime.

Source: [ramen-ai-dev/ramen-ai-integrations — plugins/cmcp-python](https://github.com/ramen-ai-dev/ramen-ai-integrations/tree/master/plugins/cmcp-python)

## Trust boundary

This integration emits TRACE Level 0 records only:

- `runtime.platform` is always `software-only`.
- `runtime.measurement` is the conventional all-zero SHA-256 development measurement.
- `appraisal.status` is always `none` because no hardware verifier is present.
- Records are signed with a dedicated Ed25519 key from `TRACE_PRIVATE_KEY_PEM`.
- The ramen-ai receipt key verifies the upstream V5 receipt and is never reused for TRACE signing.
- Production receipt keys are trusted by default; the committed conformance key must be supplied explicitly by tests and the offline example.
- Invalid receipt signatures and input bindings are rejected before TRACE signing.
- Level 1 is intentionally unsupported and fails `TR-RTE-001` because `software-only` is not a hardware TEE platform.

## Field provenance

| TRACE field | Source |
|---|---|
| `eat_profile` | TRACE v0.2 constant `tag:agentrust-io.com,2026:trace-v0.2` |
| `subject` | Verified V5 receipt ID under the `ramenai.dev` SPIFFE trust domain |
| `model` | Required caller-supplied assertion |
| `runtime` | Fixed honest software-only Level 0 values |
| `policy.bundle_hash` | Required caller digest of the policy artifact in force |
| `policy.enforcement_mode` | `enforce`, matching the adapter's blocking behavior |
| `data_class` | Required caller classification |
| `build_provenance` | Required caller build evidence |
| `appraisal` | `none`, caller-supplied verifier URI, and issue time |
| `cnf.jwk`, `signature` | Native `agentrust_trace.sign_record` output |

The Level 0 record omits `transparency` because no SCITT receipt exists. It also
omits `tool_transcript` because a V5 evaluation receipt is not the full MCP/A2A
transcript.

## Reproduction steps

From the repository root, create an isolated environment and install the exact
released TRACE packages declared by this integration:

```bash
python3 -m venv .venv-ramen-ai-cmcp
source .venv-ramen-ai-cmcp/bin/activate
python -m pip install --upgrade pip
python -m pip install -e "integrations/ramen-ai-cmcp[test]"
pytest integrations/ramen-ai-cmcp/tests -q
```

Generate a dedicated local Ed25519 key and emit the signed record. Production
must inject a persistent, independently managed TRACE signing key through its
secret manager; the adapter has no ephemeral fallback.

```bash
export TRACE_PRIVATE_KEY_PEM="$(openssl genpkey -algorithm ED25519)"
python integrations/ramen-ai-cmcp/examples/emit_record.py \
  --out /tmp/ramen-trust-record.json \
  --model-provider ramen-ai \
  --model-id conformance-fixture-evaluator \
  --model-version 1 \
  --data-class internal \
  --policy-bundle-hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --slsa-level 0 \
  --build-digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --builder https://github.com/ramen-ai-dev/ramen-ai-integrations \
  --appraisal-verifier https://ramenai.dev/trace/software-only
trace-tests verify --record /tmp/ramen-trust-record.json --level 0
```

Expected Level 0 summary:

```text
Result: PASS (8 checks, 0 skipped)
```

The former `TR-SIG-005 UNVERIFIED` limitation is completely resolved: the
artifact graded by `trace-tests` is the same native signed object returned by
`agentrust_trace.sign_record`, including `cnf.jwk` and its top-level signature.

To verify that the integration does not overclaim hardware attestation, run:

```bash
trace-tests verify --record /tmp/ramen-trust-record.json --level 1
```

Level 1 is expected to fail exactly `TR-RTE-001` for
`runtime.platform: software-only`; the signature, runtime measurement, and build
provenance checks remain valid.

## What it does NOT claim

See rules 2 and 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- No TEE, hardware root of trust, or attested-execution claim is made.
- The dedicated local signing key demonstrates native signing and verification;
  it does not by itself establish a trusted issuer chain.
- The ramen-ai evaluation API requires `RAMEN_API_KEY` and `OPENAI_API_KEY`
  (BYOK on Starter/Professional tiers). Conformance runs offline against committed
  fixtures and does not call the live API.
- V5 receipts bind policy UUIDs but not rule content; the caller must supply the
  digest of the policy artifact actually in force.

## Verified-tier review

Done. A maintainer reproduced the Level 0 result above on 2026-08-24 against
released `agentrust-trace` and `agentrust-trace-tests` in an isolated
environment (23 tests passed, `Result: PASS (8 checks, 0 skipped)`), and the
manifest is now `tier: verified`. Re-verification happens at every release
that touches this integration.

## Conformance CI

The repository-root workflow
[`.github/workflows/ramen-ai-cmcp-conformance.yml`](../../.github/workflows/ramen-ai-cmcp-conformance.yml)
installs `agentrust-trace==0.5.1` and `agentrust-trace-tests==0.4.1`, runs the
offline receipt and mapping tests, emits the signed record, and runs Level 0
conformance across Python 3.11–3.14.
