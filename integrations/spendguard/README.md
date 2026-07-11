# Agentic SpendGuard integration with TRACE

Agentic SpendGuard is a spend firewall for LLM agents: it reserves budget and
gates tool calls before the provider is called, and records each decision in a
signed, hash-chained ledger. This integration maps one SpendGuard evidence
bundle — the signed audit output of a single spend/gate decision — onto a TRACE
Trust Record, using the same field mapping as SpendGuard's own fixture verifier.

## Run it

Against released packages:

```bash
pip install -e "integrations/spendguard[test]"   # pulls agentrust-trace
pip install agentrust-trace-tests
pytest integrations/spendguard/tests -q
python integrations/spendguard/examples/emit_record.py --out trust-record.jwt
trace-tests verify --record trust-record.jwt --level 0
```

## What is verified

- `spendguard_trace.build_trace_record` maps the committed example evidence
  bundle (`examples/fixtures/allow/`, a signed SpendGuard allow decision) onto
  TRACE fields: `policy.bundle_hash`, `tool_transcript.hash`,
  `runtime.measurement` (the evidence-bundle hash), SPIFFE `subject`, model and
  build provenance.
- `agentrust_trace.sign_record` signs the record with an ephemeral Ed25519 key
  and `agentrust_trace.verify_record(..., allow_embedded_key=True)` verifies the
  round-trip; `tests/` includes a tamper probe that must fail verification.
- `trace-tests verify --level 0` passes on the emitted record (8 checks).

## What it does NOT claim

See rules 2 and 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **Level 0 carries an explicit `TR-SIG-005 UNVERIFIED` finding.** The released
  `agentrust-trace-tests` 0.1.0 loader rejects any plain trace record carrying a
  top-level `signature` field (anti-downgrade: it reads as a partial cMCP
  envelope), and its TR-SIG module verifies signatures only on cMCP RuntimeClaim
  envelopes. So the graded record is the unsigned payload and is **not
  cryptographically verified by trace-tests**. The signed form is written next
  to it (`<out>.signed.json`) and verifies with `agentrust_trace.verify_record`.
- The ephemeral signing key proves the sign/verify path works; it does **not**
  chain to a trusted issuer. SpendGuard's production decisions are signed with
  KMS-held keys; that trust path is not exercised here.
- The example bundle's SpendGuard-side CloudEvent signatures are verified by the
  conformance harness in the [upstream repo](https://github.com/m24927605/agentic-spendguard)
  (fixture-only today), not re-verified by this integration.
- `runtime.platform` is `software-only`. No TEE, hardware root of trust, or
  attested-execution claim is made.
- No cMCP integration is included yet. Cedar spend-policy patterns for the cMCP
  tool boundary (amount thresholds, HITL-above-X, per-workflow limits) are a
  planned follow-up; `integrates_with` will gain `cmcp` when they land.

## Conformance CI

`.github/workflows/agentrust-conformance.yml` installs the released agentrust-io
packages, runs the mapping tests, emits a record, and runs `trace-tests verify
--level 0` across Python 3.11–3.13. A clean matrix run is the basis for the
Verified tier.
