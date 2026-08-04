# Agent Passport System integration with TRACE

The Agent Passport System (APS) is an open protocol for agent identity and
scoped delegation, in which an evaluator checks an agent's declared intent
against a Values Floor and returns an Ed25519-signed policy decision.

This integration maps exactly one signed APS policy decision, the dict returned
by `agent_passport.policy.evaluate_intent`, onto exactly one TRACE Trust Record
(EAT profile `tag:agentrust-io.com,2026:trace-v0.2`). Nothing else in APS is
mapped. Action receipts, revocation, identity binding, delegation chains and
attribution are out of scope here.

## Two different signatures

Conflating these two is the mistake this integration exists to avoid.

1. **The APS evaluator signature**, carried in the decision's `signature` field
   and verified against the `evaluatorPublicKey` embedded in the same decision.
   `aps_trace` verifies it through `agent_passport.policy.verify_policy_decision`
   before it maps anything. A decision whose signature fails, or whose
   `expiresAt` has passed, raises `ValueError` and produces no record.
2. **The TRACE record signature**, applied afterwards by
   `agentrust_trace.sign_record` with a separate key, whose public JWK is bound
   into `cnf.jwk`. `aps_trace` never applies it.

Verifying signature 1 says an APS evaluator authorized this action. Verifying
signature 2 says this exported record is the one the exporter produced. Neither
implies the other.

## Run it

Against released packages:

```bash
pip install agentrust-trace agentrust-trace-tests agent-passport-system
pip install -e "integrations/aeoess-aps[test]"
pytest integrations/aeoess-aps/tests -q
python integrations/aeoess-aps/examples/emit_record.py --out trust-record.jwt
trace-tests verify --record trust-record.jwt --level 0
```

The example mints a decision at run time with ephemeral keys instead of loading
a committed fixture. APS decisions expire five minutes after evaluation and the
mapper refuses expired decisions, so a committed decision fixture would be
permanently unmappable. No network access and no credentials are needed.

## Field mapping

| TRACE field | APS source |
|---|---|
| `eat_profile` | constant `tag:agentrust-io.com,2026:trace-v0.2` |
| `iat` | `evaluatedAt`, parsed to Unix seconds |
| `subject` | `spiffe://agent-passport.org/evaluator/<evaluatorId>/decision/<decisionId>` |
| `cnf.jwk` | caller-supplied public JWK for the TRACE signing key |
| `policy.bundle_hash` | sha256 over the APS canonical bytes of `{floorVersion, principlesEvaluated}` |
| `policy.enforcement_mode` | `enforce` when any principle was evaluated `inline`, else `advisory` |
| `policy.version` | `floorVersion` |
| `runtime.platform` | `software-only` |
| `runtime.measurement` | sha256 over the APS canonical bytes of the full signed decision |
| `appraisal.status` | `permit` to `affirming`, `narrow` to `warning`, `deny` to `contraindicated` |
| `appraisal.verifier` | `urn:aps:evaluator:<evaluatorId>` |
| `appraisal.policy_ref` | `urn:aps:floor:<floorVersion>` |
| `appraisal.timestamp` | `iat` |
| `transparency` | `urn:aps:transparency:none` |

An APS verdict this mapper does not know is refused rather than appraised.

## What is verified

- `aps_trace.build_trace_record` refuses a decision with a tampered verdict, a
  corrupt signature, a passed `expiresAt`, a missing field, or an unknown
  verdict. `tests/` covers each refusal.
- `agentrust_trace.sign_record` signs the record with an ephemeral Ed25519 key
  and `agentrust_trace.verify_record(..., allow_embedded_key=True)` verifies the
  round-trip. `tests/` includes a tamper probe that must fail verification.
- `trace-tests verify --level 0` passes on the emitted record: 8 checks, of
  which TR-SIG-005 is UNVERIFIED. See below.
- Every field the mapper emits validates against the TRACE v0.2 JSON Schema.
  The fields it does not emit are pinned by a test.

## What it does NOT claim

See rules 2 and 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **The record is a partial TRACE record.** `model`, `data_class` and
  `build_provenance` are required by the v0.2 JSON Schema and are absent. An APS
  policy decision carries no model identity, no data classification and no build
  provenance, so any value there would be invented. The record passes
  `trace-tests verify --level 0`, which does not grade those fields, and it does
  not satisfy the full v0.2 schema. `tests/test_mapping.py` pins the exact set of
  absent required fields so the gap cannot widen silently.
- **Level 0 carries an explicit `TR-SIG-005 UNVERIFIED` finding.** The graded
  artifact is the unsigned record, so trace-tests reports that it is not
  cryptographically verified. The signed form is written next to it as
  `<out>.signed.json` and verifies with `agentrust_trace.verify_record`.
- **`runtime.platform` is `software-only` and there is no hardware attestation.**
  `runtime.measurement` is a digest of the signed APS decision, not a TEE
  measurement. Per the v0.2 schema, `software-only` records must never be treated
  as attested evidence.
- **The ephemeral TRACE signing key proves the sign and verify path works.** It
  does not chain to a trusted issuer.
- **`transparency` is `urn:aps:transparency:none`.** This integration publishes
  nothing to a transparency log, so there is no SCITT receipt to resolve.
- **No conformance level above 0 is claimed or configured.**

## Conformance CI

`.github/workflows/aeoess-aps-conformance.yml` at the repository root, scoped to
`integrations/aeoess-aps/**`. It installs the released packages, runs the tests,
emits a record and runs `trace-tests verify --level 0` across Python 3.11 to
3.14.
