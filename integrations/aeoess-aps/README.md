# Agent Passport System integration with TRACE

The Agent Passport System (APS) is an open protocol for agent identity and
scoped delegation, in which an evaluator checks an agent's declared intent
against a Values Floor and returns an Ed25519-signed policy decision.

This integration maps exactly one signed APS policy decision, the dict returned
by `agent_passport.policy.evaluate_intent`, onto exactly one TRACE Trust Record
(EAT profile `tag:agentrust-io.com,2026:trace-v0.2`). Nothing else in APS is
mapped. Action receipts, identity binding, delegation chains and attribution are
out of scope here. TRACE revocation is examined below; this exporter emits no
`TraceRevocation/1.0` statement and creates no revocation-store entry.

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

## Revocation

APS revokes authority: a delegation (`RevocationRecord`, keyed by delegation id) or a
principal binding (`PrincipalBindingRevocationV1`, keyed by binding id), each with a
signed observation of what was checked. TRACE revokes a record-signing key and asserts
its compromise. The two answer different questions, so the mapping is examined field by
field and, for this exporter, produces no TRACE revocation object.

TRACE's revocation surface is one mechanism that degrades gracefully: where an inclusion
proof gives a record a log position, `TraceRevocation/1.0` (trace-spec main at
`738358d`, unreleased) withdraws the key from that entry onward; where there is no
inclusion entry, `docs/verification.md` section 3.2.3 falls back to binary revocation on
the key, which is what `RevocationStore` in the released `agentrust-trace` 0.9.0
implements. Both columns below are that one rule at two levels of evidence.

| APS field or artifact | `RevocationStore` membership (0.9.0) | `TraceRevocation/1.0` (main `738358d`) |
|---|---|---|
| `RevocationRecord` (delegation id) | no_mapping | no_mapping |
| `PrincipalBindingRevocationV1` (binding id) | no_mapping | no_mapping |
| `revokedBy` | no_mapping | no_mapping: never `compromised_key_id`; APS withdraws an authority and asserts nothing about a key |
| `revokedAt` / `revoked_at` | no_mapping (a membership test carries no time) | partial: `revoked_at`, converted to Unix seconds; informational in TRACE, not the boundary |
| `reason` / `reason_code` | no_mapping | partial: `reason` as free text; a binding `reason_code` renders as text and loses its code semantics |
| `affected_scope`, revocation ids, `revocation_artifact_digest` | no_mapping | no_mapping (`additionalProperties: false`) |
| `SignedRevocationObservation` | no_mapping (the store carries no statement of what was checked) | no_mapping as statement (an observation withdraws nothing) and as bundle (cannot be constructed) |
| `last_valid_entry_id`, `log_id`, `revocation_key_id`, `sig` (required to construct a statement) | not applicable | no_mapping: this exporter emits unsigned records with `transparency: none`, so it has no log position, no record-signing key and no TRACE signing contract; the two `partial` rows above are source correspondences only and cannot complete a statement without these |

The `no_mapping` rows are a property of the record class, not pending work. An unsigned
record with `transparency: none` has no inclusion entry and no signing key, so under
section 3.2.3 it has no revocation surface at all, by construction. Nothing here becomes
a `TraceRevocation/1.0` statement and no store entry is manufactured from an APS
artifact.

One observed divergence, kept as tested against 0.9.0: an empty `RevocationStore`
accepts and an omitted store skips the check, while APS treats "no artifacts observed"
as no evidence rather than as not revoked. TRACE's own section 3.2.3 takes the APS
position at the bundle level (a verifier with no bundle reports that it performed no
revocation check). The behaviour observed at `tested_against: 0.9.0` is retained here as a tested
implementation result; agentrust-io/trace-spec#246 records it as inconsistent with
section 3.2.3.

The APS artifacts examined come from aeoess/agent-passport-system#123 (revocation
verification corpus). Mapping questions and answers: agentrust-io/integrations#140.

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
| `appraisal.status` | constant `none` |
| `appraisal.verifier` | `urn:aps:evaluator:<evaluatorId>` |
| `appraisal.policy_ref` | `urn:aps:floor:<floorVersion>` |
| `appraisal.timestamp` | `iat` |
| `transparency` | `urn:aps:transparency:none` |

An APS verdict this mapper does not know is refused rather than transcribed.

`appraisal.status` is `none` and is not a parameter. The
`agentrust-trace-adapters` convention that landed on `main` in commit `e1aa231`
(2026-08-08) sets it that way for any record assembled from evidence another
system produced: "Nobody appraised the evidence. Transcribing is not
appraising", and "A vendor's bare ALLOW/DENY result is still a policy decision,
not an appraisal of the evidence behind that decision." An APS verdict is
exactly such a policy decision. Our mapping was reviewed as defensible on
2026-08-03. A clearer adapter convention landed on 2026-08-09 that separates
policy decisions from evidence appraisal, and the exporter aligns to that
convention here. The verdict is still carried, as `policy.enforcement_mode` and
`policy.version`.

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
