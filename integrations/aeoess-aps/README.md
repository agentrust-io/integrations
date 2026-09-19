# Agent Passport System integration with TRACE

The Agent Passport System (APS) is an open protocol for agent identity and
scoped delegation, in which an evaluator checks an agent's declared intent
against a Values Floor and returns an Ed25519-signed policy decision.

This integration does two things, in two modules that share nothing but the
APS dependency.

`aps_trace` maps exactly one signed APS policy decision, the dict returned by
`agent_passport.policy.evaluate_intent`, onto exactly one TRACE Trust Record
(EAT profile `tag:agentrust-io.com,2026:trace-v0.2`). TRACE revocation is
examined below; this exporter emits no `TraceRevocation/1.0` statement and
creates no revocation-store entry.

`aps_action_receipt` verifies exactly one signed APS action intent receipt
(`ReceiptV1`, profile `aps-receipt-v1`, type `aps:action-intent:v1`) as
external action issuance evidence and reports `verified`, `invalid` or
`unverified`. It emits no TRACE record. See [Action receipts as external evidence](#action-receipts-as-external-evidence).

Nothing else in APS is mapped or verified here. Identity binding, delegation
chains and attribution are out of scope.

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
revocation check). The behaviour observed at agentrust-trace 0.9.0 is retained here as a tested
implementation result; agentrust-io/trace-spec#246 records it as inconsistent with
section 3.2.3. It was not re-evaluated at 0.10.0, where
`verify_record` refuses the record on schema grounds before any revocation check
runs, so these rows are 0.9.0 results and are not restated for 0.10.0.

The APS artifacts examined come from aeoess/agent-passport-system#123 (revocation
verification corpus). Mapping questions and answers: agentrust-io/integrations#140.

## Run it

Against released packages:

```bash
pip install agentrust-trace agentrust-trace-tests agent-passport-system
pip install -e "integrations/aeoess-aps[test]"
pytest integrations/aeoess-aps/tests -q
python integrations/aeoess-aps/fixtures/action-receipt/generate.py  # must leave git diff empty
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

## Action receipts as external evidence

TRACE keeps three evidence layers apart (trace-spec `spec/trace-v0.2.md`
section 3.3.3): session evidence, action issuance evidence, and outcome
evidence. `docs/verification.md` ("Action receipts and embodied workflows")
lists what a verifier checks on an external action receipt and the outcomes it
reports. `aps_action_receipt.verify_aps_action_receipt` runs those checks on
one APS `ReceiptV1` of type `aps:action-intent:v1` and reports an APS
issuance evidence status.

| TRACE check (verification.md) | What this verifier does on a `ReceiptV1` |
|---|---|
| Canonical action digest | Recomputes `agent_passport.compute_action_ref` over the caller supplied preimage (`agent_id`, `action_type`, `scope_required`, `timestamp`, draft-pidlisnyi-aps section 4.1) and compares it to `action_ref`. Without a preimage the check is `not_checked`. |
| Receipt signature, trusted issuer key | `agent_passport.receipt_core.verify_receipt_v1` with the caller's `resolve_key`. `ReceiptV1` embeds no key, so the trust input is always the caller's. |
| Artifact class | `receipt_type` must be `aps:action-intent:v1` (or the caller's `expected_receipt_type`). A correctly signed receipt of another type is not action issuance evidence. |
| Session or call binding | `subject_agent` and `delegation_ref` against caller expectations, and `subject_agent` against the preimage's `agent_id` whenever a preimage is supplied. |
| Chain order | Not checked. `prev` is carried but this verifier takes one receipt, not a chain. |
| Freshness | `issued_at` against a caller supplied `reference_time` and `max_age_seconds`. No wall clock default, so a committed receipt verifies identically on every run. |

| Status reported | When | TRACE outcome |
|---|---|---|
| `verified` | every check that could run passed, against a pinned key | no_mapping, see below |
| `invalid` | structure, receipt id, signature, receipt type, subject, delegation reference, action binding or freshness failed | `receipt_invalid` |
| `unverified` | the signer key is not pinned and nothing else failed (trace-spec section 3.3.2: no trust conferred, no wrongdoing proven) | `receipt_unverified` |

`verified` maps to no TRACE outcome on purpose. TRACE splits a valid receipt
into `receipt_valid_accepted` and `receipt_valid_rejected` by the outcome the
receipt payload carries. `ReceiptV1.result` is an open object and the APS
receipt core defines no verdict field inside it, so reading acceptance or
rejection out of the receipt would be a convention this integration invented.
That split is outcome evidence and belongs to the bound decision output.
`receipt_missing_required` is a chain level outcome and out of scope for a
verifier that takes one receipt.

The committed fixture in `fixtures/action-receipt/` is regenerated byte for
byte by `generate.py` from published seed labels, so it carries no secret
material and `tests/test_action_receipt.py` pins its sha256. It is possible
here where a committed decision fixture is not: freshness is judged at the
caller's reference time, not the wall clock.

`verified` does not mean the action executed, that the delegation named by
`delegation_ref` was valid or current at issuance (verify that separately with
`agent_passport.verify_delegation`), that the signature proves authority rather
than authorship, or that anyone appraised the evidence.

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
- `aps_action_receipt.verify_aps_action_receipt` returns `verified` on the
  committed fixture at its recorded reference time and `invalid` on a corrupt
  signature, a tampered field, a wrong pinned key, another receipt type, a
  wrong subject agent, a preimage naming a different agent than the receipt,
  a wrong delegation reference, a different action preimage, a preimage with
  no canonical form, a stale receipt, a future dated receipt and a malformed
  receipt, and `unverified` on an unpinned key or a resolver error. Each case mutates one thing and `tests/test_action_receipt.py`
  asserts which check carried the result.

## What it does NOT claim

See rules 2 and 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **This integration is an `external-evidence-source`, not a `record-producer`,
  and claims no conformance level.** An APS decision is signed external
  evidence. The mapper places it into a TRACE record but cannot populate
  `model`, `data_class` or `build_provenance`, which the v0.2 JSON Schema
  requires, without inventing them. So the emitted record is not a TRACE Trust
  Record, and from `agentrust-trace` 0.10.0 `verify_record` refuses it on
  schema grounds. `tests/test_mapping.py` pins both the exact set of absent
  required fields and that refusal, so neither can change silently. The same
  role, for the same reason, is used by `nobulex`.
- **`trace-tests verify --level 0` is a coverage report here, not a claim.** It
  reports 8 checks with an explicit `TR-SIG-005 UNVERIFIED` finding because the
  graded artifact is the unsigned record. A clean Level 0 run means nothing the
  suite could check went wrong. It does not mean the record verifies.
- **The signed form `<out>.signed.json` demonstrates the sign path only.** Its
  signature is valid over the emitted claims, and `verify_record` still refuses
  it, because signature validity is not schema validity.
- **`runtime.platform` is `software-only` and there is no hardware attestation.**
  `runtime.measurement` is a digest of the signed APS decision, not a TEE
  measurement. Per the v0.2 schema, `software-only` records must never be treated
  as attested evidence.
- **The ephemeral TRACE signing key proves the sign and verify path works.** It
  does not chain to a trusted issuer.
- **`transparency` is `urn:aps:transparency:none`.** This integration publishes
  nothing to a transparency log, so there is no SCITT receipt to resolve.
- **No conformance level is claimed or configured.**

## CI

`.github/workflows/aeoess-aps-conformance.yml` at the repository root, scoped to
`integrations/aeoess-aps/**`, runs two jobs across Python 3.11 to 3.14:

- **floating** installs the latest released packages, unpinned on purpose, as
  drift detection. This is the "harness gets pinned, subject does not" rule
  from #169.
- **fixed** installs exactly the versions named in `integration.yaml`
  `tested_against`, checks that the installed versions match that file, and
  runs the same steps. This is what backs the `tested_against` claim.

Both run the tests, emit a record, and run `trace-tests verify --level 0` as a
coverage report.
