# Confidential Workflow Acceptance Harness

The [canonical acceptance procedure](https://github.com/agentrust-io/integrations/issues/199)
defines the paired controls and evidence boundaries. The utility-specific
reproduction steps and local trust boundary are documented below.

## Offline synthetic evidence reappraisal

`harness.reappraisal` retains an immutable copy of a deterministic run result
and compares it with explicit current verifier inputs: scenario, policy/trust
digests, a named dependency inventory, evaluation time and freshness budget.
Changed inputs or expired evidence return `reassessment_required` with reasons;
the historical result is retained. A changed dependency calls for reassessment,
not automatic refusal of the new workload. Refused, unknown and incomplete
historical results cannot become applicable without a fresh passing run.

Run with `HarnessRunner().run(scenario, observed_at=...)` to retain the full
scenario digest and original observation time in memory. These fields are
private local reuse metadata and are always excluded from public `to_dict()`
output. Both the result and each observation use explicit public-field lists;
new internal dataclass fields are excluded by default, and emitted mutable
values are copied. The public result schema rejects the private metadata. `EvidenceSnapshot.capture`
retains them separately inside its local `result_json`; the snapshot, its
content digests and dataclass representations are private and must not be
published. Capture rejects mismatched scenarios and missing or future
observation times. Later capture never resets evidence age. Legacy run objects
without both fields require a fresh run before retention for reappraisal.

Use `EvidenceSnapshot.capture(scenario, result, context, captured_at=...)`, then
`appraise(snapshot, scenario, current_context, evaluated_at=...,
max_age_seconds=...)`. Times are UTC Unix integer seconds. The optional run timestamp is caller-trusted
fixture input, not authenticated time. Evidence
expires exactly at the verifier-selected age limit. This is evidence freshness,
not the credential-expiry verification exercised by protocol-specific adapters.
The existing unittest discovery command runs the paired reappraisal controls.

This utility accepts caller-trusted local synthetic fixtures only. It does not
authenticate a snapshot, verify completeness of caller-supplied dependencies,
provide persistent revocation, execute an adapter, or authorize a new action.
Its hashes identify bytes; replacing both content and hashes is outside this
local trust boundary. `applicable` is limited to the selected synthetic claim
and explicit inputs, not protocol acceptance or permission to execute.

A deterministic software harness for issue #199. It keeps authorization, delivery,
receipt, admission, execution, response verification and release outcomes separate
and preserves unavailable evidence instead of inferring success from dispatch.

## Scope of this PR

The expanded experimental implementation provides:

- a fixed harness core;
- machine-readable manifest and result schemas;
- deterministic software adapters;
- paired valid controls and weakened-gate mutation proofs;
- explicit `waiting_on_release` handling;
- branch-preserving observations for retries;
- causal provenance fields (`caused_by`) on observations.

The published release API calls and one first-party software peer path are
exercised, but this is not a claim of independently established protocol
conformance, hardware attestation or completed Issue #199 acceptance.
See [About, licensing, IP boundaries, glossary and live-peer threat model](REMOTE-CA2A-PEER.md).

## Reproduce

```bash
python -m pip install --require-hashes -r ../../requirements/confidential-workflow-probe.txt
python -m unittest discover -s tests -v
```

The released component and bounded live-peer experiments use:

- `cmcp-runtime==0.7.0`
- `ca2a-runtime==0.4.0`
- `agentrust-trace==0.11.0`
- `agentrust-trace-tests==0.6.2`

Run these commands from this integration directory. The Level 0 regression checks
both records emitted by the released-package probe through the TRACE loader and
TR-ENV, TR-SIG, TR-POL and TR-APR modules, with default freshness checks. It also
rejects a subject-tampered twin. The probe emits current Unix timestamps and
synthetic `did:example:` subjects. Optional checks can be skipped by the suite;
this is bounded synthetic software conformance, with no live dispatch, trusted
identity provisioning, higher-level appraisal or hardware acceptance.

The cA2A runtime pin is recorded here and in the probe lock because the integration
manifest schema does not permit `ca2a-runtime` in `tested_against`.

The manifest's `tested_against` records the bounded released-package software
run using cMCP 0.7.0 above; it does not re-date the historical two-host captures.
Srinivasa Dinakar Jainti (`@dinakarjs`) maintains this successor following the
requested takeover of #330; the original contributor and capture attribution
remain in their existing records.

Protocol/API changes remain in the owning repositories. Any scenario that needs
an unreleased surface must carry `waiting_on_release`; a blocked required case
makes the overall result `incomplete`.

## Mutation proof rule

A valid comparison case and a weakened safety gate are separate controls.

For a negative scenario:

1. the negative input must be refused or remain unknown at the affected boundary;
2. a separately valid input must pass;
3. weakening/removing only the safety gate must cause the negative scenario to
   become accepted.

This prevents a green test from being attributed to the wrong guard.

## Evidence semantics

Every observation records a boundary, outcome, source, evidence class, lineage,
and optional causal parent. Main-lineage summaries never allow a retry branch to
overwrite an earlier unknown outcome.

The fixed core rejects malformed adapter histories with `ValueError` before
producing a result. Each source identifies one observation per lineage, each
boundary has one outcome per lineage, and each non-null causal parent names an
earlier observation in that lineage. A later observation cannot overwrite an
earlier boundary outcome. Unsupported mutation names are rejected before the
adapter runs. Response verification points to the actual
main-lineage execution observation, including timeout and no-dispatch outcomes.
Retry observations apply authorization, version admission, revocation, replay
and execution-evidence checks to the shared synthetic inputs in their own
lineage. Their receipt and admission observations precede execution. A retry
after a main-lineage timeout models a separately observed synthetic attempt;
its result does not replace the main path's evidence. No live retry is run.
`retry-dispatch` and `retry-receipt` represent scripted synthetic transport
observations, including when authorization is contradicted; neither establishes
authorized delivery or permission to execute. Consumers must inspect the
lineage's authorization, admission and guarded execution outcomes. A known
rejection (authorization, version admission, revocation or replay) produces
`execution=contradicted` even if execution evidence is also missing. Missing
evidence produces `unavailable` only when these guards allow execution. The
explicit missing-evidence mutation cannot override a known guard refusal.
The synthetic execution outcome evaluates the permitted-execution claim;
`contradicted` does not prove that no physical side effects occurred. Retry
attempts are independently scripted even when the main input has `dispatch=False`;
their observations do not establish real-world dispatch.

The public result must never contain protected payloads, secrets, device IDs or
low-entropy digests of protected material.

All seven main-lineage boundaries are required for this fixed workflow. A result
passes only when each is `established`. Missing observations remain `unavailable`;
an explicit `not_applicable` outcome also leaves the result `unknown`. Contradicted
evidence still produces `refused`, and a release dependency produces `incomplete`.
A forbidden recipient takes precedence over permission.
The deterministic software-version gate uses [SemVer 2.0.0](https://semver.org/)
with a fixed minimum of `1.0.0`: `1.0.0-rc.1` is below that minimum, and build
metadata does not change precedence. Invalid versions are refused.

## Conduit result acceptance

Both Conduit paths require literal boolean success flags, a nonempty session,
a full lowercase 40-hex commit and an integer zero exit code (booleans are
refused). Completion requires `running is False`; only `running is True`
continues remote polling. The signed remote path passes the authorized
transaction ID through both worker calls, their result echoes and hash-covered
receipt details, and binds it into the signed execution output. Missing or
mismatched worker context remains unknown. The caller independently checks the
signed execution fields before reporting success.

These stricter echoes require Conduit operator adoption and a fresh live
capture. Historical captures are not reclassified. Tests use a mocked worker
through the real released cA2A service/client and TRACE signing/verification;
they establish software refusal boundaries, not independent remote execution.
