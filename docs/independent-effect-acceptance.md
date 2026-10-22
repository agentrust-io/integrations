# Independent effect observation: #333 scenario checklist

Status: informative, unexecuted checklist for
[#333](https://github.com/agentrust-io/integrations/issues/333).
The reusable acceptance procedure remains in
[#199](https://github.com/agentrust-io/integrations/issues/199).
This draft retains its current path pending final placement confirmation; it
does not propose a second reusable procedure. Rajnish recommends extending
`integrations/alakris-authority-comparison/` and reusing its contract and CI.
Existing owners retain implementation and runtime/profile decisions.

## Prerequisites and scope

Use one disposable marker namespace with synthetic data and an independently
enrolled target observer. Before execution, identify the released runtime/API,
target operator, exact package/source/build and policy pins, invocation, trust
inputs, authenticated job/attempt/payload/authority binding, observation window,
cleanup policy and retained evidence. Different keys or hostnames alone do not
establish independent operation. No host, account or paid service is committed.

Proofable is a recommended dispatch-only candidate for the revocation case,
not a selected runtime or measured commit-after-revocation result. Label that
profile in the result fields themselves. Chris's released outbound invocation
and authenticated binding to target readback remain prerequisites. The
non-operational cMCP ExecutionRegistry is not an implemented alternative.

The current synthetic fixture disables the executor; it does not independently
model authority unavailability. Proofable's current unreachable case is
not_applicable because that path evaluates authority locally. EO01 therefore
requires a separate scope decision: acceptance of bounded MintID author-record
evidence, a synthetic extension separating authority and executor availability,
or another released runtime. Synthetic evidence and published author records
do not satisfy independently operated live acceptance.

## EO01–EO08 acceptance matrix

All rows are proposed and unexecuted. Apply the reusable procedure in #199.

| ID | Paired case | Observation needed |
| --- | --- | --- |
| EO01 | Fresh valid authority / unreachable authority without authorized fallback | Same hosted target and observer pipeline: exactly one independently observed durable effect / zero protected effects with complete bounded observation; authority availability varies independently of executor availability |
| EO02 | Recovery before / after original deadline | Eligible continuation / expired original attempt not revived; a fresh authorization is a distinct request |
| EO03 | Post-dispatch revocation with dispatch-only / final-commit profile | Declare profile in fields; measure whether the first commits; the second requires refusal when revocation is causally visible before final authorization |
| EO04 | Bound target, marker and job / substituted relation | Authenticated readback / specific binding refusal or unestablished relation |
| EO05 | Single / duplicate dispatch | Separate ingress and durable-effect counts; deduplication may hide repeated ingress; any exactly-once result is bounded to the tested operation |
| EO06 | Commit and response / commit with lost response | Independently observed target effect in both; response delivery unknown in the second |
| EO07 | Complete bounded observation / unavailable observer or log loss | Supported result / unknown, never inferred zero effects |
| EO08 | Enrolled observation / substituted signer or prior-run receipt | Accepted observation / trust or run-binding refusal |

Each negative case needs a fresh valid positive control through the same hosted
target and observer pipeline, not the synthetic Executor's in-process counter.
Capture ingress observations, durable-effect count and authenticated readback
separately for both controls. Missing completion reports or empty incomplete
logs do not establish zero protected effects. Preserve unknown outcomes.

For revocation retain causal ordering of dispatch, revocation visibility and
any final authorization check. Wall-clock order alone does not establish
visibility. A single run does not establish a propagation or availability SLA.

## Review handoff

Vlad retains the adapter and evidence-packet implementation. Retain exact tested
source and dependency pins, commands, raw observations and digests. Regenerate
`results/tests.txt` from that revision with both fixture sets present and record
the actual collected, passed and skipped counts; do not copy a reported count
without executing it. Rajnish reported 34 tests with zero skips at c5a0b8c,
while the retained transcript said 27; this checklist is not a fresh rerun.

Our independent evidence review starts after the released-runtime connection,
target operator and pinned packet are available. Disclose any shared
implementation work. Keep downloaded-packet integrity, offline appraisal,
author-record reports and separately operated live observations distinct.
No live run, hardware assurance, production guarantee or issue closure is
established by this checklist.
