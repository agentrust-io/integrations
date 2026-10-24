# Informative confidential-workflow acceptance profile

This procedure organizes the existing acceptance criteria in
[integrations #199](https://github.com/agentrust-io/integrations/issues/199),
following the [maintainer scope ruling](https://github.com/agentrust-io/.github/issues/64#issuecomment-6229479023).
It introduces no protocol requirement, certification, separate tracker, or new
acceptance result. The applicable protocol, selected policy and released API
contracts determine the actual checks.

## Freeze the claim and evaluation context

For each run, record the protected assets, permitted recipients, workload and
delegating principals, tool and peer roles, operator boundaries, trusted issuers
and key-enrollment sources. State the exact claim and required observations at
each boundary before evaluation.

Pin source commits, released package versions and dependency-lock digests.
Record verifier-selected policy, trust inputs and evaluation time separately
from producer assertions. Give every run and attempt an identifier and retain
causal links. Preserve failed and unknown attempts when later attempts succeed.

Unavailable released APIs are `waiting_on_release`, not simulated passes.
A dependency change identifies work requiring reassessment; its digest alone
does not establish compatibility or justify an authorization decision.

## Label the evidence mode

| Mode | What the observation can establish | Boundary |
| --- | --- | --- |
| Synthetic | Deterministic behavior of injected adapters and test instrumentation | No live dispatch or hardware claim |
| Historical replay | Signature/content checks on captured bytes under explicit key pins | Capture time is retained; present freshness and live session authentication are not inferred |
| Same-operator live software | Fresh observed software interaction | Hosts and signers may remain under common control |
| Independently operated live | Observations from separately controlled peers and authenticated enrollment | Independence and enrollment require their own evidence |
| Hardware | The specifically verified hardware claim | Never inferred from software, signatures or multiple hosts |

Classify individual observations as well as the run. One live observation cannot
upgrade synthetic or missing evidence elsewhere. Hardware work remains parked
with [WCM #200](https://github.com/agentrust-io/weight-custody-manifest/issues/200)
pending the existing host/operator prerequisites. Hardware conformance and
release decisions remain with their owners, including
[cA2A #47](https://github.com/agentrust-io/ca2a/issues/47).

## Run the selected implementation

The [current deterministic harness](README.md) documents its own reproduction
command and evidence semantics. The separately reviewed
[released-protocol extension, PR #330](https://github.com/agentrust-io/integrations/pull/330),
documents its exact released dependencies and additional commands. Use the
instructions and lockfile from the selected immutable checkout; do not assume
that unmerged extension files exist on the default branch.

Archive the command, environment, exit status and raw log. For offline packets,
retain the packet digest, explicit public-key pins and how those pins were
obtained. Signature validity does not establish external enrollment. A bare
HTTP refusal status does not establish an authenticated peer response.

This procedure alone establishes no execution result. Contributor-run unit
checks and live execution, if performed, need separately recorded results.

The [offline synthetic reappraisal utility](README.md#offline-synthetic-evidence-reappraisal)
implements current-context and evidence-age comparisons for local retained
deterministic results. It does not implement protocol credential expiry,
live revocation, authenticated storage or complete dependency discovery.

## Pair each refusal with a valid control

| Case | Paired observations |
| --- | --- |
| Workload, key, configuration or version substitution | Authorized baseline and changed-input refusal at the applicable gate |
| Tool or delegated-peer admission | Valid issuer/holder/scope and untrusted issuer, holder or request substitution |
| Response binding | Authenticated response and altered MAC, wrong request/transaction and replay controls |
| Revocation or changed authorization policy | Same otherwise-valid request under acceptable and rejecting current policy/trust state |
| Expiry | Valid signed authorization before expiry and refusal at/after the selected contract's expiry boundary |
| Changed dependency or trust input | Previous evidence remains historical; reappraise affected claims using the changed inputs, retaining a matched unchanged control |
| Egress/disclosure | Permitted recipient/path and forbidden recipient/bypass attempts at the actual egress boundary |
| Missing evidence or timeout | Preserve unavailable/unknown; distinguish pre-dispatch refusal from loss after possible execution |
| Retry | Separate admission and observations for the new attempt; original unknown remains unknown |

For policy, revocation and expiry cases, identify the verifier's evaluation time,
source of policy/trust state and freshness rules. Avoid changing unrelated inputs
between twins. Use controlled time in deterministic tests rather than sleep-based
expiry tests. A historical packet can still have a valid signature after its
authorization expires; signature validity and permission for a new action are
different outcomes.

For dependency changes, identify the affected claim and why reappraisal is
required. A changed version does not automatically mean refusal; reassessment
may establish compatibility. Missing required reassessment cannot be replaced by
an old pass. Preserve original evidence and any withdrawal or replacement event.

The table is an evaluation checklist, not a statement that every row is already
implemented. Record unsupported required cases as incomplete or
`waiting_on_release`, with the specific missing capability.

## Demonstrate that the intended gate matters

For each gate claim, run its negative case and valid twin, then weaken only the
tested gate in an isolated test environment. The relevant negative-case
assertion should fail while the valid twin remains admitted. Restore the gate
and retain the mutation result; weakened controls are never deployed.

Observe construction/dispatch at the actual tested boundary. An initialized zero
counter without observing that boundary is insufficient. Synthetic observation
hooks remain synthetic. Explain any case that cannot safely or independently
exercise its gate rather than counting it as mutation coverage.

## Retain and appraise the results

Record run/attempt IDs, revisions and dependency identities, exact claim,
policy/trust inputs, evaluation time, evidence class, observer/control provenance,
command/log references, expected and observed outcomes, mutation result and
unavailable evidence. Keep authorization, delivery, receipt, admission,
execution, response verification and release separate.

Missing required observations remain unknown/unavailable; demonstrated policy
contradictions are refused. A successful software check does not close #199's
independently operated live, protected inference/disclosure, production
revocation or hardware obligations. Public packets exclude protected payloads,
secrets, device identifiers and low-entropy digests of protected material.

Self-reported confidence, repeated agreement and low output uncertainty cannot
substitute for current authorization or required boundary evidence. Evaluate
the concrete policy and evidence claims independently of response consistency.

Adapter implementation remains with its existing owners. Delegation-composition
design remains with [parent #41](https://github.com/agentrust-io/.github/issues/41).
