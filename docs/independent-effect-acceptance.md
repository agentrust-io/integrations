# Independent effect observation: proposed acceptance procedure

Status: informative design contribution within [#333](https://github.com/agentrust-io/integrations/issues/333)
and [#199](https://github.com/agentrust-io/integrations/issues/199).
This is not an adapter, target deployment, new roadmap or completed live test.
Existing owners retain implementation and runtime/profile placement.

## Bounded claim

Use one disposable marker namespace with synthetic random data. Enroll a target
observer independently of the executor's administrative custody. Record the
executor's authority decision, dispatch, target ingress, durable commit, readback
and client response as distinct observations. A caller's job ID is correlation
data until authenticated evidence establishes its relation to the executor run.

The [#333 discussion](https://github.com/agentrust-io/integrations/issues/333)
identifies Proofable as a dispatch-only candidate. This is a reported candidate
profile, not measured commit-after-revocation behavior. The proposed target run
would distinguish dispatch authorization from a final-commit recheck. Supported
outbound target operations and authenticated job/authority binding remain
unresolved prerequisites in #333.

## Before a live run

The owners select a released runtime/API, target operator, bounded operation,
credentials/capabilities, cleanup policy, trusted observer enrollment, workload
and evidence-retention contract. No account or paid service is activated by
this proposal. The target operation is a synthetic marker, not sensitive data.

Freeze exact software versions, commands, policy/trust inputs and scenario IDs.
Record whether the two systems actually have different operators and control
roots; different hostnames or keys alone do not establish independence.

## Acceptance matrix

All rows below are proposed, not executed measurements.

| ID | Paired case | Observation needed |
| --- | --- | --- |
| EO01 | Valid authority / unreachable authority without authorized fallback | Commit / refusal before effect; incomplete target visibility stays unknown |
| EO02 | Recovery before / after original deadline | Eligible continuation / expired attempt not revived |
| EO03 | Post-dispatch revocation with dispatch-only / final-commit profile | First may commit; second requires refusal if revocation is causally visible before final authorization |
| EO04 | Bound target, marker and job / substituted relation | Correct readback / specific binding refusal or unestablished relation |
| EO05 | Single / duplicate dispatch | Separate ingress and durable-effect counts; deduplication can hide repeated ingress |
| EO06 | Commit and response / commit with lost response | Known target effect in both; response delivery unknown in the second |
| EO07 | Complete bounded observation / unavailable observer or log loss | Supported result / unknown, not inferred zero effects |
| EO08 | Enrolled observation / substituted signer or prior-run receipt | Accepted observation / trust or run-binding refusal |

Use causal barriers for dispatch, revocation observation and final authorization.
Wall-clock ordering alone does not prove that an executor observed revocation.
Record time uncertainty; do not infer a general propagation SLA from one run.
Target readback needs an authenticated relation to the intended operation, not
merely a marker with matching text. An empty log proves no global absence.

## Evaluation protocol and evidence manifest

Before implementing a checker, freeze expected outcomes and the target's known
state. For each row retain a manifest with case/version, runtime and checker
commits, package locks, invocation, run/attempt IDs, synthetic payload identity,
namespace, trust enrollment, observation window, causal events, raw evidence
locations/digests, expected distinctions, evidence class and private exclusions.
Public evidence uses only non-confidential authorized material.

Compare the executor completion report with the independent target result;
neither silently replaces the other. Give a strong stateful comparator the
same observations, time and policy inputs. Keep faults written independently
of checker outputs and hold out mechanisms rather than just random instances.
Report disagreements by authorization, dispatch, commitment and response axis,
legitimate success preserved, unknown outcomes, coverage and operational cost.

Planned mutations disable signer enrollment, run/payload binding, deadline and
observation-completeness checks individually. Each negative has a valid twin
and fails a behavioral assertion when its guard is removed. Reject-all also
fails the positive controls. No mutation trial is claimed executed here.

Local synthetic tests can evaluate the checker contract after scope agreement.
They cannot close independently operated live acceptance, production revocation,
hardware custody or confidential release criteria in #199.

## Literature and contribution boundary

- [Park and Sandhu, UCONABC, 2004](https://profsandhu.com/cs5323_s17/UCON-2004.pdf):
  ongoing controls motivate naming the decision boundary. This procedure adds
  no general continuous-authorization implementation.
- [Herlihy and Wing, Linearizability, 1990](https://cs.brown.edu/people/mph/HerlihyW90/p463-herlihy.pdf):
  histories describe particular operations and objects; admission ordering is
  not automatically target-effect ordering.
- [Lee et al., RIFL, SOSP 2015](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf):
  durable completion and managed effects need atomic coupling. An unrelated
  external target is not made exactly once by an executor replay ledger.
- [RFC 9334, RATS Architecture, 2023](https://www.rfc-editor.org/rfc/rfc9334.html):
  authenticated claims and relying-party trust are separate roles.
- [Zabolotnii, Runtime Assurance Contracts, v2, 16 October 2026](https://arxiv.org/html/2609.39717v2):
  detector coverage and a strong stateful baseline matter more than gate count.

The literature supplies design antecedents. The intended contribution is an
evaluated evidence contract for this bounded workflow, not a new general
authorization architecture. No upstream issue is closed by this document.
