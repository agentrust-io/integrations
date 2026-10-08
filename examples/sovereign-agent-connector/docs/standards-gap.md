# Agentic Usage Control Profile: standards-gap analysis

**Date:** 13 August 2026  
**Status:** Experimental. This is the analysis behind the example in this folder, not a standards submission.

## Decision requested

Determine whether existing standards already provide an interoperable way to bind all of the following into one independently verifiable decision:

1. a resource owner's negotiated usage agreement;
2. recursively attenuated authority across dynamic agent delegation;
3. workload and placement appraisal;
4. policy enforcement before each protected dispatch; and
5. portable, complete evidence of the resulting execution trajectory.

The internal standards review concludes that the component capabilities exist but their cross-standard binding, deterministic projection, stable evidence joins, and execution-completeness rules do not exist as an adopted profile. External reviewers are asked to confirm, narrow, or overturn that conclusion; their response does not block internal progress.

If that hypothesis is confirmed, the proposed contribution is an **Agentic Usage Control Profile (AUCP)**. It is a composition and conformance profile, not a new contract protocol, authorization token, attestation envelope, policy engine, or transparency log.

## Why a decision is needed now

The original Sovereign Agent Connector design correctly identified the end-to-end problem but proposed several bespoke artifacts. Subsequent standards review found substantial overlap:

- Dataspace Protocol and ODRL already express and negotiate usage agreements.
- OAuth and MCP authorization already protect the first resource boundary.
- AAT, cA2A, and AGT already provide forms of attenuated agent authority.
- RATS and EAT already define evidence appraisal and signed attestation results.
- SCITT and TRACE Registry already address signed statements and independently verifiable registration receipts.

Building the original artifact set before validating the remaining gap would risk creating parallel standards. The next decision is therefore about the missing joins, not implementation ownership.

## Concrete scenario and acceptance test

A French healthcare data owner permits a lead agent to summarize a protected dataset subject to these constraints:

- purpose: clinical summarization;
- processing jurisdiction: France;
- onward delegation: permitted only with equal or narrower authority;
- model/tool destination: approved processors satisfying the placement policy;
- evidence: every protected dispatch must be independently verifiable.

The lead agent delegates summarization to a child agent. At runtime the child considers two model endpoints:

1. an approved endpoint appraised as operating in France;
2. an EU-branded endpoint actually appraised outside France.

Required result:

- The French route is allowed only after the agreement, authority chain, workload/placement result, and local policy intersect successfully.
- The non-French route is denied before any protected payload is dispatched.
- Both decisions produce signed receipts bound to the same agreement, delegation lineage, workflow, action, appraisal, enforcement decision, and registration receipt.
- A verifier with no account at the resource owner, agent operator, cloud provider, cMCP runtime, or evidence issuer can reproduce the verdict from a captured bundle and an explicit trust policy.

## Composition map

```text
Resource owner
    |
    | Dataspace Protocol / ODRL Agreement
    v
Root agent authority
    |
    | AAT semantics or mapped cA2A delegation
    v
Child agent authority -------- RATS Attestation Result / EAT claims
    |                                      |
    +------------------+-------------------+
                       v
        Deterministic effective-policy projection
                       |
                       v
             cMCP-compatible PEP decision
                 /                 \
          deny before dispatch     allow + dispatch
                 \                 /
                       v
           Agentic Usage Control Receipt
                       |
                       v
              TRACE / SCITT evidence
                       |
                       v
             Independent offline verifier
```

The implementation names illustrate one conforming path. They are not normative dependencies.

## Standards coverage and provisional gap classification

Classification:

- **Covered:** no AUCP-specific semantic addition is expected.
- **Binding needed:** the component exists, but an interoperable cross-standard mapping or invariant appears to be missing.
- **Validation needed:** the apparent gap may already be addressed by an existing profile or active draft.

| Required property | Existing basis | What is already covered | Provisional remaining need | Class |
|---|---|---|---|---|
| Usage agreement negotiation | Dataspace Protocol, IDS usage contracts | Offers, agreements, transfer state, machine-readable policy | Identify the exact agreement and project its applicable terms into agent execution | Binding needed |
| Usage-policy expression | ODRL 2.2 and domain profiles | Permissions, prohibitions, duties, constraints, inheritance | Deterministic agentic profile for purpose, destination, jurisdiction, onward delegation, and evidence duties | Binding needed |
| First resource authorization | OAuth, RAR, token exchange, MCP authorization | Audience-bound access, scopes/details, resource metadata, token handling | Preserve usage obligations beyond the initially authorized resource | Binding needed |
| Recursive agent authority | IETF AAT draft v01, cA2A credentials, AGT delegation chains | Proof of possession, parent binding, narrowing, depth, tool/argument constraints, offline chain verification, fail-closed unknown constraints | Bind the root authority to a negotiated agreement and carry inherited usage obligations/evidence requirements | Binding needed |
| Workload identity | SPIFFE, WIMSE work, DID methods, Agent Manifest | Principal and workload-key identification | Define identifier normalization and bind the executing workload to the agreement and authority leaf | Binding needed |
| Workload appraisal | RATS architecture and Attestation Results | Separation of evidence, verifier, appraisal policy, result, and relying-party policy | Require action-level reference to the exact appraisal result and policy | Binding needed |
| Location and jurisdiction | EAT location claims or profiled extensions plus operator evidence | A signed carrier for location-related claims | Define provenance, freshness, assurance, residual operator trust, and versioned mapping from location/region to legal jurisdiction | Binding needed |
| Policy decision interoperability | AuthZEN; local deterministic policy engines | PDP/PEP decision exchange or local evaluation | Define the intersection algorithm and digest without mandating a particular PDP | Binding needed |
| Agent message transport | A2A/cA2A, potentially ANP | Discovery and message transport; cA2A signed provenance | Carry stable agreement, authority, workflow, and action references without making transport the authority source | Binding needed |
| Tool/model dispatch boundary | MCP/cMCP | Tool invocation; cMCP can enforce before dispatch and emit TRACE | Standardize verified external context, `not_dispatched` evidence, and action binding | Binding needed |
| Signed execution evidence | TRACE and other signed records | Integrity and provenance of individual events | Define stable joins and the minimum complete evidence path for a protected action | Binding needed |
| Transparency receipts | SCITT RFC 9943; TRACE Registry implementation | Signed statements, registration receipts, inclusion, subject-linked sequences, and independent verification | Map evidence registration to SCITT; define execution-boundary completeness outside SCITT rather than another log | Binding needed |
| Status and revocation | OAuth status mechanisms, SSF/CAEP, issuer status statements | Changes in authorization or security state | Define freshness and offline evaluation rules for the instant of action | Binding needed |
| End-to-end conformance | No adopted profile identified yet | Component-level conformance only | Test the conjunction and reject valid-but-unjoinable or incomplete artifact sets | Candidate genuine gap |

## Standards-gap conclusion

### Decision

**The standards gap is confirmed, narrowly.**

No reviewed adopted standard or active draft binds a negotiated resource-owner usage agreement to recursive agent authority, workload/placement appraisal, pre-dispatch enforcement, and an independently verifiable complete action trajectory. Each component standard intentionally stops at its own boundary. AUCP is justified only as the profile that defines the projections, bindings, joins, failure states, and conformance tests across those boundaries.

This conclusion justified a minimal experiment. It does not by itself justify a standards submission or production API changes.

### Primary-source findings

| Source | What the source establishes | Boundary relevant to AUCP | Finding |
|---|---|---|---|
| [Dataspace Protocol 2025-1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/HEAD/) | Stable schemas and protocols for publishing data, negotiating Agreements, and accessing data in a dataspace | Does not specify recursive agent authority, workload appraisal, action-level PEP evidence, or a portable cross-runtime trajectory | Reuse agreement negotiation; add a binding profile |
| [ODRL Information Model 2.2](https://www.w3.org/TR/odrl-model/) | W3C Recommendation for permissions, prohibitions, duties, constraints, policy inheritance, and domain profiles | An ODRL evaluator determines policy-rule performance; ODRL does not define agent-token attenuation, runtime dispatch proof, attestation joins, or evidence completeness | Define an ODRL agentic-usage profile and deterministic projection, not a new policy language |
| [AAT draft v01](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01) | Active Internet-Draft for offline-verifiable, proof-of-possession agent delegation with depth, lifetime, capability, cryptographic-linkage, and fail-closed extension constraints | Its capability model is task/tool and argument authority. It does not bind a Dataspace/ODRL Agreement, establish placement, record PEP dispatch state, or define an execution evidence graph | Use or map AAT semantics; define agreement and obligation bindings as extensions/profile rules |
| [RATS architecture, RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) | Separates Attester, Evidence, Verifier, appraisal policy, Attestation Results, and Relying Party policy | It appraises an entity; it does not connect the result to a resource agreement, delegated action, enforcement decision, or trajectory completeness | Reuse the appraisal model and bind the exact result/policy to each protected action |
| [EAT, RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) | Standards-track JWT/CWT attestation claims, including location, accuracy, timestamp, and age | Claim trust follows verifier policy; a location claim is not inherently trustworthy and legal jurisdiction is not derived by the format | Profile provenance/freshness and derive jurisdiction under relying-party policy; do not invent a location envelope |
| [SCITT architecture, RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) | Signed Statements, transparent registration receipts, independently verifiable inclusion, and subject-linked sequences | Registration proves issuer attribution/inclusion, not statement accuracy. Subject sequences can aid completeness for submitted statements, but cannot prove that every required runtime boundary emitted a statement | Align TRACE receipts with SCITT and define AUCP boundary-completeness rules outside the log |
| [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | OAuth-based protected-resource discovery, resource indicators, audience validation, and prohibition on token passthrough | Protects the MCP server boundary and requires separate downstream tokens; it does not propagate usage agreements or prove downstream policy enforcement | Complement MCP; never replace its authorization layer |

### Exact missing normative surface

The gap is not "agent sovereignty" generally. It is these six interoperable rules:

1. **Agreement-to-authority binding:** identify which negotiated agreement constrains the root agent authority and verify that the subject/key is entitled to exercise it.
2. **Usage-obligation attenuation:** preserve non-removable duties, prohibitions, purposes, destinations, and evidence requirements through every delegated authority derivation.
3. **Agreement-to-PEP projection:** deterministically translate applicable ODRL terms and appraised attributes into the policy evaluated for a particular protected action.
4. **Action-level evidence joins:** bind the exact agreement, authority leaf/chain, appraisal result, policy version, decision, and dispatch state to one action and workflow.
5. **Boundary completeness:** define which agent-to-agent and agent-to-tool/model boundaries must emit evidence, and make absence distinguishable from a valid allow or deny.
6. **Cross-artifact conformance:** reject artifact sets that are individually valid but stale, widened, substituted, replayed, inconsistent, unjoinable, or incomplete.

### Claims AUCP must not make

- It does not replace a legal agreement or create liability merely through a signature.
- It does not make an EAT location claim true or allow hardware attestation to prove geography.
- It does not make SCITT registration prove the truth or real-world completeness of submitted statements.
- It does not supersede OAuth/MCP resource authorization.
- It does not standardize another generic delegation token while AAT is active.
- It does not claim adopted-standard status for AAT; v01 remains an active Internet-Draft.

## The candidate AUCP contribution

AUCP should add only what is necessary to compose the standards above:

1. **Agreement projection rules**: a versioned, deterministic mapping from applicable agreement/ODRL terms to normalized usage constraints.
2. **Authority binding rules**: a binding from the agreement and its subject to the root authority, plus monotonic propagation through the agent authority chain.
3. **Effective-policy invariant**: a deterministic intersection of usage constraints, delegated authority, resource policy, and appraised runtime attributes.
4. **Stable join identifiers**: agreement, workflow, action, authority-chain, appraisal, policy, and evidence identifiers that can be cross-checked without trusting a collector.
5. **Usage Control Receipt**: a signed normalized verdict referencing existing artifacts by digest rather than duplicating or replacing them.
6. **Dispatch-state semantics**: an interoperable distinction among not evaluated, denied before dispatch, dispatched, failed after dispatch, and unknown.
7. **Evidence-completeness rules**: the minimum signed path required for a verifier to decide that no required boundary is silently absent.
8. **Conformance vectors**: allowed, denied, stale, widened, substituted, replayed, unjoinable, and incomplete trajectories.

No new primitive should enter AUCP unless the decision record states why existing work cannot provide it.

## Binding invariant

For every protected action `a` in workflow `w`:

```text
usage_constraints(a) = project(applicable_agreement(a))

agent_authority(a) = attenuate(
    agreement_bound_root_authority(a),
    delegation_chain(a)
)

runtime_policy(a) = intersect(
    usage_constraints(a),
    agent_authority(a),
    local_resource_policy(a),
    appraised_runtime_attributes(a)
)

permit(a) only if requested_action_and_destination(a) satisfies runtime_policy(a)
```

An independently verifiable verdict additionally requires:

```text
agreement(a)
AND valid_agent_authority_chain(a)
AND authority_is_within_agreement(a)
AND workload_and_placement_appraised(a)
AND policy_enforced_before_dispatch(a)
AND complete_signed_evidence_path(a)
AND required_registration_receipts_present(a)
```

Every projection, intersection, and artifact reference must identify a versioned algorithm or profile and a digest.

## Open questions for reviewers

### Data-space and usage-policy reviewers

1. Does Dataspace Protocol or an IDS profile already specify how an agreement follows a dynamically selected, recursively delegated agent execution path?
2. Under IDS semantics, is each cross-organization sub-agent a new consumer/participant, or can it remain a workload of the original participant?
3. How should `DISTRIBUTE` and `NEXT_POLICY` map to recursive agent authority and runtime-selected processors?
4. At what point does a model endpoint become a recipient rather than a processor or tool of the contracting participant?
5. Is the desired outcome prevention before dispatch, evidence for contractual enforcement, or both?
6. Should AUCP be an ODRL profile, a Dataspace Protocol profile, or a liaison profile referencing both?

### IETF AAT authors

1. Can an AAT root token be bound normatively to an external negotiated usage agreement by identifier and digest?
2. Can inherited duties such as evidence production, retention, and onward-use restrictions be represented and made non-removable?
3. Does the chain model distinguish resource-owner usage constraints from the agent principal's delegated capabilities?
4. Are stable workflow/action and appraisal references within scope, extension points, or intentionally out of scope?
5. Can a verifier prove monotonic preservation of jurisdiction and purpose constraints without defining a competing token format?

### RATS/EAT and SCITT reviewers

1. What evidence and appraisal-result profile is appropriate for an attributable but not hardware-proven placement claim?
2. How should freshness, provenance, measurement method, and residual operator trust be represented?
3. Is legal jurisdiction best derived by relying-party policy rather than asserted directly by the attester?
4. Can a SCITT registration receipt bind the enforcement receipt while preserving independent verification of the referenced evidence graph?
5. What completeness claim, if any, can SCITT support beyond inclusion of submitted statements?

### Counsel and governance reviewers

1. What does a cryptographic agreement receipt prove, and what must it explicitly not claim about legal assent or liability?
2. What binds an agent or workload key to authority to act for a legal entity?
3. Is an accountable operator assertion adequate for the intended sovereignty control when hardware cannot prove geography?
4. Which agreement, governing-law, DPA, or audit artifact must the technical receipt reference?

## Explicit no-build list

Until a reviewer demonstrates a concrete deficiency, do not build:

- a new agreement-negotiation protocol;
- a generic digital or legal contract format;
- a third general agent attenuation token;
- a raw attestation envelope or proprietary geography proof;
- a new OAuth authorization server;
- a new policy-decision protocol;
- a new agent discovery protocol;
- a new transparency-log architecture;
- a generic cross-organization trust score.

## Minimal validating experiment

The experiment answers one question: can the existing standards be joined without inventing a new core primitive?

1. Create a Dataspace Protocol-style ODRL Agreement for synthetic French health data.
2. Map a cA2A delegation chain to AAT semantics.
3. Supply a RATS Attestation Result/EAT claim set bound to the child workload key.
4. Project and intersect the agreement, authority, appraisal, and local policy.
5. Attempt one permitted French endpoint and one prohibited non-French endpoint.
6. Prove the prohibited payload was not dispatched.
7. Emit one Usage Control Receipt for each decision.
8. Register the receipts through the existing TRACE Registry path using SCITT-aligned terminology.
9. Assemble a portable bundle and reproduce both verdicts offline.

Success requires at least 80% of the semantics to come from existing standards or existing AgenTrust components. Any new field must be classified as a projection, binding, join, normalized verdict, dispatch-state marker, or completeness mechanism.

## Minimal experiment execution log

### MVE-0: composition oracle

**Status:** Passed on 13 August 2026

Implemented:

- ODRL-shaped, owner-signed French-health agreement and deterministic projection;
- cA2A's actual `DelegationCredential` and `verify_chain` implementation;
- RATS-shaped, verifier-signed appraisal bound to the cA2A leaf workload key;
- deterministic policy intersection and an observable dispatch boundary;
- one allowed French route and one non-French denial with `not_dispatched` evidence;
- signed Usage Control Receipts binding agreement, authority chain, appraisal, policy, workflow, and action;
- TRACE Registry's actual inclusion-proof verifier over the two receipts;
- offline verification of signatures, joins, decisions, boundary completeness, and inclusion;
- adversarial tests for agreement tampering, delegation widening, appraisal substitution, false dispatch state, missing boundaries, missing receipt, and bad inclusion proof.

Bounded interpretation: MVE-0 validates the composition rules and offline-verifier shape. Its ODRL agreement and RATS appraisal are standards-shaped synthetic fixtures, and its enforcement receipt is produced by the experiment's deterministic PEP rather than the live cMCP server. MVE-1 replaces the deterministic PEP with live cMCP enforcement.

### MVE-1: live adapter composition

**Status:** Passed in software-only mode on 13 August 2026.

**Evidence:** `vectors/french-healthcare/cmcp-live-bundle.json`

Completed:

1. Verified AUCP context is injected into an adapter around cMCP's real policy evaluator.
2. The approved French resource is dispatched; cMCP's enforcing `PolicyDeny` stops the US resource before dispatch.
3. cMCP's real append-only audit chain records both actions and dispatch states.
4. cMCP's real ephemeral `SigningKey` and TRACE generator produce a signed session claim bound to the audit root, tip, length, and Cedar policy hash.
5. Signed per-action adapter bindings join the AUCP receipt, cMCP audit entry, policy bundle, and TRACE record.
6. Offline verification checks every join and fails on audit, TRACE, binding, or completeness tampering.

Limitations at the MVE-1 checkpoint (the clean-room verifier below addresses the
third item; the committed vector remains software-only):

- Placement appraisal remains a synthetic, verifier-signed RATS-shaped fixture and the TRACE platform is honestly `software-only`.
- At the time, cMCP 0.4 imported a deprecated Cedar backend. The example now runs on cmcp-runtime 0.7 and ca2a-runtime 0.4 without that dependency.
- At this checkpoint, the clean-room verifier had not yet reproduced the bundle.

### MVE-2: clean-room independent verifier

**Status:** Passed locally on 13 August 2026; external reproduction pending.

`tools/independent_verify.py` imports no AUCP, cMCP, cA2A, TRACE, or registry
implementation. It independently verifies the complete MVE-1 bundle using the
standard library and Ed25519 from `cryptography`.

It reproduced:

- allowed: `urn:uuid:action-allowed-001`;
- denied before dispatch: `urn:uuid:action-denied-001`;
- platform: `software-only`;
- hardware-attested: `false`.

The independent-verifier tests cover the positive reproduction and
six fail-closed mutations across agreement, delegation, registry proof, dispatch
state, TRACE summary, and binding completeness.

This is a second implementation inside the project. Confirmation by an independent
party is still open.

## Requested review outcome

Each reviewer should return one of these outcomes with citations or concrete counterexamples:

- **Gap confirmed:** no existing profile provides the end-to-end binding and conformance property.
- **Partially covered:** identify the existing profile and the smallest remaining delta.
- **Already solved:** identify the specification sections and at least one interoperable implementation demonstrating the complete property.
- **Problem not validated:** no buyer workflow requires dynamic delegation and runtime-selected downstream processors under a continuing usage agreement.

The preferred outcome is the smallest truthful delta, including no new project if existing standards already solve the problem.
