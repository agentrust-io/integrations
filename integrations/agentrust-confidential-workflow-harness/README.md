# Confidential Workflow Acceptance Harness

A deterministic software harness for issue #199. It keeps authorization, delivery,
receipt, admission, execution, response verification and release outcomes separate
and preserves unavailable evidence instead of inferring success from dispatch.

## Scope of this PR

This initial implementation provides:

- a fixed harness core;
- machine-readable manifest and result schemas;
- deterministic software adapters;
- paired valid controls and weakened-gate mutation proofs;
- explicit `waiting_on_release` handling;
- branch-preserving observations for retries;
- causal provenance fields (`caused_by`) on observations.

It does **not** claim cMCP or cA2A conformance, live-peer acceptance, hardware
attestation, or completion of the full software milestone.

## Reproduce

```bash
python -m unittest discover -s tests -v
```

The deterministic adapter records the package release targets that will be used
when protocol-specific adapters are wired:

- `cmcp-runtime==0.5.0`
- `ca2a-runtime==0.2.0`

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
Retry observations record authorization from the shared synthetic inputs in
their own lineage; they do not replace the main path's evidence.

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
