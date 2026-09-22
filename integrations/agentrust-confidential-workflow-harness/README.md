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

The public result must never contain protected payloads, secrets, device IDs or
low-entropy digests of protected material.

Missing main-lineage observations remain `unavailable`; adapters must explicitly
report `not_applicable`. A forbidden recipient takes precedence over permission.
The deterministic software-version gate uses [SemVer 2.0.0](https://semver.org/)
with a fixed minimum of `1.0.0`: `1.0.0-rc.1` is below that minimum, and build
metadata does not change precedence. Invalid versions are refused.
