# Proposal for OpenShell: stable governance evidence export

Status: issue-ready design note; not submitted upstream without NVIDIA maintainer
guidance or a contributor vouch.

## Problem

OpenShell already produces the security-relevant inputs needed by external
governance systems, but collecting a complete, mutually correlated evidence set
requires several commands and direct access to a rotating file inside the
sandbox. Consumers should not have to infer whether a capture is complete or
whether a policy, workload, and OCSF stream describe the same execution.

This proposal does not add TRACE or AgenTrust logic to OpenShell. It adds a
vendor-neutral export contract that TRACE, SIEM, compliance, and incident
response tooling can consume.

## Proposed surface

Add a command such as:

```text
openshell sandbox evidence export <sandbox> --since <timestamp> --output <directory>
```

The export directory would contain:

```text
manifest.json
effective-policy.yaml
events.ocsf.jsonl
```

`manifest.json` should provide:

- a stable format version;
- sandbox immutable ID and display name;
- OpenShell product version;
- effective policy revision and SHA-256 digest;
- immutable workload/container image digest when available;
- capture start and end in Unix milliseconds;
- an explicit `complete` boolean and a machine-readable incompleteness reason;
- OCSF schema version and event count;
- SHA-256 digests for every exported file;
- trace/span correlation identifiers when available.

## Required invariants

1. The policy is the effective policy for the exported sandbox and revision,
   not merely the caller's input file.
2. Every OCSF event has `metadata.uid` equal to the manifest sandbox ID.
3. Every event product identity and version agree with the manifest.
4. `complete: true` is emitted only when the exporter can account for the full
   requested interval without rotation, buffer loss, or collection failure.
5. Secrets, credentials, authorization headers, and URL query strings remain
   excluded under OpenShell's existing OCSF redaction rules.
6. File digests cover exact bytes; consumers choose their own signing and
   attestation scheme outside OpenShell.

## Why this belongs upstream

OpenShell is the only component that can authoritatively state the effective
policy revision, sandbox identity, product version, workload identity, and
capture completeness. External adapters can hash these values, but must not
invent them.

The proposal complements the portable log-collection work in NVIDIA/OpenShell
issue #1922 and the OCSF trace-correlation work in issue #2640. It does not
require either issue to adopt TRACE.

## Acceptance tests

- export an interval containing allowed and denied activity and validate every
  JSONL line against OpenShell's vendored OCSF v1.7.0 schemas;
- verify every manifest digest from exact output bytes;
- rotate or truncate the source log during export and assert `complete: false`;
- change the effective policy and assert both revision and digest change;
- attempt cross-sandbox event substitution and assert verification fails;
- scan fixtures for known credential and query-string canaries.

## Reference consumer

`agentrust-trace-adapters` consumes this evidence as a TRACE Level 0
third-party-control-plane record. It deliberately reports `software-only` and
`appraisal.status: none`; hardware assurance still requires independently
verified attestation evidence.
