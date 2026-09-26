# OpenShell bundle verifier: candidate v1

Unreleased consumer-side proposal for
[NVIDIA/OpenShell #2745](https://github.com/NVIDIA/OpenShell/issues/2745).
The field layout below is proposed for producer review. It is not a published
OpenShell export format. Tests and the example use synthetic events and ephemeral
software keys. They do not run OpenShell or use hardware evidence.

## Run the synthetic acceptance cases

From the repository root, in a development environment:

```console
python -m pip install -e packages/agentrust-trace-adapters pytest
python -m pytest packages/agentrust-trace-adapters/tests/test_openshell_bundle.py -q
python packages/agentrust-trace-adapters/examples/synthetic_openshell_bundle.py
```

These source-tree commands test the package code. The verifier ships in
`agentrust-trace-adapters` 0.1.1 and later; 0.1.0 does not include it. The
producer contract it checks is still a candidate, so its shape can change before
an upstream exporter exists.

## Inputs and trust

Import `verify_bundle` from `agentrust_trace_adapters.openshell_bundle`. Supply
immutable bytes for `manifest.json`, `manifest.sig`, and the two evidence files.
The caller separately supplies trusted Ed25519 public keys indexed by key ID,
the expected sandbox ID, and the expected capture start/end. Resolve those keys
through the deployment authority outside the bundle. A key embedded in an export
is never a trust anchor. The API reads no paths and makes no network calls.

`manifest.sig` is a UTF-8 JSON object with exactly these fields:

```json
{"algorithm":"Ed25519","key_id":"gateway-1","signature":"BASE64_SIGNATURE"}
```

The signature covers the exact original `manifest.json` bytes. The verifier does
not reserialize or canonicalize them. The key ID is a lookup hint into the
caller's trust map; the algorithm is fixed. Duplicate JSON keys and non-finite
constants are rejected. Unrecognized manifest versions or fields are rejected.

The manifest has exactly these fields (digest placeholders below are illustrative):

```json
{
  "format": "agentrust.openshell-evidence-candidate.v1",
  "sandbox_id": "sandbox-a",
  "openshell_version": "synthetic",
  "policy_revision": "policy-1",
  "capture_start": 100,
  "capture_end": 200,
  "complete": true,
  "incomplete_reason": null,
  "event_count": 3,
  "sequence": {"epoch": "boot-1", "first": 10, "last": 12},
  "files": {
    "effective-policy.yaml": "sha256:EXACT_FILE_DIGEST",
    "events.ocsf.jsonl": "sha256:EXACT_FILE_DIGEST"
  }
}
```

Capture times are inclusive epoch milliseconds. Integer fields are nonnegative
integers at most 2^53-1; booleans do not count as integers. Each event has an
in-range `time`, `metadata.uid` equal to the sandbox ID, and
`metadata.product.version` equal to the manifest version. `metadata.sequence`
is a nonnegative integer when present. The verifier checks these binding fields,
not the complete OCSF schema. The example's events are minimal synthetic objects,
not purported schema-valid OpenShell exports.

Both files are required and the policy bytes are nonempty. Hashes cover exact
bytes, including line endings. The event count covers all JSONL lines; blank or
malformed lines are rejected. Extra files are rejected. Manifests and signatures
are separate API arguments and are not entries in `files`.

## Coverage contract

The producer signs `sequence.first` and `sequence.last` from its authoritative
emit counters for this interval. It must not derive them merely from whichever
events survived export. The nonempty epoch names one counter lifetime. A restart
or uncertain mapping between the requested time interval and the counter range
requires `complete: false` and a reason. Use `sequence: null` when bounds cannot
be supplied. The consumer cannot verify the honesty of those producer claims.

A reset spanning epochs needs separate bundles; this candidate does not combine
counter lifetimes. The signed epoch is a producer assertion, not independent
proof that events all came from one process lifetime.

| Result | Meaning |
|---|---|
| `verified_complete_over_range` | Nonempty, unique, ordered sequences cover every number in the signed bounds, and the producer reports complete |
| `provable_gap` | Authenticated file contents omit numbers inside the signed bounds |
| `not_established` | Empty events, missing bounds or sequence values, or the producer reports incomplete without a detectable gap |

Malformed inputs, wrong sandbox/interval, invalid signatures, digest or count
mismatches, duplicates, reversed ordering and out-of-range values raise
`BundleError`. These are rejected bundles, not a fourth coverage grade. A returned
result records that signature and file-integrity checks passed.

Removing an event from an existing signed export fails the file hash. To isolate
the sequence check, the tests also sign exports whose file hashes correctly
cover a missing first, middle or last event while retaining the original signed
bounds. Those return `provable_gap`. This avoids a hash failure masking a broken
sequence check. Bounds are checked arithmetically without allocating a list for
the entire sequence range.

## Limits

A valid signature authenticates the key holder's assertions, including policy
revision and completeness. It does not prove the policy was enforced, that all
actions emitted events, or that a signing gateway is honest. Events suppressed
before sequence assignment remain invisible. A trusted gateway can also lie
about its bounds. Contiguous numbers alone cannot prove interval coverage.

The caller owns key rotation/revocation, deployment authorization, freshness,
replay tracking, resource limits and key-to-sandbox permissions. Expected sandbox
and interval checks prevent substitution for a different request; replay of the
same authorized interval is not prevented. Parse and input-size limits should be
applied before processing untrusted large bundles. No protected payload or real
credential is used by the acceptance cases. No redaction or credential-canary
claim is made for a producer that has not been run.

This candidate omits workload identity, configuration revision, schema-version
negotiation and trace/span metadata from the broader issue proposal. Adding those
requires agreement with the producer and a format revision. It does not emit
TRACE records or turn gateway assertions into hardware-attested evidence.

## Validation record (2026-09-20)

Python 3.12, with the repository's hash-pinned `requirements/adapters.txt`:

```console
python -m pytest packages/agentrust-trace-adapters/tests integrations/openshell/test_demo.py -q
# 106 passed (50 new bundle cases, 55 existing package cases, 1 existing demo)
```

The wheel and source distribution built successfully. The synthetic example ran
and returned a verified single-event range marked `evidence: synthetic`.
Ruff and `git diff --check` passed.

Temporary mutations independently disabled 11 checks. Every mutation made the
new acceptance suite fail; the original source was restored afterward.

| Disabled check | Failing cases |
|---|---:|
| Gateway signature verification | 8 |
| Exact file digest match | 5 |
| Expected sandbox | 1 |
| Event sandbox | 1 |
| Event product version | 1 |
| Event capture interval | 1 |
| Event sequence bounds | 1 |
| Event count | 1 |
| Unique, ordered sequences | 2 |
| Missing numbers in the signed range | 4 |
| Producer incomplete status | 1 |

This is targeted mutation evidence, not exhaustive fault coverage. The test
producer signs through the same cryptography library that verifies signatures;
it does not use verifier serialization helpers. No live producer run, OCSF schema
conformance, hardware acceptance or independent implementation comparison was run.
