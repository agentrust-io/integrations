# OpenShell to TRACE

Builds a Level 0 TRACE Trust Record from NVIDIA OpenShell's full OCSF JSONL
export, the effective OpenShell policy, and AGT Agent Control Specification
decisions. It does not claim that imported control-plane logs are hardware
attestation.

Compatibility is tested against NVIDIA OpenShell `v0.0.105`, including its
OCSF v1.7.0 product identity (`OpenShell Sandbox Supervisor`, vendor
`OpenShell`). The adapter also binds every event's `metadata.uid` and product
version to the declared sandbox execution instead of trusting caller metadata.

## Evidence contract

The adapter requires:

- the effective policy bytes from `openshell policy get <sandbox> --full`;
- the corresponding policy revision;
- the ACS manifest bytes used by the governed agent;
- complete OCSF JSONL from `/var/log/openshell-ocsf.*.log` or a durable sink;
- ACS decisions correlated to the same sandbox execution;
- the immutable workload or container-image digest;
- an operator-supplied SPIFFE URI or DID, model identity, and public signing JWK.

Gateway `openshell logs` output is not sufficient for a record. The gateway
keeps a bounded volatile buffer, whereas the JSONL file contains full OCSF
objects and is the evidence this adapter validates and hashes.

## Use

Enable OpenShell OCSF JSON export before the execution:

```bash
openshell settings set my-sandbox --key ocsf_json_enabled --value true
openshell policy get my-sandbox --full > effective-policy.yaml
openshell sandbox get my-sandbox --output json > sandbox.json
```

Copy or continuously ship the OCSF JSONL before its three-day rotation window
expires. Then build the unsigned record:

```python
from agentrust_trace_adapters import OpenShellEvidence, build_openshell_record

evidence = OpenShellEvidence(
    sandbox_id=sandbox["id"],
    policy_revision=str(sandbox["policy"]["revision"]),
    openshell_policy=open("effective-policy.yaml", "rb").read(),
    acs_manifest=open("agent-control.yaml", "rb").read(),
    ocsf_jsonl=open("openshell-ocsf.jsonl", "rb").read(),
    acs_decisions=tuple(acs_decisions),
    capture_start=start_ms,
    capture_end=end_ms,
    capture_complete=True,
    openshell_version=openshell_version,
)

record = build_openshell_record(
    evidence,
    subject="spiffe://example.org/agent/codex",
    model_provider="openai",
    model_id="gpt-5",
    data_class="internal",
    workload_digest=image_digest,
    jwk=public_jwk,
)
```

Pass the result to `agentrust_trace.sign_record`. Signing is deliberately
separate from evidence assembly.

## Reproduce the signed proof

The `demo/` directory contains a release-shaped OpenShell v0.0.105 OCSF fixture,
an effective policy, an AGT ACS manifest, and correlated decisions. After the
adapter package is published:

```bash
pip install agentrust-trace-adapters==0.1.0
python integrations/openshell/demo/build_signed_record.py --output signed-record.json
```

The command builds the imported-evidence record, signs it with an ephemeral
Ed25519 key, verifies the signature with the released `agentrust-trace` package,
and writes the record. The key is intentionally not persisted.

## What the record claims

| TRACE field | Value |
|---|---|
| `origin.kind` | `third-party-control-plane` |
| `origin.producer` | `nvidia-openshell/<version>` |
| `runtime.platform` | `software-only` |
| `appraisal.status` | `none` |
| `policy.bundle_hash` | Exact canonical bundle of OpenShell policy, revision, and ACS manifest |
| `tool_transcript.hash` | Exact canonical envelope of OCSF events and ACS decisions |

OpenShell Docker, Podman, MicroVM, or Kubernetes execution does not by itself
support a hardware TRACE claim. A higher level requires a quote and independent
verification bound to this workload and record.

## Failure behavior

The adapter refuses to emit a record when capture is incomplete, an OCSF line is
malformed or not from OpenShell, either policy layer is absent, the revision is
missing, or the workload digest is unavailable. It never fills those gaps with
placeholders.

## Conformance

The emitted record targets TRACE Level 0:

```bash
pip install agentrust-trace-tests
trace-tests verify --record signed-record.json --level 0
```

For the small upstream surface that would make production collection portable,
see the [vendor-neutral evidence export proposal](upstream-evidence-export-proposal.md).
