<p align="center">
  <img src="https://raw.githubusercontent.com/altrudev/Frequency-Agent-Execution-Assurance/main/frequency-agent-execution-assurance-logo.png" alt="Frequency Agent Execution Assurance" width="720" />
</p>

# Frequency Agent Execution Assurance integration with TRACE

Frequency Agent Execution Assurance consumes standalone TRACE Trust Records as externally supplied evidence. The public TRACE adapter verifies the record with a caller-supplied trusted issuer key, fingerprints the exact record and key files, and projects selected verified fields into a claim-limited Frequency external-evidence record.

The public repository also includes an executable conformance evaluator, portable signed evidence bundles, and bounded reference adapters for external workloads. Those surfaces are separate from this marketplace integration's declared TRACE role of `record-consumer`.

## Reproduce the current public boundary

Current public release:

`v0.2.0`

Exact release commit:

`146a51a724a3dcb1afc21cc8d7955abc61bfdb83`

```bash
git clone --branch v0.2.0 --depth 1 \
  https://github.com/altrudev/Frequency-Agent-Execution-Assurance.git
cd Frequency-Agent-Execution-Assurance

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt -r adapters/agentrust-trace/requirements.txt

pytest -q tests adapters/agentrust-trace/tests adapters/thrixel-world/tests adapters/aya-workcell/tests
python -m conformance.demo
```

At this release the combined public suite contains 55 passing tests.

The TRACE adapter uses `agentrust-trace==0.10.0`.

## TRACE verification scope

A reviewer can reproduce that:

- a valid standalone TRACE Trust Record verifies with an independently supplied JWK;
- the exact TRACE record and trusted-key files are SHA-256 fingerprinted in the projection;
- tampering fails closed;
- a wrong trusted key fails closed;
- the projection records an explicit claim ceiling rather than promoting TRACE verification into an external-effect claim;
- `signing_key_runtime_binding_verified` is explicitly `false`.

That last field is deliberate. A valid TRACE signature is not promoted into proof that the signing key is independently bound to the runtime measurement or attestation named by the record.

## Public execution-conformance surface

Separately from TRACE record consumption, the public repository now provides a reference evaluator that checks:

- complete intent and run-schema binding into signed closure;
- intent, authority, and execution correlation;
- exact authorized-request digest;
- authority validity window;
- independently supplied trusted observer identity;
- observation ordering after execution;
- Ed25519 observer attestation;
- execution-to-observation effect correlation;
- required evidence references;
- signed closing commitment;
- claim ceilings that fail closed to `NOT VERIFIED`.

## Portable evidence bundles

The public `frequency.portable-evidence-bundle.v1` surface can package an execution-evidence run for offline verification while keeping trust roots external to the bundle.

A valid outer bundle signature does not upgrade invalid inner execution evidence. Nonce, adapter, source-commit, issuer and replay-context mismatches fail closed.

## Reference workload adapters

The public repository includes:

- a non-executing Thrixel/world adapter that binds a pinned workload profile without enabling vendor execution, publishing or financial actions;
- an AYA workcell adapter that maps AYA Score, Lease, CapabilityReport and Receipt into the Frequency evidence model while preserving AYA's research-runtime and claim boundaries.

Neither reference adapter changes this integration's TRACE conformance claim or implies vendor endorsement/certification.

## Public repository boundary

Release `v0.2.0` also removes unrelated runtime code that had entered the original public repository and adds a regression gate that restricts tracked content to the intended Frequency Agent Execution Assurance surface.

This cleanup changes the public repository boundary; it does not change the TRACE role from `record-consumer`.

## What this integration does not claim

The public adapter does not expose Frequency Core and does not authorize or execute an agent action.

It does not independently establish:

- hardware attestation validity;
- signing-key-to-runtime-measurement binding;
- transparency-registry inclusion;
- the content behind a transcript hash;
- that a third-party tool call occurred;
- that an external state mutation occurred;
- vendor certification or marketplace verification beyond the status assigned by AgenTrust.

The Apache-2.0 license applies to the public TRACE adapter directory. Frequency Core and the broader enforcement product remain separately licensed proprietary software.
