# Frequency Agent Execution Assurance integration with TRACE

Frequency Agent Execution Assurance consumes standalone TRACE Trust Records as externally supplied evidence. The public TRACE adapter verifies the record with a caller-supplied trusted issuer key, fingerprints the exact record and key files, and projects selected verified fields into a claim-limited Frequency external-evidence record.

The public repository now also includes an executable conformance evaluator for authority-to-execution binding, trusted independent observation, required evidence, signed closure, and claim ceilings. That evaluator is a separate public assurance surface; it does not change this marketplace integration's declared TRACE role of `record-consumer`.

## Reproduce the current public boundary

Tested public commit:

`2b40cc45965e1feb33c91b58b54a3c41de6038bf`

```bash
git clone https://github.com/altrudev/Frequency-Agent-Execution-Assurance.git
cd Frequency-Agent-Execution-Assurance
git checkout 2b40cc45965e1feb33c91b58b54a3c41de6038bf

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt -r adapters/agentrust-trace/requirements.txt

pytest -q tests adapters/agentrust-trace/tests adapters/thrixel-world/tests
python -m conformance.demo
```

At this commit the combined public suite contains 28 passing tests.

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

- intent, authority, and execution binding;
- exact authorized-request digest;
- authority validity window;
- independently supplied trusted observer identity;
- Ed25519 observer attestation;
- execution-to-observation effect correlation;
- required evidence references;
- signed closing commitment;
- claim ceilings that fail closed to `NOT VERIFIED`.

The first concrete workload adapter is a non-executing Thrixel/world reference adapter. It demonstrates how a pinned external workload can be bound into the same conformance contract while leaving credentials, vendor execution, publishing, financial actions, and Frequency Core outside the public repository.

The Thrixel reference adapter is not a TRACE conformance claim and does not imply endorsement or certification by Thrixel or AgenTrust.

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
