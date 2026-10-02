# Frequency Agent Execution Assurance integration with TRACE

Frequency Agent Execution Assurance consumes standalone TRACE Trust Records as externally supplied evidence. The public adapter verifies the record with a caller-supplied trusted issuer key, fingerprints the exact record and key files, and projects selected verified fields into a claim-limited Frequency external-evidence record.

## Run it

Against the public v0.1.0 release:

```bash
git clone --branch v0.1.0 --depth 1 \
  https://github.com/altrudev/Frequency-Agent-Execution-Assurance.git
cd Frequency-Agent-Execution-Assurance

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r adapters/agentrust-trace/requirements.txt

python adapters/agentrust-trace/demo.py
pytest -q adapters/agentrust-trace/tests
```

The adapter uses `agentrust-trace==0.10.0`. Its tests exercise the released verifier with a valid signed record, a tampered record, and a wrong caller-supplied trusted key.

## What is verified

A reviewer can reproduce that:

- a valid standalone TRACE Trust Record verifies with an independently supplied JWK;
- the exact TRACE record and trusted-key files are SHA-256 fingerprinted in the projection;
- tampering fails closed;
- a wrong trusted key fails closed;
- the projection records an explicit claim ceiling rather than promoting TRACE verification into an external-effect claim.

## What this integration does not claim

The public adapter does not expose Frequency Core and does not authorize or execute an agent action. It does not independently verify hardware attestation, transparency-registry inclusion, the content behind a transcript hash, or any external state mutation.

The Apache-2.0 license applies to the public TRACE adapter directory. Frequency Core and the broader enforcement product remain separately licensed proprietary software.
