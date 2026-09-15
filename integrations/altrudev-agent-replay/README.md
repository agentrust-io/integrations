# Agent Replay integration with TRACE

Agent Replay consumes standalone TRACE Trust Records as supplementary evidence during AI-agent incident reconstruction. It verifies the TRACE record against a caller-supplied trusted issuer key, then records a bounded verification summary alongside the reconstructed timeline.

## Run it

From the Agent Replay repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[trace]'

agent-replay verify-trace session.trace.json \
  --trusted-key issuer-public.pem

agent-replay reconstruct \
  examples/refund-750/events.jsonl \
  --trace-record session.trace.json \
  --trace-key issuer-public.pem \
  --json
```

The adapter uses the released `agentrust-trace` package for TRACE schema/profile, signature, and freshness verification. It does not enable embedded-key trust; the issuer key is supplied independently.

## What is verified

A reviewer can reproduce that:

- malformed or invalid TRACE records are rejected by the released TRACE verifier;
- the caller-supplied trusted key is used rather than `cnf.jwk` as the trust root;
- a successfully verified record is attached under `trace_evidence`;
- the verification scope explicitly does not claim hardware-attestation verification, transparency-ledger verification, or transcript-to-incident binding.

## What this integration does not claim

Agent Replay does not independently verify TEE evidence or SCITT/registry inclusion. It does not yet accept cMCP RuntimeClaim envelopes. It also does not claim that an incident input is the transcript committed by `tool_transcript.hash` unless a separate transcript-binding verifier establishes that relationship.

## Conformance

The marketplace submission starts at TRACE conformance level 0. A higher tier or level should only be requested after the AgenTrust conformance suite has been run against the exact released package versions used by the integration.
