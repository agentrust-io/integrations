# ComputeID AgentPassport — TRACE Adapter

Converts ComputeID AgentPassport /verify evidence into a TRACE v0.2-shaped record. ComputeID issues cryptographically signed, independently verifiable identity credentials for AI agents (hybrid RSA-SHA256 + ML-DSA-65). This adapter maps that identity evidence into TRACE's references[] extension mechanism so a TRACE-consuming verifier can incorporate it as third-party evidence.

**What this does NOT claim**: this integration does not pass TRACE conformance at Level 0, Level 1, or Level 2 today. See CONFORMANCE.md for the exact, current, machine-readable result and why each failure is expected given ComputeID's scope. No trace_conformance_level is declared in integration.yaml for this reason.

ComputeID is an identity-issuance system, not an execution-attestation runtime: it does not evaluate policy, run model inference, or execute tool calls, so it does not populate TRACE's `policy`, `model`, `data_class`, or `build_provenance` fields.

The TRACE record itself is genuinely signed — `cnf.jwk` names a real Ed25519 key (`adapter-signing-key.pem` / `adapter-signing-pubkey.pem`), and `signature` is a real Ed25519 signature over the record's canonical JSON, verified by `trace-tests` itself (see CONFORMANCE.md). This is a separate concern from the ComputeID AgentPassport's own RSA + ML-DSA-65 identity keys, which sign the identity evidence this record *references*, not the record itself.

## Run it

Exact, copy-pasteable steps against released packages:

```bash
pip install agentrust-trace-tests==0.5.1
node convert-to-trace.js evidence/<a-fresh-verify-response>.json > trace-record.json
trace-tests verify --record trace-record.json --level 0
```

Expected output: `Result: FAIL (7 checks, 1 failure(s), 0 skipped)` — see CONFORMANCE.md for the full, current, verbatim result, why the one failure is expected, and why this count will legitimately change if run against a bundle old enough to fail freshness (`TR-ENV-002`) — that's correct behavior, not a defect.

## What is verified

A reviewer can reproduce, from this repository alone, with no live dependency on ComputeID's service beyond registering one fresh passport: that a ComputeID `/verify` response is independently checkable via `offline-verifier.js` and the included `ca-cert.pem` with zero network calls once captured (both the classical RSA-SHA256 and ML-DSA-65 signatures are recomputed from raw key/signature/payload bytes in the bundle, not read from the service's own claimed result — verified adversarially against a tampered payload); that converting real evidence into a TRACE record produces the result in CONFORMANCE.md; and that the hash-chained ComputeID audit log is independently verifiable via `verify-audit-chain.js` (requires live database access — documented as the one check that cannot be reproduced from a static bundle alone).

## Maintainer

trustedaicompute-ops (GitHub org) — contact via computeid-backend issues.
