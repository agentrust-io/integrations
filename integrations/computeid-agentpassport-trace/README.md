# ComputeID AgentPassport — TRACE Adapter

Converts ComputeID AgentPassport /verify evidence into a TRACE v0.2-shaped record. ComputeID issues cryptographically signed, independently verifiable identity credentials for AI agents (hybrid RSA-SHA256 + ML-DSA-65). This adapter maps that identity evidence into TRACE's references[] extension mechanism so a TRACE-consuming verifier can incorporate it as third-party evidence.

**What this does NOT claim**: this integration does not pass TRACE conformance at Level 0, Level 1, or Level 2 today. See CONFORMANCE.md for the exact, current, machine-readable result and why each failure is expected given ComputeID's scope. No trace_conformance_level is declared in integration.yaml for this reason.

ComputeID is an identity-issuance system, not an execution-attestation runtime: it does not evaluate policy, run model inference, or execute tool calls, so it does not populate TRACE's policy or appraisal fields. It also does not currently bind a proof-of-possession key (cnf/JWK) into the credential.

## Run it

Exact, copy-pasteable steps against released packages and a real, already-captured ComputeID production evidence bundle:

```bash
pip install agentrust-trace-tests
node convert-to-trace.js evidence/opaque-diligence-demo-fresh.json > trace-record.json
trace-tests verify --record trace-record.json
```

Expected output: Result: FAIL (8 checks, 4 failure(s), 0 skipped) — see CONFORMANCE.md for the full result.

## What is verified

A reviewer can reproduce, from this repository alone, with no live dependency on ComputeID's service: that evidence/opaque-diligence-demo-fresh.json is a genuine, unmodified ComputeID /verify response, independently checkable via offline-verifier.js and the included ca-cert.pem with zero network calls; that converting this real evidence into a TRACE record produces the exact result in CONFORMANCE.md; and that the hash-chained ComputeID audit log is independently verifiable via verify-audit-chain.js (requires live database access — documented as the one check that cannot be reproduced from a static bundle alone).

## cnf / proof-of-possession gap

TRACE requires cnf with a JWK kty for proof-of-possession binding. ComputeID passports do not currently carry this. Tracked as a separate spec question, since it touches how TRACE could represent our existing DPoP-based proof-of-possession model.

## Maintainer

trustedaicompute-ops (GitHub org) — contact via computeid-backend issues.
