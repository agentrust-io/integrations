# TRACE Conformance Result

**Result: FAIL at Level 0 — 4 of 8 checks fail.**

This is the real result of running agentrust-trace-tests 0.5.1 against a TRACE record built from an actual, unmodified ComputeID /verify API response (not a hand-built sample). Reproduction steps are in README.md.

## The four failures, and why each is expected

1. **cnf must contain jwk with kty** (2 related findings) — ComputeID passports do not currently bind a proof-of-possession key into the credential. This is a real, genuine gap, tracked in a linked spec issue.

2. **TR-POL-001: policy field is missing or not an object** — expected. ComputeID is an identity-issuance system; it does not evaluate or enforce policy.

3. **TR-APR-001: appraisal is required** — expected. ComputeID does not produce a third-party appraisal or attestation judgment.

## What this result proves

That this adapter's mapping is honest and internally consistent: every failure traces directly to a documented scope boundary (identity issuance, not execution attestation), not to an implementation defect. The two hardest cryptographic checks — classical and post-quantum signature verification — pass, both independently, both adversarially tested (verified true against the genuine ComputeID CA certificate, verified false against a locally-generated fake certificate with a different key).

## Fixed during this test

An earlier draft of convert-to-trace.js used a placeholder eat_profile value. Corrected to the TRACE-required tag:agentrust-io.com,2026:trace-v0.2 before this result was produced.
