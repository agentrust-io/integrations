# SOVP integration with TRACE

A command-line adapter that turns a SOVP attestation result into an
Ed25519-signed AgenTrust **TRACE Trust Record**. It maps the caller-supplied
`agentrust` fields into a TRACE v0.2 envelope, signs the record with
`agentrust_trace.sign.sign_record` (JCS pre-image, `cnf.jwk` bound), and writes
JSON that `agentrust-trace-tests` can verify.

What it does **not** claim (see rule 4 in
[CONTRIBUTING.md](../../CONTRIBUTING.md)): it does not certify SOVP or any SOVP
deployment; it does not call non-attested data attested; it infers no attestation
claim it was not given. Every field that would assert a strong guarantee is set
to its weakest honest value — `runtime.platform: software-only`,
`origin.kind: third-party-control-plane`, `appraisal.status: none`,
`build_provenance.slsa_level: 0` — because the bridge transcribes SOVP's
evidence rather than measuring a hardware TEE.

Source, tests, and CI live in the canonical repository:
<https://github.com/litzki-systems/sovp-agentrust-bridge>.

## Run it

Against released packages only:

```bash
pip install litzki-sovp-agentrust-bridge==0.1.1 agentrust-trace==0.10.0 agentrust-trace-tests==0.5.1

# Throwaway local signing key (never commit it):
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem

# Emit a signed TRACE record from the example SOVP attestation:
curl -fsSL https://raw.githubusercontent.com/litzki-systems/sovp-agentrust-bridge/ef5fd2c4b8e105935f183476fd6ed2ea1afb4d8e/integrations/litzki-sovp/examples/sovp-attestation.json -o sovp-attestation.json
litzki-sovp-trace --input sovp-attestation.json --private-key ed25519-private.pem --output sovp.trace.json

# Verify it:
trace-tests verify --record sovp.trace.json --level 0
```

## What is verified

Reproduced on 2026-09-23 in a fresh Windows Python 3.12 environment using
the released bridge 0.1.1, `agentrust-trace` 0.10.0 and
`agentrust-trace-tests` 0.5.1, with the pinned example above. The bridge's
`appraisal.verifier` is a URI. These are exact tested versions, not a claim
that every later release is compatible.

`trace-tests verify --record sovp.trace.json --level 0` passes **8/8, 0
failures** (`TR-ENV`, `TR-SIG`, `TR-POL`). Unlike an unsigned-artifact Level 0,
`TR-SIG` reports **`Ed25519 signature verified`** — the emitted record carries a
real signature bound to `cnf.jwk`, re-verifiable with
`agentrust_trace.verify_record(record, public_key)`.

Level 0 is the honest ceiling: the bridge is `software-only` (no hardware TEE),
which `agentrust-trace-tests` accepts only at Level 0.

Reproduction is run continuously by the source repository's CI
(`.github/workflows/ci.yml`, Python 3.11 and 3.12): `pytest` plus the
`trace-tests verify --level 0` sequence above.

## Conformance CI

This is a manifest-only listing: the integration's code, tests, and conformance
workflow live in the source repository
(<https://github.com/litzki-systems/sovp-agentrust-bridge>), whose CI runs the
`pytest` + `trace-tests verify --level 0` sequence above on every push and pull
request across Python 3.11 and 3.12. Per CONTRIBUTING, vendor integrations keep
their integration-specific conformance workflow in their own repository.
