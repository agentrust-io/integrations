# SOVP integration with TRACE

A command-line adapter that turns a SOVP attestation result into an
Ed25519-signed AgenTrust **TRACE Trust Record**. It maps the caller-supplied
`agentrust` fields into a TRACE v0.2 envelope, signs the record with
`agentrust_trace.sign.sign_record` (JCS pre-image, `cnf.jwk` bound), and writes
JSON that `agentrust-trace-tests` can verify.

Since 0.2.0 the record can point at the SOVP verdict document. Given the full
`SovereignAttestation` document and its URL, the bridge adds exactly one
`references` entry (TRACE v0.2 §3.1.2): `rel: infrastructure-trust`, `id` the
document URL, `resolver: urn:sovp:litzki-systems-llc`, and `digest` = SHA-256
over the RFC 8785 bytes of the whole document. The entry is a pointer, not
evidence, and changes no assurance field.

What it does **not** claim (see rule 4 in
[CONTRIBUTING.md](../../CONTRIBUTING.md)): it does not certify SOVP or any SOVP
deployment; it does not call non-attested data attested; it infers no attestation
claim it was not given; it does not verify the SOVP document's signature and does
not copy the SOVP verdict into the record. Every field that would assert a strong
guarantee is set to its weakest honest value — `runtime.platform: software-only`,
`origin.kind: third-party-control-plane`, `appraisal.status: none`,
`build_provenance.slsa_level: 0` — because the bridge transcribes SOVP's
evidence rather than measuring a hardware TEE.

What a record proves, and where that proof stops, field by field:
[evidence boundary](https://github.com/litzki-systems/sovp-agentrust-bridge/blob/935ace0cca4a94d0a966cd6a13c132246c31d7ce/docs/evidence-boundary.md).

Source, tests, and CI live in the canonical repository:
<https://github.com/litzki-systems/sovp-agentrust-bridge>.

## Run it

Against released packages only:

```bash
pip install litzki-sovp-agentrust-bridge==0.2.0 agentrust-trace==0.11.0 agentrust-trace-tests==0.6.2

# Throwaway local signing key (never commit it):
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem

# Emit a signed TRACE record from the example SOVP attestation. The example
# embeds a copy of the live SOVP document, so the record carries a references entry:
curl -fsSL https://raw.githubusercontent.com/litzki-systems/sovp-agentrust-bridge/935ace0cca4a94d0a966cd6a13c132246c31d7ce/integrations/litzki-sovp/examples/sovp-attestation.json -o sovp-attestation.json
litzki-sovp-trace --input sovp-attestation.json --private-key ed25519-private.pem --output sovp.trace.json

# Verify it:
trace-tests verify --record sovp.trace.json --level 0

# Recompute the digest of the referenced SOVP document:
python -c "import hashlib,json,rfc8785;d=json.load(open('sovp-attestation.json'))['sovp_attestation_document'];print('sha256:'+hashlib.sha256(rfc8785.dumps(d)).hexdigest())"
```

Records are fresh for 24 hours after `iat`; generate a new one for each check.

## What is verified

Release 0.2.0 at commit `935ace0`, installed from PyPI into a fresh
environment on 2026-10-11 with `agentrust-trace` 0.11.0 and
`agentrust-trace-tests` 0.6.2: `trace-tests verify --record sovp.trace.json
--level 0` reports **PASS (15 checks, 3 skipped)**, with `TR-SIG` reporting
**`Ed25519 signature verified`**. The three skips are two optional fields and the
affirming-appraisal requirement, which applies from Level 1. The digest in
`references[0]` matches an independent recomputation
(`sha256:cc57734e5b23eea6b1183ab1b97c0833368977660ae3f64c3be92bd4d0a97f45`).
With `agentrust-trace` 0.10.0 and `agentrust-trace-tests` 0.5.1 the same record
passes **8/8**. These are exact tested versions, not a claim that every later
release is compatible.

The AgenTrust maintainers reproduced release 0.1.1 independently on 2026-09-23
in a fresh Windows Python 3.12 environment. Release 0.2.0 has not yet been
reproduced by a maintainer.

`trace-tests verify` checks the signature against the key the record carries in
`cnf.jwk`, so a record signed with any key passes Level 0. A relying party
verifies with `agentrust_trace.verify_record(record, trusted_key)`, which rejects
keys it does not already trust; the source repository's tests show both outcomes.

Level 0 is the honest ceiling: the bridge is `software-only` (no hardware TEE),
which `agentrust-trace-tests` accepts only at Level 0.

## Conformance CI

This is a manifest-only listing: the integration's code, tests, and conformance
workflow live in the source repository
(<https://github.com/litzki-systems/sovp-agentrust-bridge>), whose CI runs
`pytest`, the `trace-tests verify --level 0` sequence above and a digest
recomputation on every push and pull request, across Python 3.11 and 3.12,
against both the pinned versions and the latest releases. Per CONTRIBUTING,
vendor integrations keep their integration-specific conformance workflow in
their own repository.
