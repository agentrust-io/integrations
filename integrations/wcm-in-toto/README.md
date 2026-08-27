# WCM ↔ in-toto Attestation Statement v1

Wraps a Weight Custody Manifest as an in-toto Statement so it can travel through
supply-chain tooling that already exists: OCI referrers, DSSE envelopes, Rekor
entries, GitHub attestations, `slsa-verifier`. None of that machinery has to
learn a new document format.

`predicateType: https://wcm.agentrust-io.com/attestation/manifest/v1`

## The design decision worth reading

**The predicate embeds the signed manifest verbatim.** It does not summarize it.

A DSSE envelope is signed by whoever built the attestation. A WCM manifest is
jointly signed by the builder and the custodian, and under a sovereign profile by
a quorum. Those are different trust roots answering different questions.

If this module flattened custody terms into predicate fields, a consumer who
verified the DSSE signature would be trusting the attestation builder's
transcription of those terms rather than the parties who agreed them, and the
jointly-signed original would be gone. So the manifest goes in whole, signatures
included, and the DSSE layer is transport.

There is a `predicate.summary` block for convenience. It is never the authority:
`verify_statement` reads only `predicate.manifest`, and a test asserts that
tampering with the summary changes no verdict.

## What verification actually checks

`verify_statement` answers two questions and reports them separately, so a caller
cannot collapse them by accident:

| Question | Field | Failure means |
|---|---|---|
| Does the subject digest equal the manifest's `weights_hash`? | `subject_matches` | A genuine manifest stapled to a different artifact |
| Do the builder and custodian signatures verify against keys you trust? | `manifest_verified` | The custody agreement is not the one you think |

`trusted` is both. It also carries `notes`, the non-blocking advisories
`verify_manifest` raises about what a manifest actually protects (an open base,
a symmetric BYOM posture). Dropping those would let a statement read as promising
more than the manifest delivers.

A `predicate.manifest_hash` binds the predicate to the exact document bytes, so
an edited `manifest` block is caught before signature checking even begins.

**The DSSE envelope signature is deliberately not checked here.** That is the
envelope tooling's job and it answers a different question, namely who built this
attestation. Conflating the two is precisely how a consumer ends up trusting a
transcription.

## What this does not do

It moves a document. It does not extend WCM's guarantee, add attestation, or turn
an unverified manifest into a verified one. A consumer that checks the DSSE
signature and stops has verified who built the envelope and nothing about
custody.

Confidential computing does not hold against an operator who physically owns the
hardware (WCM `SPEC.md` §3.6). Wrapping a manifest in in-toto changes that not at
all.

## shake256 manifests are refused

WCM permits sha256 and shake256 for `weights_hash`. in-toto subjects are keyed by
algorithm name and the digest set has no registered shake256 entry, so a shake256
manifest raises rather than being filed under `sha256`, where every verifier
would compare the wrong bytes. Re-issue with sha256 to publish as an attestation.

## Run it

```bash
pip install weight-custody-manifest

# wrap
python wcm_in_toto.py wrap manifest.json --name example-8b > statement.json

# verify; supply the keys you trust for builder and custodian
python wcm_in_toto.py verify statement.json --key builder.pub --key custodian.pub
```

`verify` exits non-zero when the statement is not trusted, so it drops into CI
without a wrapper script. Keys are raw Ed25519 public key material in hex or
base64url.

As a library:

```python
from wcm_in_toto import build_statement, verify_statement

statement = build_statement(manifest, name="example-8b")
outcome = verify_statement(statement, context)
if not outcome.trusted:
    raise SystemExit(outcome.reason)
```

`--name` is required. WCM identifies weights by digest on purpose, so that
renaming a file changes nothing, which means a manifest carries no artifact name
for an in-toto subject to use. Supply the one your distribution channel uses.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
