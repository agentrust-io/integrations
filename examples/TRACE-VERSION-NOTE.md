# The recorded trust records here are TRACE v0.1

Every `*/trace-output/*.json` in this repository, plus
`industrial-embodied-ai/agent-manifest.json`, is the recorded output of a demo run
that happened while the stack emitted **TRACE v0.1**, carrying the profile URI
`tag:agentrust.io,2026:trace-v0.1`.

The stack now emits **v0.2** (`tag:agentrust-io.com,2026:trace-v0.2`). The v0.1
profile URI named a domain this project never controlled, which RFC 4151 does not
permit for a tag URI. See [trace-spec#107](https://github.com/agentrust-io/trace-spec/pull/107).

## Why these were not rewritten

Eleven of them carry a real Ed25519 signature over the record, and the profile URI
sits inside the signed payload. Editing the string while keeping the old signature
would produce a record that **fails verification**: an artifact claiming v0.2 that
no v0.2 verifier would accept. These examples exist to demonstrate verifiable
evidence, so shipping a record that does not verify is worse than shipping one that
is honestly a version behind.

The signing keys are deliberately not committed, so they cannot be re-signed here.

Three further records carry no signature
(`healthcare/{sg-moh,uk-nhs,us-fda-samd}`). Those were held back too, so the
recorded corpus stays internally consistent rather than half-migrated.

## What to do instead

Regenerate them by re-running the examples against the current stack
(`agentrust-trace>=0.5`, cMCP on the v0.2 profile). The regenerated records will
carry the v0.2 profile with a signature that covers it.

Until then, read them as what they are: evidence of runs that happened under v0.1,
still verifiable with `agentrust-trace-tests` 0.3.x.

Documentation in this repository **has** moved to v0.2 and to `agentrust-io.com`,
since nothing signs it.

`industrial-embodied-ai/policy/manifest.json` and `industrial-embodied-ai/catalog.json`
were also held back, for a subtler reason: nothing signs them directly, but their
SHA-256 digests are recorded inside the signed trust record as
`cmcp_policy_bundle_hash` and the catalog hash. Editing a byte of either breaks the
evidence chain even though neither file carries a signature of its own, which
`validate_artifacts.py` catches. They regenerate with the records.
