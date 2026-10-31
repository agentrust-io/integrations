# Evidence-driven release gate: composed first-party SOFTWARE federation

**Date:** October 16, 2026
**Scope:** AgenTrust integrations #199, Frequency two-host software laboratory
**Decision:** **Software integration pilot PASS; full independently accepted
confidential workflow gate remains OPEN.**

## Verified execution boundary

The origin first uses released `cmcp-runtime==0.7.0` for `conduit.inspect`
authorization. A separately restricted SSH forced-command peer on the VPS
then challenges the caller and verifies the released
`ca2a-runtime==0.4.0` signed delegation/holder proof against an explicitly
pinned issuer. A persistent SQLite ledger consumes the challenge before any
side effect. The remote peer launches only Frequency Conduit's fixed
network-disabled `inspect` job, observes its completion, and returns the
authenticated released cA2A 0.4.0 response envelope.

The VPS separately signs a TRACE 0.11.0 / TRACE v0.2 Level 0
**software-only** provenance record and companion receipt-binding manifest.
The origin verifies both with the pinned remote Ed25519 key; the semantic
`policy.bundle_hash` remains the hash of the actual scope/repo/root policy,
not a disguised execution artifact. The signed manifest separately binds the
exact request hash, transaction, nonce, job result, start/end receipt hashes,
and TRACE record hash.

**Real sample transaction:**
`live-ca2a-a40f23585ad2451f9c738971ae64c050`

**Pinned replay fixture:** `evidence/live-software-20261016.json`

**Historical TRACE record hash:**
`sha256:f830659f2af40ff74a42b48e04b1a6c544c41f25e9863c18aae56adc70ff77a5`

**Fixture SHA-256:**
`402a8f0cc05bc517d2918e7a49b10051cb60122fcac8909f1a9ed308c12fdc13`

## Adversarial evidence

The live two-host matrix passed **11/11** scenarios on October 16, including
valid control, local cMCP denial, remote untrusted issuer, expired signed delegation, missing TRACE trust,
wrong TRACE public key, mutated credential scope, response MAC alteration,
post-execution receipt loss reported as unknown, a fresh valid replay twin,
and a consumed challenge replay refused by the peer.

The repository unit/mutation suite passed **81/81** on Prometheus,
including signature/refusal controls, offline software TRACE replay and
historical evidence tampering. Source and dependency versions are pinned in
the PR and hash-locked requirements, and the captured packet includes only
a public, non-confidential `inspect` execution.

## Required acceptance outcomes

| Gate | Result | Qualification |
|---|---|---|
| cMCP permission before dispatch | PASS | Released gateway |
| cA2A signed delegation + holder proof | PASS | VPS independently checks proof within same-operator trust domain |
| Remote transport / bounded execution | PASS | Pinned SSH forced command and Conduit sandbox |
| Persistent replay refusal | PASS | SQLite consumed challenge, not hardware anti-replay |
| cA2A authenticated response | PASS | Live source, ephemeral session MAC |
| TRACE signature and companion result binding | PASS | Level 0 signed software evidence |
| Positive / refusal adversarial controls | PASS | Local suite and 11-case live matrix |
| Offline independently runnable signature check | PASS | Public packet; key provenance remains self-asserted |
| External independently operated peer | OPEN | No second organizational trust domain |
| Confidential model/tool execution and disclosure | OPEN | Only a read-only `inspect` job was exercised |
| Independently enrolled revocation/custody | OPEN | No authoritative revocation snapshot or external signer custody |
| Physical TPM / TEE confidential execution | OPEN | No hardware-backed measurement or key release |
| Independent replay by Dinakar | OPEN | Requires another reviewer to perform and record it |
| Maintainer signoff/merge | OPEN | Cannot be self-issued or bypassed |

## Non-equivalence rules

A successful software Level 0 TRACE record proves the pinned software
signing key endorsed its claims and the content was not altered since signing.
It does **not** prove a hardware identity, a confidential runtime, complete
monitoring, independent custody or any claim about a secret not exercised by
this test. Likewise, a positive cA2A response is not proof of independent
organizational acceptance. A missing post-dispatch response is an **unknown
execution state**, never a clean refusal or proof of no side effect.

Historical offline replay validates signatures while deliberately not making
a *freshness* claim. The live cA2A per-occurrence state is non-exportable and
must be freshly exercised to verify the session.

For implementation About, licensing boundaries, protocol/version pinning,
dependency attribution and glossary mapping, see
[REMOTE-CA2A-PEER.md](REMOTE-CA2A-PEER.md), the reproducible packet in
[evidence/](evidence/), and the original [README](README.md).

## Replay-observation qualification

The exact old-request replay row observes a returned status 403 only. Its
original client occurrence has already been consumed, so the matrix does not
verify a second response MAC for it. The row reports
`response_authentication: not-verified`; it is not an authenticated cA2A
refusal claim. A fresh client occurrence reusing the consumed challenge can
provide a separately authenticated refusal control. The historical packet's
peer channel key is also unsigned metadata, as reported by the offline verifier.
