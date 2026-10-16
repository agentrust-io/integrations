# About: bounded cA2A + cMCP + TRACE software federation experiment

This is a **public reference integration**, built for AgenTrust integrations
Issue #199. It combines the independently published
`cmcp-runtime==0.7.0`, `ca2a-runtime==0.4.0`, and
`agentrust-trace==0.11.0` APIs with Frequency Conduit's separately operated
*software process* on another host. It does not incorporate proprietary OPAQUE,
Anthropic, or other confidential-computing software, and does not claim
institutional endorsement by those organizations.

The repository's root `LICENSE` is Apache-2.0. External runtime packages are
separate dependencies, not re-licensed by this submission: the installed
distribution metadata identifies `cmcp-runtime` and `ca2a-runtime` as MIT,
`agentrust-trace` as Apache-2.0, and `cryptography` as
Apache-2.0 OR BSD-3-Clause. Their own upstream source, copyright notices and
licenses remain authoritative. Frequency first-party private authority,
production deployment configuration, service keys, and any unpublished
software are not transferred or relicensed by the integration.

## What is actually implemented

1. The originating host calls the **published cMCP gateway** to authorize
   `conduit.inspect` and creates one cA2A `PendingResponse` occurrence.
2. The remote VPS forced SSH command issues an expiring cA2A challenge and
   publishes a *pinned software channel public key*. The caller uses signed
   cA2A `DelegationCredential` and an Ed25519 holder-possession proof bound
   to the remote audience, challenge, capability and **hash of the exact
   authenticated request envelope**.
3. The remote peer independently verifies the chain against a
   **pre-enrolled issuer key**, local capability scope and holder possession.
   A persistent SQLite replay ledger consumes the challenge before dispatch.
4. Only the fixed, network-disabled Frequency Conduit `inspect` intent is
   permitted. No arbitrary shell command is exposed by the peer.
5. The remote response is authenticated using published
   `ResponseProducer`/`PendingResponse.verify` primitives and binds the
   source transaction, request hash, nonce, reported Conduit receipt hashes,
   commit and exit status.
6. The remote process signs a **TRACE v0.2 Level 0 software record** and an
   independently Ed25519-signed companion manifest binding the exact request
   and Conduit observations. The origin verifies the TRACE signature and
   companion manifest with an **out-of-band pinned remote signing key**. The
   manifest is separate so TRACE's `policy.bundle_hash` continues to describe
   the actual static access policy rather than falsely representing a receipt.

The remote endpoint is deployed in a *separate virtual environment* using a
SHA-256 hash-locked dependency set; it is reachable only as an SSH forced
command using a dedicated restricted key, not a new public TCP listener.

## Evidence and claims NOT established

- Hardware TEE/TPM attestation, confidential inference, protected model
  weights, protected key release or confidential data disclosure.
- Independent organizational custody: the test's source host, remote host,
  issuer enrolment and verifier signing key are all under one operator.
- Live signed revocation checking, real external delegated peers, and
  authoritative validation of the claimed software image identity.
- A successful read-only `inspect` job is not proof of actual mediated
  sensitive-data access or a confidential AI model computation.
- The TRACE record is Level 0 software evidence and uses the documented
  software-mode placeholder URIs, not a hardware RIM or transparency proof.
- Approval, merger, or standards conformance across every scenario in Issue
  #199. Those require Dinakar's independent matrix and authorized maintainer
  review on the exact frozen commit.

## Reproduction and deployment controls

The upstream CI runs unit tests against hash-pinned package releases without
any external SSH key. For a live controlled laboratory, an operator must
separately provision **on the VPS** the channel X25519 private key, challenge
HMAC secret, issuer public key, TRACE Ed25519 signing key and replay database
in `~/.local/state/frequency-ca2a-peer`. Secrets must be mode 0600 and the
directory mode 0700. The matching channel and TRACE public keys must be
pinned independently **on the originating host**. The forced SSH command
executes `python -m harness.remote_peer_service` and has no PTY, port
forwarding or unrestricted shell. Do not commit any operator keys or
deployment configuration. Do not assume that generated test keys are
independent attestation authorities.

A live test needs the separately deployed pinned remote peer, the local
operator identity, and a valid existing Conduit `inspect` repository. Use
`run_remote_ca2a_live.py` only in the recorded first-party lab environment.
**Never** retry an uncertain `execute` occurrence automatically: a lost
response can conceal a completed side effect.

## Evidence-driven release gate

The complete production gate remains **BLOCKED** until both protocol-specific
remote positive and negative tests and independent third-party replay pass,
the signature/issuer and revocation custody are independently controlled,
and the acceptance scope includes mediated tool calls, uncertain deliveries,
release/disclosure and valid control/mutation twins. Mark every evidence item
as synthetic, same-operator live software, or independently anchored hardware;
never promote a lower class because its checks are green.

## Technical glossary

| Project term | Standard equivalent |
|---|---|
| Frequency Conduit node | Authorized remote execution worker and RPC endpoint |
| EDRG | Evidence-driven release acceptance gate |
| Governance admission | cMCP policy decision / tool-call authorization |
| Delegation | Signed capability credential / delegated authorization |
| Holder proof | Proof of possession of an Ed25519 delegation key |
| cA2A channel | Per-request X25519-derived authenticated response channel |
| Peer appraisal | Verification of issuer, subject, scope and possession |
| Receipt binding | Cryptographic commitment to request and observed result |
| TRACE Level 0 | Software-signed provenance record without hardware attestation |
| Evidence manifest | Signed, canonicalized statement of observed execution facts |
| Receipt hash chain | Tamper-evident append-only log linkage, not independent custody |
| Replay ledger | Persistent single-use nonce/challenge consumption database |
| Unknown delivery | Indeterminate execution outcome after lost confirmation |
| Mutation twin | Positive control paired with one deliberately weakened safety guard |
| Independent verifier | Separately controlled party reproducing acceptance evidence |

## Private lab live run and evidence export

The operator supplies a local mode-0600 JSON config with SSH key **path**,
issuer and holder private key **paths**, pinned public keys, permitted repo,
and SSH hostname (never the private key contents). The following commands
create a fresh occurrence and an offline packet in an operator-controlled
private directory:

```sh
python run_remote_ca2a_live.py --config /private/client.json --evidence-out /private/new-evidence.json
python run_remote_ca2a_matrix.py --config /private/client.json --output /private/new-matrix.json
```

The signed, non-sensitive example packet and verification instructions are
available in [evidence/](evidence/). The public fixture intentionally excludes
private keys, live SSH credentials, session challenge and raw authorization
payloads; the reviewer must enroll the public key through a distinct trust
channel. The exported packet is useful for *historical software signature
verification*, not live session-MAC replay or hardware assurance.

## Expiry and revocation enforcement boundary

The origin now issues transaction-specific signed cA2A credentials with a
**60-second default expiry** and a five-second clock-skew allowance. An
expired credential was refused by the remote VPS in the 11-case live matrix.
The released SDK unit/mutation suite also proves signed revocation and stale
revocation-snapshot refusal with valid twins. **No live independently supplied
revocation snapshot has been enrolled on the VPS**, because a fresh-looking
operator-authored snapshot must not be treated as independent revocation
authority. That remains a separate release gate.
