# Independently replayable software-signature evidence

The accompanying `live-software-20261016.json` is an **actual** Prometheus →
VPS software execution packet generated October 16, 2026. It contains a
TRACE v0.2 Level 0 record signed with the VPS's Ed25519 software key, a separate
signed companion manifest bound to the cA2A request hash, and hashes of the
Frequency Conduit start and completion receipts. It does **not** contain
private keys, raw cA2A holder proofs, decrypted confidential data or the VPS
network address.

Packet file SHA-256:

`402a8f0cc05bc517d2918e7a49b10051cb60122fcac8909f1a9ed308c12fdc13`

## Offline verification

Use the hash-locked released dependencies from the repository root. Then from
the harness directory:

```sh
python verify_remote_peer_packet.py \
  --packet evidence/live-software-20261016.json \
  --trace-public 2c6ba06dde1a1a7dc8c9676a7c38de76c3f2df6268413cc27779bc6eb0c2d7f1 \
  --issuer-public 880a6aa8cd1976f69176cb1a095b5deb8449579d253b14003fc14ff9d983ed02 \
  --peer-public 69a7a6092973975edd92b2a836704a5c90c462825e69a08d20996e795a854d3d
```

**Trust warning:** The three public keys above are disclosed *by the same
operator that controls both hosts*. They allow anyone to independently
recompute and check the signatures, but do not establish externally enrolled
identity, independent key custody, or hardware attestation. Reviewers must
authenticate the keys through a separate trusted channel before using them
as externally trusted identities.

Offline replay deliberately disables **current-age** enforcement to validate
a historical signed record. This cannot demonstrate *current* nonce freshness
or reproduce the cA2A session MAC: the official `PendingResponse` refuses
export or reuse of its ephemeral state by design. Live validation must instead
rerun the peer interaction, with a new challenge and nonce. Signatures prove
that the pinned software signer endorsed the recorded claims, **not** that an
external observer independently measured the job or confidential execution.
The underlying Conduit receipt log remains under the same operator.

See [About, licensing, glossary and assurance boundaries](../REMOTE-CA2A-PEER.md).
