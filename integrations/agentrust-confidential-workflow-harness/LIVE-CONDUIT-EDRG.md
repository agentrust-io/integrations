# Live Frequency Conduit bridge acceptance, October 16 2026

The `harness.conduit_live` bounded adapter performs cMCP 0.7.0 authorization
before dispatching one fixed `inspect` intent to the VPS with the preexisting
Frequency Conduit CLI. That CLI uses restricted-key SSH transport and a
whitelisted, resource-limited, network-disabled worker intent.

The consumer verifies the start and finish receipt hashes, immediate hash-chain
link, session identity, remote node identity, clean worktree, pinned commit,
network-disabled plan, and successful completion. It fails closed to unknown
rather than treating a lost response as refusal or confirmed execution.

Reproduced locally as 45 unit tests passing (six new controls). Live run:

- Transaction: `edrg-632c5f773d8d42d980f59b4dbcaf72fb`
- Result: `observed-live-conduit-inspect`
- VPS commit: `53c3399c1fa74a985cd74de3c40d48ca02e53bfb`
- Start receipt: `24656869ff9decd0bc3fff92f06f8932eb68f14f268b71eb0236cce8c2eedfe5`
- Final receipt: `80474eeaa16bdc78cd6c6bf5bc3f3c146049d74be02c2bd9c7d6c798de8eb2a8`
- Classification: live two-host, same operator; SHA-256 chained software receipts

Run the *optional, host-specific* probe on a configured Prometheus:
`PYTHONPATH=integrations/agentrust-confidential-workflow-harness python -c 'from harness.conduit_live import run; print(run(transaction_id="unique-id", repo="/home/ubuntu/src/integrations", cli="/home/triangulatorium/.local/bin/frequency-conduit"))'`

This bridge does **not** issue a cA2A credential, verify a real cA2A peer
attestation, create a remote cA2A authenticated response, or produce a TRACE
standard-conforming externally attested execution receipt. It also does not
provide independently operated or hardware-backed evidence. The validated
hash-chain alone is not a digital signature and is not tamper proof against
the operator who controls the receipt store. Those distinctions remain release
gates for upstream Issue #199 and should not be elided.
