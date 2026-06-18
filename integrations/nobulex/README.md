# Nobulex integration with TRACE (external execution evidence)

Nobulex is a Python SDK that emits Ed25519-signed receipts for agent actions. Each receipt is JCS-canonical (RFC 8785) and carries `action_ref = SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))` as a content-derived identifier.

This positions Nobulex receipts as external execution evidence in the sense described in trace-spec #34: signed assertions from a non-gateway authority, bound to a specific call by `action_ref`, independently verifiable against the issuer public key.

**What this integration does:** generates verifiable per-action receipts from Python agents that can be attached as `external_execution_evidence` on cMCP audit entries.

**What it does not claim:** Nobulex receipts are not TRACE Trust Records. They are per-action signed assertions that a verifier can optionally check alongside a Trust Record, as described in trace-spec #34.

## Run it

```bash
pip install nobulex
```

```python
from nobulex import Agent

agent = Agent("my-agent")
receipt = agent.act("tool_call", scope="resource:read")

assert receipt.verify()          # Ed25519 signature over JCS-canonical fields
print(receipt.action_ref)        # SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))
print(receipt.signature)         # hex-encoded Ed25519 signature
print(receipt.signer_public_key) # hex-encoded Ed25519 public key
```

## What is verified

Running the above produces a receipt where:
- `receipt.verify()` returns `True` — signature is valid over the canonical field set
- `receipt.action_ref` is a 64-character hex string — SHA-256 over JCS-canonical JSON
- The receipt can be independently verified by any party holding `signer_public_key`

## Links

- PyPI: https://pypi.org/project/nobulex/
- npm: https://www.npmjs.com/package/@nobulex/core
- Repo: https://github.com/arian-gogani/nobulex
- Demo: https://nobulex.com/demo
