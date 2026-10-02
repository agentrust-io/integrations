# Embodied Action Receipt Fixtures

Fixture-style example for offline verification of embodied-action receipts.

This example complements the cMCP Embodied Action Evidence Profile and the TRACE
`verification.action_receipts` axis. It demonstrates action-level evidence below
a session-level TRACE claim without claiming physical completion, controller
safety, or functional-safety certification.

Related design threads:

- cMCP Embodied Action Evidence Profile: agentrust-io/cmcp#339
- TRACE action-receipt verification axis: agentrust-io/trace-spec#66

## What It Shows

The fixtures cover four verifier outcomes:

| Fixture | Expected result | What it demonstrates |
|---|---|---|
| `valid-chain.json` | `accepted` | A signed, hash-chained controller receipt sequence binds to the TRACE session, cMCP call id, and action reference. |
| `missing-receipt.json` | `missing` | `verification.action_receipts: required` fails when no action receipt is attached. |
| `signature-mismatch.json` | `invalid` | A receipt with a bad Ed25519 signature is rejected. |
| `controller-rejected.json` | `rejected` | A valid signed receipt can prove controller rejection; rejection is evidence, not a verifier failure. |

## Boundary

For embodied AI, `verification.action_receipts: required` means every externally
consequential action has offline-verifiable receipt evidence bound to the
session or cMCP audit `call_id`.

It does not mean TRACE proves:

- physical completion;
- controller safety;
- functional-safety certification;
- that the real world changed as intended.

## Run

```bash
cd embodied-action-receipts
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Verify one fixture manually:

```bash
python verify_receipts.py fixtures/valid-chain.json
```

Regenerate fixtures from the deterministic test key:

```bash
python generate_fixtures.py
```

The deterministic signing seed is public test material. It is only used to make
the committed fixtures reproducible and must never be used in production.
