# sovereign-agent-connector: usage control across agent delegation

A hospital lets an agent summarize patient records for a clinical purpose, with
processing in France only. The agent delegates the job to a sub-agent, and the
sub-agent picks a model. This example shows the hospital's rule still holding at
that second hop: the French model route is dispatched, the non-French route is
denied before any data moves, and both outcomes land in one signed bundle that a
separate verifier can check offline.

It is an experimental composition called the Agentic Usage Control Profile (AUCP).
It joins existing pieces rather than defining new ones:

| Piece | Used for |
|---|---|
| ODRL-shaped agreement, signed by the data owner | The usage rule: purpose, jurisdiction, destinations |
| [cA2A](https://github.com/agentrust-io/ca2a) delegation credentials | Authority that can only narrow from agent to sub-agent |
| [cMCP](https://github.com/agentrust-io/cmcp) attestation provider and Cedar evaluator | Workload appraisal and the enforce-before-dispatch decision |
| cMCP audit chain and [TRACE](https://github.com/agentrust-io/trace-spec) record | Signed evidence of what was allowed and what was denied |
| TRACE Registry inclusion-proof algorithm, via `trace-verify` | Merkle inclusion proofs over the receipts |

AUCP adds only the joins: a projection of the agreement into policy, bindings
from each receipt to the exact agreement, delegation chain, appraisal and policy,
a dispatch state on every action, and a completeness check so a missing boundary
fails verification. The inventory of those additions is in
[`schemas/aucp-semantic-delta-v0.1.json`](schemas/aucp-semantic-delta-v0.1.json).

## Run it

Python 3.11 or later.

```bash
cd examples/sovereign-agent-connector
pip install -r requirements.txt

# Rebuild both bundles through the real cA2A and cMCP code paths
python scripts/generate_bundle.py vectors/french-healthcare/example-bundle.json \
  vectors/french-healthcare/example-trust-anchors.json
python scripts/generate_live_bundle.py vectors/french-healthcare/cmcp-live-bundle.json \
  vectors/french-healthcare/cmcp-live-trust-anchors.json

# Verify the live bundle with code that imports none of AUCP, cMCP, cA2A or TRACE
python tools/independent_verify.py vectors/french-healthcare/cmcp-live-bundle.json \
  --trust-anchors vectors/french-healthcare/cmcp-live-trust-anchors.json

python -m pytest tests -q
```

The verifier prints:

```text
PASS: AUCP MVE-1 bundle independently verified
workflow: urn:uuid:workflow-fr-health-001
allowed: urn:uuid:action-allowed-001
denied-before-dispatch: urn:uuid:action-denied-001
platform: software-only; hardware-attested=false
```

Trust anchors are kept in a separate file on purpose. The public keys inside a
bundle are metadata; the verifier never accepts them as their own root of trust.

## What is in the folder

| Path | Contents |
|---|---|
| `agentrust_auc/` | Projection, binding, receipt, bundle and verification logic, plus the cMCP adapter. A local module, not a published package. |
| `tools/independent_verify.py` | Clean-room verifier using only the standard library and `cryptography` |
| `scripts/` | Generators for the two committed bundles |
| `vectors/french-healthcare/` | Synthetic bundles and their trust anchors |
| `tests/` | 52 tests: the allow and deny paths, tampering with every signed artifact, substituted trust anchors, and placement checks |
| `profiles/`, `schemas/` | Profile identifiers and the semantic-delta inventory |
| `docs/` | [Start here](docs/START-HERE.md), the [standards-gap analysis](docs/standards-gap.md), the [verifier notes](docs/independent-verifier.md) and two decision records |

Profile identifiers are `https://agentrust-io.com/profiles/aucp/v0.1` for the base
bundle and `https://agentrust-io.com/profiles/aucp/v0.1/cmcp-mve1` for the cMCP
adapter bundle.

## Limits

This is an experiment, not a standard, and no standards body has reviewed it.
Identifiers, fields and fixtures may change. All data is synthetic. The committed
evidence is software-only, so it makes no hardware or geography claim; a placement
assertion is operator evidence that relying-party policy maps to a jurisdiction.
