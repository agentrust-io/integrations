# DecisionAssure → TRACE Adapter

Converts a [DecisionAssure](https://github.com/a1k7/DecisionAssure-Runtime-Governance) JSON trace into a **TRACE v0.1 compliant** claim (JSON and signed JWT).

## Conformance Level

**Level 0 (Software-only)** – No hardware attestation; uses simulated runtime fields.

| Check | Status |
|-------|--------|
| `eat_profile`, `iat`, `subject` | ✅ |
| `cnf.jwk` with Ed25519 | ✅ |
| `policy.bundle_hash` valid digest | ✅ |
| Passes `trace-tests verify` | ✅ (see below) |

## Usage

```bash
pip install -r requirements.txt
python da_to_trace.py decisionassure_trace.json
trace-tests verify --record claim.json

Output

claim.json – JSON claim that passes trace-tests
claim.jwt – signed JWT (Ed25519) for production use
Example

bash
$ python da_to_trace.py bigmae_decisionassure_execution_permitted-3.json
✅ Wrote claim.json
✅ Wrote claim.jwt

$ trace-tests verify --record claim.json
TRACE Conformance Report -- Level 0
Result: PASS
Limitations

Hardware attestation fields are placeholders (software‑simulated).
Not yet multi‑agent delegation or full A2A transcripts.
Maintainer

a1k7
