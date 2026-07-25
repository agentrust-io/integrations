# comply54 → TRACE Adapter

Converts a [comply54](https://github.com/comply54/comply54) `ComplianceResult` JSON into a **signed TRACE v0.1 JWT** (Ed25519).

comply54 evaluates AI agent actions against African regulatory frameworks (NDPA 2023, CBN Transaction Controls, KDPA 2019, POPIA, and 9 other jurisdictions). This adapter maps the compliance decision into the TRACE attestation format so the policy outcome becomes a cryptographically verifiable evidence record.

## Conformance Level

**Level 0 (software-only)** — No hardware TEE attestation. The JWT is signed with Ed25519 and carries all required TRACE envelope fields. Hardware attestation fields (`model.weights_digest`, `build_provenance.digest`, `runtime.measurement`) use `sha256:<all-zeros>` canonical Level 0 placeholders.

| Check | Status |
|-------|--------|
| `eat_profile` = `tag:agentrust.io,2026:trace-v0.1` | ✅ |
| `iat` (integer Unix timestamp) | ✅ |
| `subject` (SPIFFE URI) | ✅ |
| `cnf.jwk` with Ed25519 public key | ✅ |
| `policy.bundle_hash` (SHA-256 of sorted pack IDs) | ✅ |
| `appraisal.status` mapped from comply54 decision | ✅ |
| Ed25519 signature binding | ✅ |
| Hardware TEE measurement | ❌ Level 0 — placeholder |

## Decision → Appraisal Mapping

| comply54 `overall` | TRACE `appraisal.status` |
|--------------------|--------------------------|
| `allow` | `affirming` |
| `audit` | `warning` |
| `escalate` | `warning` |
| `deny` | `contraindicated` |

`audit` is an "allow with mandatory trail" outcome — the action proceeds but must be logged. `warning` is the nearest valid TRACE status (action proceeded with a caveat). `none` would suppress the appraisal entirely, which is semantically wrong for an audit outcome.

## Usage

**1. Install dependencies**

```bash
pip install comply54 PyJWT cryptography
```

**2. Generate a comply54 ComplianceResult and save as JSON**

```python
from comply54 import NigeriaFintechCompliance
import json

compliance = NigeriaFintechCompliance()
result = compliance.check(
    "transfer_funds",
    {"amount": 15_000_000, "currency": "NGN"},
    context={"kyc_tier": 3},
)
with open("result.json", "w") as f:
    json.dump(result.model_dump(mode="json"), f, default=str)
```

**3. Convert to TRACE JWT**

```bash
python src/comply54_to_trace.py result.json \
  --agent-id payments-agent \
  --model anthropic/claude-sonnet-4-6
```

Output: `claim.jwt` (signed JWT, compact format) + printed to stdout.

**4. Inspect the JWT payload**

```bash
python -c "
import jwt
payload = jwt.decode(open('claim.jwt').read(), options={'verify_signature': False})
print('eat_profile:', payload['eat_profile'])
print('appraisal:  ', payload['appraisal'])
print('comply54:   ', payload['comply54'])
"
```

**5. Run tests**

```bash
pip install -r integrations/comply54/requirements.txt -r integrations/comply54/requirements-dev.txt
python -m pytest integrations/comply54/tests/ -v
```

All 31 tests should pass — 27 unit/schema tests plus 4 `agentrust-trace-tests` Level 0 conformance tests (TR-ENV, TR-SIG, TR-POL).

## Key Management

By default a fresh Ed25519 key is generated per run (suitable for testing and CI).

For persistent keys, set `TRACE_PRIVATE_KEY_PEM`:

```bash
# Generate a persistent key
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
key = Ed25519PrivateKey.generate()
print(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())
" > signing.pem

export TRACE_PRIVATE_KEY_PEM="$(cat signing.pem)"
python src/comply54_to_trace.py result.json
```

## What is verified

- `eat_profile` is exactly `tag:agentrust.io,2026:trace-v0.1`
- `policy.bundle_hash` is `sha256:` + hex(SHA-256(JSON-sorted pack IDs)) — reproducible from the same comply54 result
- `appraisal.status` matches the comply54 decision using the mapping table above
- `comply54.audit_id` matches the `audit_id` from the source ComplianceResult
- JWT is signed with Ed25519; public key is embedded in `cnf.jwk`

## Limitations

- Hardware attestation fields (`runtime.measurement`, `build_provenance.digest`, `model.weights_digest`) are software-simulated placeholders. Level 1/2 requires running comply54 inside a TEE (AMD SEV-SNP, Intel TDX, or equivalent).
- `transparency` is empty — no SCITT log anchor at Level 0.
- Model identity fields reflect what the caller passes via `--model`. comply54 evaluates policy against the agent's action; it does not independently verify which model ran.

## comply54 extension claims

The JWT carries a top-level `comply54` object with African-regulatory-specific context:

```json
{
  "comply54": {
    "audit_id": "uuid",
    "overall": "deny",
    "jurisdictions": ["NG", "KE", "ZA"],
    "packs_evaluated": ["nigeria/cbn", "nigeria/ndpa", "universal/pii-leakage"],
    "violations": [
      {
        "pack": "nigeria/cbn",
        "regulation": "CBN Transaction Controls",
        "action": "deny",
        "messages": ["CBN NIP cap exceeded: ₦15,000,000 > ₦10,000,000 limit"]
      }
    ]
  }
}
```

### Extension-claim profile

The TRACE core schema (kept as `tests/fixtures/trace-claim.json` — a local regression fixture, not the canonical schema) is `additionalProperties: false` at the root. The `comply54` key is a **private claim** in the sense of RFC 7519 §4.3 — it is not part of the TRACE core envelope and must not be validated against the core schema.

Schema-conformance tests strip the `comply54` key before validating the core fields. Consumers that wish to process the extension claims should do so after verifying the TRACE core fields pass schema validation.

## Repository

[comply54/comply54](https://github.com/comply54/comply54)
