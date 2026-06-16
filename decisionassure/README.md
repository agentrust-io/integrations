# DecisionAssure → TRACE Adapter

Converts a [DecisionAssure](https://github.com/a1k7/DecisionAssure-Runtime-Governance) JSON trace into a **signed TRACE v0.1 JWT** (Ed25519) that includes all required claims.

## Conformance Level

**Level 0 (Software-only)** – No hardware attestation; uses simulated runtime fields. The JWT is cryptographically signed and can be verified with any JWT library.

| Check | Status |
|-------|--------|
| `eat_profile`, `iat`, `subject` | ✅ |
| `cnf.jwk` with Ed25519 | ✅ |
| `policy.bundle_hash` valid digest | ✅ |
| Signature binding | ✅ (Ed25519) |

## Usage

1. Install dependencies:
   ```bash
   pip install -r requirements.txt

2. Run the adapter:

'''bash
python da_to_trace.py decisionassure_trace.json > claim.jwt
The JWT is written to claim.jwt and also printed to stdout.
Verify the JWT payload (example using Python):

bash
python -c "import jwt; print(jwt.decode(open('claim.jwt').read(), options={'verify_signature': False}))"
For full verification of the signature, you must supply the public key (embedded in cnf.jwk). The JWT structure conforms to TRACE v0.1.
Key Persistence (Important)

By default, when TRACE_PRIVATE_KEY_PEM is not set, the adapter generates a new ephemeral Ed25519 key on every run. This means:

The resulting JWT is cryptographically signed and can be verified against the cnf.jwk embedded in the claim.
However, the private key is lost after the run, so the signature cannot be independently re-verified later (e.g., by an auditor).
For production use, set the environment variable TRACE_PRIVATE_KEY_PEM to a persistent Ed25519 private key (PEM format). You can generate one using:

bash
openssl genpkey -algorithm ED25519 -out private_key.pem
export TRACE_PRIVATE_KEY_PEM="$(cat private_key.pem)"
The adapter will then use that key consistently, allowing long‑term verification.

Example

bash
$ python da_to_trace.py bigmae_decisionassure_execution_permitted-3.json > claim.jwt
⚠️  TRACE_PRIVATE_KEY_PEM not set. Generating ephemeral key.
    The JWT signature cannot be independently re-verified later.
    Set TRACE_PRIVATE_KEY_PEM to a persistent Ed25519 PEM for production.

$ python -c "import jwt; print(jwt.decode(open('claim.jwt').read(), options={'verify_signature': False})['decision'])"
ALLOW
Output

claim.jwt – Signed JWT (compact format, Ed25519)
Limitations

Hardware attestation fields are placeholders (software‑simulated).
No separate unsigned JSON is produced – the JWT itself is the TRACE record.
The policy bundle hash (policy.bundle_hash) is a placeholder – in a real integration, it should be replaced with a hash of the actual policy file.
Repository

DecisionAssure Runtime Governance