# Demo 3: Offline TRACE verification

**Duration:** ~60 seconds

The signed TRACE claim from demo-01 is verified using only the claim itself and the hashes embedded in it. No running cMCP runtime, no server, no network call. This is the portability property of TRACE: verification is fully self-contained.

**Requires demo-01 to have run first** (reads `../workspace/trace-claim.json`).

## Run

```
python run.py
```

## What to show the audience

1. `verify.py` loads only `workspace/trace-claim.json` and the hashes committed inside it
2. All cryptographic checks pass: schema, signature, policy hash, catalog hash, attestation freshness, audit chain
3. `hardware_attestation` lands in `unverified_fields`, so the status reads `partially_verified`
   - This is expected under `CMCP_DEV_MODE=1` (software-only TEE, no hardware to attest)
   - On real Intel TDX or AMD SEV-SNP, that field verifies too and the status becomes `verified`
4. Point out: `runtime.measurement` and `policy.bundle_hash` are committed in the Ed25519 signature
   - Changing either field would break the signature
   - No connection to the operator who produced the claim is needed

## Key takeaway

The TRACE claim is a portable proof. A regulator, auditor, or counterparty who holds the issuer's public key can verify any claim independently. The operator who produced it does not need to be online or trusted. Software-only mode proves the whole chain except the hardware root; hardware mode closes that last gap.
