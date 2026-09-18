# Historical controlled-execution proof (2026-09-17) plus live harness

Two layers. Do not mix them.

## Historical evidence

Captured from live OntoGuard ALLOW `2fcdc71e-dc28-4d94-9150-fae4517103f3`.
The signed authorization expires on 2026-09-24. Signatures and digests
remain inspectable after expiry. Live adapter replay of *that* captured
authorization is expected to fail closed once expired. Do not extend or
bypass that expiry.

## Live executor harness

`controlled_executor.py` mints a **TEST-ONLY** authorization at runtime
with an ephemeral key. That object is harness-only. It is **not** a live
OntoGuard Decision API result.

Order of operations:

1. mint and cryptographically verify the test authorization
2. derive the $250,000 partner action binding
3. only then PENDING → RELEASED, commit_count 0 → 1
4. sign a fresh ephemeral executor receipt
5. pass the live objects through `ontoguard_trace.project`
6. separately rerun $260,000, refuse, commit_count stays 0, no TRACE

This is a controlled software-only store. Not a bank transfer, not L5,
and not OntoGuard core.

```bash
python verify_proof.py
python controlled_executor.py
```
