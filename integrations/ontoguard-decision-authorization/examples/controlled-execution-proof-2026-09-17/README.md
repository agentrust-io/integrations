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

1. mint the TEST-ONLY signed authorization
2. strictly validate the proposed partner action
3. verify the signed authorization again at the controlled executor's commit boundary
4. require ALLOW + release authorization + exact validated action binding
5. only then PENDING → RELEASED, commit_count 0 → 1
6. sign a fresh ephemeral executor receipt
7. pass the live objects through `ontoguard_trace.project`
8. separately rerun $260,000 and digest-only bypass attempts; refuse before commit

A caller-computed action digest is not authority. The controlled executor requires
the signed authorization and trusted JWKS at its bounded commit boundary.

This is a controlled software-only store. Not a bank transfer, not L5,
and not OntoGuard core.

```bash
python verify_proof.py
python controlled_executor.py
```
