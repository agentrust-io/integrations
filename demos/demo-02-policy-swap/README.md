# Demo 2: Policy swap = attestation failure

**Duration:** ~90 seconds

The operator swaps the Cedar policy bundle (v1 → v2). The TRACE claim's `policy.bundle_hash` changes immediately. Any verifier that pinned the v1 hash will reject all claims produced by the reloaded runtime — the policy identity is no longer what was approved.

On real Intel TDX hardware, the policy hash is incorporated into RTMR[2] at startup. Swapping the bundle means the TEE measurement changes — so the attestation quote itself mismatches, before any claim is evaluated.

## Run

```bash
bash run.sh
```

## What to show the audience

1. `check_hash.py` output: v1 hash and v2 hash printed side-by-side — visibly different values
2. cMCP starts with v1 → `write_file` succeeds, TRACE claim shows v1 hash
3. Operator restarts cMCP with v2 → `write_file` is DENIED (Cedar `forbid` rule)
4. TRACE claim from the v2 run shows a different `policy.bundle_hash`
5. Key point: any system that approved v1's hash would reject v2's claims — policy substitution is detectable

## Policies

| Bundle | Cedar rules |
|---|---|
| `policies-v1/` | `permit` all catalog tools |
| `policies-v2/` | `permit read_file`, `forbid write_file` |

The only change is one Cedar file. The bundle hash changes completely (sha256 over the entire bundle content).
