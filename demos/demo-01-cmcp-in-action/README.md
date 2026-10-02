# Demo 1: cMCP in action

**Duration:** ~90 seconds

Cedar enforced in enclave. Every tool call produces a TRACE claim carrying the policy bundle hash. On real Intel TDX hardware this hash is incorporated into RTMR[2]; with `CMCP_DEV_MODE=1` the TEE is software-only but the hash still appears in `policy.bundle_hash` in the claim.

## Run

```bash
bash run.sh
```

## What to show the audience

1. cMCP starts — note the policy bundle hash printed at startup
2. `write_file` call goes through — Cedar evaluated it as permitted
3. TRACE claim in the response shows:
   - `runtime.platform: software-only` (would be `intel-tdx` on real hardware)
   - `runtime.measurement: sha256:000...` (all-zeros in dev mode; real hardware gives a non-zero sha384)
   - `policy.bundle_hash: sha256:...` — this is the hash that would go into RTMR[2]
4. `workspace/hello.txt` is created — real filesystem write under governance

## Policy

`policies/allow-filesystem-tools.cedar` permits `write_file` and `read_file` for any principal. Nothing else in the catalog is callable.
