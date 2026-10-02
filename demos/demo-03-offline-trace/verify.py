"""
Demo 3: Offline TRACE claim verification

Verifies the signed cMCP RuntimeClaim from demo-01 using ONLY:
  - workspace/trace-claim.json (the claim)
  - policy_bundle_hash and tool_catalog_hash from the claim itself

No running cMCP Runtime. No server connection. No network call.

The claim's own embedded hashes are used as the "approved" values because
demo-01 produced them under controlled conditions. In production, a verifier
pins these hashes independently of the claim producer.

Usage:
  python verify.py   (from repo root, or via run.sh)
"""
import json
import pathlib
import sys

CLAIM_PATH = pathlib.Path(__file__).parent.parent / "workspace" / "trace-claim.json"


def main():
    if not CLAIM_PATH.exists():
        print(f"Claim not found: {CLAIM_PATH}")
        print("Run demo-01 first:  bash demo-01-cmcp-in-action/run.sh")
        sys.exit(1)

    claim = json.loads(CLAIM_PATH.read_text())

    trace = claim.get("trace", {})
    gw = claim.get("gateway", {})
    policy_hash = trace.get("policy", {}).get("bundle_hash", "")
    catalog_hash = gw.get("catalog", {}).get("hash", "")

    print("=== Demo 3: Offline TRACE verification ===")
    print()
    print(f"Claim:         {CLAIM_PATH}")
    print(f"Policy hash:   {policy_hash}")
    print(f"Catalog hash:  {catalog_hash}")
    print()
    print("No network call. No gateway. Verifying Ed25519 signature and hashes...")
    print()

    from cmcp_verify import ApprovedHashes, verify_trace_claim

    approved = ApprovedHashes(
        policy_bundle_hash=policy_hash,
        tool_catalog_hash=catalog_hash,
    )
    result = verify_trace_claim(claim, approved)

    sep = "=" * 60
    print(sep)
    print("VERIFICATION RESULT")
    print(sep)
    print(f"  Status:           {result.status.value}")
    print(f"  Verified fields:  {', '.join(result.verified_fields)}")
    print(f"  Unverified:       {', '.join(result.unverified_fields)}")
    print(f"  Failure reason:   {result.failure_reason}")
    print(f"  Attestation age:  {result.attestation_age_seconds}s")
    print(f"  Fresh:            {result.is_attestation_fresh}")
    if result.details:
        print("  Details:")
        for k, v in result.details.items():
            print(f"    {k}: {v}")
    print(sep)
    print()

    dev_mode_only = (
        set(result.unverified_fields) == {"hardware_attestation"}
        and not result.failure_reason
    )

    if result.status.value == "verified":
        print("All cryptographic checks passed.")
        print()
        print("'hardware_attestation' is in unverified_fields because CMCP_DEV_MODE=1")
        print("uses a software-only TEE. On real Intel TDX or AMD SEV-SNP, it would")
        print("also be verified and status would remain 'verified' with full hardware")
        print("provenance.")
    elif result.status.value == "partially_verified" and dev_mode_only:
        # Expected outcome under CMCP_DEV_MODE=1: every cryptographic check passes
        # and only hardware_attestation is unverified because there is no real TEE.
        print("All cryptographic checks passed.")
        print()
        print("Status is 'partially_verified' because CMCP_DEV_MODE=1 uses a software-only")
        print("TEE, so 'hardware_attestation' cannot be verified. On real Intel TDX or AMD")
        print("SEV-SNP, that field is verified too and the status becomes 'verified'.")
    elif result.status.value == "partially_verified":
        print(f"Partial verification. Failure: {result.failure_reason}")
        sys.exit(1)
    else:
        print(f"Verification FAILED. Reason: {result.failure_reason}")
        sys.exit(1)

    print()
    print("No network call was made. No cMCP Runtime was contacted.")
    print("Policy hash and measurement are committed in the Ed25519 signature.")


if __name__ == "__main__":
    main()
