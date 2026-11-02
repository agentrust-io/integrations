"""Verify an Agent Manifest issued by Provenza, with the agent-manifest SDK.

Provenza issues a composition-only v0.2 manifest per agent, signed as a hybrid
COSE_Sign (Ed25519 + ML-DSA-65) by the organization's audit key. This script
checks, offline:

  1. both COSE signatures, against keys you supply (verify_cose_manifest);
  2. the tool catalog root, recomputed from the bound tools (build_catalog_tree);
  3. the SDK verification engine's verdict (verify_manifest). For a
     composition-only manifest the expected verdict is INCOMPLETE: the
     signature is authentic and the unbound artifacts are declared.

Keys: either a JSON object {kid hex: base64url public key} (--keys), or the
organization's audit public keys as Provenza shows them, standard base64
(--ed25519, --ml-dsa; GET /api/v1/audit/keys). Take them from a source you
trust independently of the manifest file.

Exit code 0 when the signatures verify and the verdict is VALID or INCOMPLETE,
1 otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from agent_manifest import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_cose_manifest,
    verify_manifest,
)
from agent_manifest._merkle import build_catalog_tree
from agent_manifest.models import ToolEntry

ACCEPTED = (OverallResult.VALID, OverallResult.INCOMPLETE)


def trusted_keys_from_b64(*keys: str | None) -> dict[str, str]:
    """{kid hex: base64url key} from standard-base64 raw public keys. The COSE
    kid of each signer is SHA-256 of its raw public key."""
    out = {}
    for key in keys:
        if key:
            raw = base64.b64decode(key)
            out[hashlib.sha256(raw).hexdigest()] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return out


def check(envelope: bytes, trusted_keys: dict[str, str]) -> dict[str, Any]:
    """Run the three checks; return a report (raises on a bad signature)."""
    cose = verify_cose_manifest(envelope, trusted_keys)
    manifest = cose.manifest
    report: dict[str, Any] = {
        "manifest_id": manifest["manifest_id"],
        "agent_id": manifest["agent_id"],
        "issuer": manifest["issuer"],
        "signatures_verified": bool(cose.verified),
        "signers": len(cose.signatures),
        "profile": manifest.get("profile"),
        "unbound_artifacts": manifest.get("unbound_artifacts", []),
    }
    tm = manifest.get("artifacts", {}).get("tool_manifest")
    if tm is not None:
        root = build_catalog_tree([ToolEntry.model_validate(t) for t in tm["tools"]])
        report["tools"] = [t["tool_name"] for t in tm["tools"]]
        report["catalog_hash_matches"] = root == tm["catalog_hash"]
    result = verify_manifest(envelope, VerificationContext(trusted_keys=trusted_keys), RevocationStore())
    report["verdict"] = result.result.value
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("manifest", help="the .cose file (Provenza: agent page -> Agent Manifest)")
    p.add_argument("--keys", help="JSON {kid hex: base64url public key}")
    p.add_argument("--ed25519", help="the audit key's Ed25519 public key, base64")
    p.add_argument("--ml-dsa", help="the audit key's ML-DSA-65 public key, base64")
    args = p.parse_args(argv)

    keys = json.loads(Path(args.keys).read_text()) if args.keys else {}
    keys.update(trusted_keys_from_b64(args.ed25519, args.ml_dsa))
    if not keys:
        p.error("give the signing keys: --keys or --ed25519/--ml-dsa")

    try:
        report = check(Path(args.manifest).read_bytes(), keys)
    except Exception as e:  # a bad signature, an unknown key, a malformed envelope
        print(json.dumps({"error": type(e).__name__, "detail": str(e)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    ok = report["signatures_verified"] and report.get("catalog_hash_matches", True) \
        and OverallResult(report["verdict"]) in ACCEPTED
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
