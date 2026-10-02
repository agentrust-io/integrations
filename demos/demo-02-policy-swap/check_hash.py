"""
Compute the cMCP policy bundle hash for policies-v1 and policies-v2.

Matches the exact algorithm in cmcp_runtime.policy.bundle._canonical_bundle_hash:

  sha256(json({
    "manifest": <raw manifest dict>,
    "policy_files": {<rel_path>: sha256(file_text.encode()), ...},  # sorted
    "schema_hash": sha256(schema_text.encode())
  }, sort_keys=True, separators=(",",":")))

Usage:
  python check_hash.py
  python check_hash.py v1    # print only v1
  python check_hash.py v2    # print only v2
"""
import hashlib
import json
import pathlib
import sys


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_hash(policies_dir: pathlib.Path) -> str:
    raw_manifest = json.loads((policies_dir / "manifest.json").read_text())

    # Glob all .cedar files, sorted, relative paths as POSIX strings
    cedar_files = sorted(policies_dir.glob("**/*.cedar"))
    policy_files = {
        cf.relative_to(policies_dir).as_posix(): sha256_hex(cf.read_text().encode())
        for cf in cedar_files
    }

    schema_content = (policies_dir / "schema.cedarschema").read_text()

    canonical = json.dumps(
        {
            "manifest": raw_manifest,
            "policy_files": dict(sorted(policy_files.items())),
            "schema_hash": sha256_hex(schema_content.encode()),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()

    return "sha256:" + sha256_hex(canonical)


def main():
    base = pathlib.Path(__file__).parent
    targets = {"v1": base / "policies-v1", "v2": base / "policies-v2"}

    filter_arg = sys.argv[1] if len(sys.argv) > 1 else None

    hashes = {}
    for label, path in targets.items():
        h = bundle_hash(path)
        hashes[label] = h
        if filter_arg is None or filter_arg == label:
            print(f"{label}  {h}")

    if filter_arg is None:
        print()
        if hashes["v1"] != hashes["v2"]:
            print("Hashes differ -- policy swap is detectable by any verifier")
            print("that pinned the v1 hash.")
        else:
            print("WARNING: hashes are identical")


if __name__ == "__main__":
    main()
