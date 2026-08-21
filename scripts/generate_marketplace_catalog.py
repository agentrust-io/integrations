"""Generate the public AgenTrust Marketplace catalog from integration manifests."""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path

import yaml

try:
    from scripts.validate_integrations import discover_manifests, validate_repository
except ModuleNotFoundError:  # Direct execution puts scripts/ rather than the repo root on sys.path.
    from validate_integrations import discover_manifests, validate_repository


CATALOG_VERSION = 1
STACK_LABELS = {"trace": "TRACE", "cmcp": "cMCP", "agent-manifest": "Agent Manifest"}
REPOSITORY_TREE = "https://github.com/agentrust-io/integrations/tree/main/"


def build_catalog(root: Path) -> dict:
    failures = validate_repository(root)
    if failures:
        raise ValueError("invalid integration repository:\n" + "\n".join(failures))

    integrations = []
    for manifest in discover_manifests(root):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        path = manifest.parent.relative_to(root).as_posix()
        market = data["marketplace"]
        integrations.append(
            {
                "name": market.get("display_name", data["name"]),
                "package_name": data["name"],
                "vendor": data["vendor"],
                "description": data["description"],
                "path": path,
                "url": REPOSITORY_TREE + path,
                "homepage": data.get("homepage"),
                "repository": data["repository"],
                "tier": data["tier"],
                "stack": [STACK_LABELS[value] for value in data["integrates_with"]],
                "category": market["category"],
                "mark": market["mark"],
                "featured": market.get("featured"),
                "keywords": market.get("keywords", []),
            }
        )

    integrations.sort(key=lambda item: (item["featured"] or 999, item["name"].casefold()))
    return {"catalog_version": CATALOG_VERSION, "count": len(integrations), "integrations": integrations}


def render(root: Path) -> str:
    return json.dumps(build_catalog(root), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    output = root / "marketplace" / "catalog.json"
    expected = render(root)
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != expected:
            print("marketplace/catalog.json is stale; run scripts/generate_marketplace_catalog.py")
            if output.is_file():
                print("".join(difflib.unified_diff(output.read_text(encoding="utf-8").splitlines(True), expected.splitlines(True), fromfile="committed", tofile="generated")))
            return 1
        print(f"marketplace/catalog.json is current ({build_catalog(root)['count']} integrations)")
        return 0
    output.parent.mkdir(exist_ok=True)
    # Commit byte-stable LF JSON on every platform; Path.write_text translates
    # newlines on Windows and makes the Linux CI parity check report false drift.
    output.write_bytes(expected.encode("utf-8"))
    print(f"wrote {output.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
