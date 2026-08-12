"""Generate the README integration index from integration manifests."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


START = "<!-- integration-index:start -->"
END = "<!-- integration-index:end -->"


def manifests(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("integration.yaml")
        if not any(part.startswith((".", "_")) for part in path.relative_to(root).parts[:-1])
    )


def render(root: Path) -> str:
    rows = [
        "| Integration | Vendor | Integrates with | Tier |",
        "|---|---|---|---|",
    ]
    for manifest in manifests(root):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        directory = manifest.parent.relative_to(root).as_posix()
        targets = ", ".join(data["integrates_with"])
        rows.append(
            f'| [{data["name"]}]({directory}/) | {data["vendor"]} | {targets} | {data["tier"]} |'
        )
    return "\n".join(rows)


def update(readme: str, generated: str) -> str:
    if readme.count(START) != 1 or readme.count(END) != 1:
        raise ValueError("README must contain exactly one integration-index marker pair")
    prefix, remainder = readme.split(START, 1)
    _, suffix = remainder.split(END, 1)
    return f"{prefix}{START}\n{generated}\n{END}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    readme_path = root / "README.md"
    current = readme_path.read_text(encoding="utf-8")
    expected = update(current, render(root))
    if args.check:
        if current != expected:
            print("README integration index is stale; run scripts/generate_integration_index.py")
            return 1
        return 0
    readme_path.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
