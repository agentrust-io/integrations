"""Validate every integration manifest in the repository."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import jsonschema
import yaml


def discover_manifests(root: Path) -> list[Path]:
    """Return real integration manifests, excluding templates and hidden trees."""
    manifests = []
    for manifest in root.rglob("integration.yaml"):
        relative = manifest.relative_to(root)
        if any(part.startswith((".", "_")) for part in relative.parts[:-1]):
            continue
        manifests.append(manifest)
    return sorted(manifests)


def validate_repository(root: Path) -> list[str]:
    schema_path = root / "schema" / "integration.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    failures: list[str] = []

    manifests = discover_manifests(root)
    if not manifests:
        return ["no integration manifests found"]

    for manifest in manifests:
        integration_dir = manifest.parent
        label = integration_dir.relative_to(root).as_posix()
        readme = integration_dir / "README.md"
        if not readme.is_file():
            failures.append(f"{label}: missing README.md")
            continue

        try:
            document = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            jsonschema.validate(document, schema)
        except (OSError, yaml.YAMLError, json.JSONDecodeError) as exc:
            failures.append(f"{label}: cannot load manifest: {exc}")
        except jsonschema.ValidationError as exc:
            failures.append(f"{label}: {exc.message}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    root = args.root.resolve()
    manifests = discover_manifests(root)
    failures = validate_repository(root)
    for manifest in manifests:
        print(f"CHECK {manifest.parent.relative_to(root).as_posix()}")
    for failure in failures:
        print(f"FAIL  {failure}")
    print(f"{len(manifests)} integration(s), {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
