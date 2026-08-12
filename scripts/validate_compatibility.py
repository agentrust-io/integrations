"""Check tested-against declarations against the repository support floor."""

from __future__ import annotations

from pathlib import Path

from packaging.version import InvalidVersion, Version
import yaml


ROOT = Path(__file__).resolve().parents[1]


def validate(root: Path = ROOT) -> list[str]:
    policy = yaml.safe_load((root / "compatibility.yaml").read_text(encoding="utf-8"))
    floors = {name: Version(rule["minimum"]) for name, rule in policy["packages"].items()}
    failures: list[str] = []
    for manifest in sorted(root.rglob("integration.yaml")):
        relative = manifest.relative_to(root)
        if any(part.startswith((".", "_")) for part in relative.parts[:-1]):
            continue
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        for package, raw_version in (data.get("tested_against") or {}).items():
            if package not in floors:
                failures.append(f"{relative}: unsupported tested_against package {package!r}")
                continue
            try:
                version = Version(str(raw_version))
            except InvalidVersion:
                failures.append(f"{relative}: {package} has invalid version {raw_version!r}")
                continue
            if version < floors[package]:
                failures.append(
                    f"{relative}: {package} {version} is below supported floor {floors[package]}"
                )
    return failures


if __name__ == "__main__":
    errors = validate()
    for error in errors:
        print(f"FAIL {error}")
    print(f"compatibility policy: {len(errors)} failure(s)")
    raise SystemExit(bool(errors))
