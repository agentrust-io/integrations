from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.validate_integrations import discover_manifests, validate_repository


SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["name"],
    "properties": {"name": {"type": "string"}},
}


def _repository(tmp_path: Path) -> Path:
    schema_dir = tmp_path / "schema"
    schema_dir.mkdir()
    (schema_dir / "integration.schema.json").write_text(json.dumps(SCHEMA), encoding="utf-8")
    return tmp_path


def _integration(root: Path, relative: str, *, readme: bool = True) -> None:
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / "integration.yaml").write_text(yaml.safe_dump({"name": relative}), encoding="utf-8")
    if readme:
        (directory / "README.md").write_text("# Integration\n", encoding="utf-8")


def test_discovers_manifests_across_supported_repository_layouts(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _integration(root, "integrations/vendor-product")
    _integration(root, "plugins/agentrust-codex")
    _integration(root, "scheduled-agents")
    _integration(root, "integrations/_template")

    discovered = [path.relative_to(root).as_posix() for path in discover_manifests(root)]

    assert discovered == [
        "integrations/vendor-product/integration.yaml",
        "plugins/agentrust-codex/integration.yaml",
        "scheduled-agents/integration.yaml",
    ]


def test_reports_missing_readme(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _integration(root, "plugins/example", readme=False)

    assert validate_repository(root) == ["plugins/example: missing README.md"]
