from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.generate_marketplace_catalog import build_catalog, render


def _write_repository(root: Path, entries: list[tuple[str, dict]]) -> None:
    schema = json.loads((Path(__file__).parents[1] / "schema" / "integration.schema.json").read_text())
    (root / "schema").mkdir()
    (root / "schema" / "integration.schema.json").write_text(json.dumps(schema), encoding="utf-8")
    for relative, document in entries:
        directory = root / relative
        directory.mkdir(parents=True)
        (directory / "README.md").write_text("# Integration\n", encoding="utf-8")
        (directory / "integration.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")


def _manifest(name: str, *, featured: int | None = None) -> dict:
    marketplace = {"category": "Developer tools", "mark": name[:2].upper()}
    if featured is not None:
        marketplace["featured"] = featured
    return {
        "name": name, "vendor": "Example", "integrates_with": ["agent-manifest"],
        "description": f"Connects {name} to Agent Manifest for deterministic testing.",
        "maintainer": {"github": "example"}, "repository": "https://example.com/source",
        "license": "Apache-2.0", "tier": "community", "marketplace": marketplace,
    }


def test_catalog_contains_every_manifest_and_prefers_featured_order(tmp_path: Path) -> None:
    _write_repository(tmp_path, [("integrations/zulu", _manifest("Zulu")), ("plugins/alpha", _manifest("Alpha", featured=2))])
    catalog = build_catalog(tmp_path)
    assert catalog["count"] == 2
    assert [item["name"] for item in catalog["integrations"]] == ["Alpha", "Zulu"]
    assert catalog["integrations"][0]["stack"] == ["Agent Manifest"]
    assert catalog["integrations"][0]["url"].endswith("plugins/alpha")


def test_wcm_manifests_carry_the_wcm_stack_label(tmp_path: Path) -> None:
    """A stack the generator cannot label is a KeyError, not a missing filter.

    The Marketplace derives its stack facet from this field, so an unmapped
    identifier takes the whole catalog build down rather than silently listing
    an integration with no technology.
    """
    document = _manifest("Custody Gate")
    document["integrates_with"] = ["wcm", "trace"]
    document["wcm_roles"] = ["manifest-verifier"]
    document["wcm_conformance_levels"] = ["L1"]
    document["trace_roles"] = ["record-producer"]
    document["trace_conformance_level"] = 0
    document["marketplace"] = {"category": "Model & weight custody", "mark": "CG"}
    _write_repository(tmp_path, [("integrations/custody-gate", document)])

    catalog = build_catalog(tmp_path)

    assert catalog["integrations"][0]["stack"] == ["WCM", "TRACE"]
    assert catalog["integrations"][0]["category"] == "Model & weight custody"


def test_render_is_deterministic(tmp_path: Path) -> None:
    _write_repository(tmp_path, [("integrations/alpha", _manifest("Alpha"))])
    assert render(tmp_path) == render(tmp_path)
    assert render(tmp_path).endswith("\n")


def test_catalog_rejects_invalid_manifest_before_generation(tmp_path: Path) -> None:
    broken = _manifest("Broken")
    del broken["marketplace"]
    _write_repository(tmp_path, [("integrations/broken", broken)])
    try:
        build_catalog(tmp_path)
    except ValueError as exc:
        assert "marketplace" in str(exc)
    else:
        raise AssertionError("invalid manifest was accepted")
