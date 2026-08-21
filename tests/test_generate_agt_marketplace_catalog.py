import json
from pathlib import Path
import pytest
from scripts.generate_agt_marketplace_catalog import build_catalog, render, validate_catalog
SHA = "a" * 40

def integration(root: Path, slug: str, heading: str, name: str, description: str) -> None:
    directory = root / "agent-governance-python" / "agentmesh-integrations" / slug
    directory.mkdir(parents=True)
    (directory / "README.md").write_text(f"# {heading}\n", encoding="utf-8")
    (directory / "pyproject.toml").write_text(f'[project]\nname = "{name}"\ndescription = "{description}"\n', encoding="utf-8")

def test_catalog_is_complete_sorted_and_commit_pinned(tmp_path):
    integration(tmp_path, "zulu", "Zulu Adapter — extra", "zulu-package", "Zulu description")
    integration(tmp_path, "alpha", "Alpha Adapter", "alpha-package", "Alpha description")
    integration(tmp_path, "template-agentmesh", "Template", "template", "Not a listing")
    catalog = build_catalog(tmp_path, SHA)
    assert catalog["count"] == 2
    assert [item["name"] for item in catalog["integrations"]] == ["Alpha Adapter", "Zulu Adapter"]
    assert all(f"/tree/{SHA}/" in item["url"] for item in catalog["integrations"])
    assert json.loads(render(tmp_path, SHA)) == catalog

def test_package_json_metadata_is_supported(tmp_path):
    directory = tmp_path / "agent-governance-python" / "agentmesh-integrations" / "typescript"
    directory.mkdir(parents=True)
    (directory / "README.md").write_text("# TypeScript Adapter\n", encoding="utf-8")
    (directory / "package.json").write_text(json.dumps({"name": "@agentmesh/typescript", "description": "TypeScript description"}), encoding="utf-8")
    assert build_catalog(tmp_path, SHA)["integrations"][0]["package_name"] == "@agentmesh/typescript"

def test_scoped_package_heading_is_presented_as_a_marketplace_name(tmp_path):
    integration(tmp_path, "copilot", "@microsoft/agentmesh-copilot-governance", "package", "Description")
    assert build_catalog(tmp_path, SHA)["integrations"][0]["name"] == "Copilot Governance"

def test_readme_metadata_fallback_supports_unpackaged_integration(tmp_path):
    directory = tmp_path / "agent-governance-python" / "agentmesh-integrations" / "readme-only"
    directory.mkdir(parents=True)
    (directory / "README.md").write_text("# README Only\n\nA useful integration.\n", encoding="utf-8")
    item = build_catalog(tmp_path, SHA)["integrations"][0]
    assert item["package_name"] == "readme-only"
    assert item["description"] == "A useful integration."

def test_validator_rejects_duplicate_and_unpinned_entries(tmp_path):
    integration(tmp_path, "alpha", "Alpha", "alpha", "Description")
    catalog = build_catalog(tmp_path, SHA)
    catalog["integrations"].append(dict(catalog["integrations"][0]))
    catalog["count"] = 2
    with pytest.raises(ValueError, match="duplicate name"):
        validate_catalog(catalog)
    catalog = build_catalog(tmp_path, SHA)
    catalog["integrations"][0]["url"] = "https://example.com/main/alpha"
    with pytest.raises(ValueError, match="pinned"):
        validate_catalog(catalog)
