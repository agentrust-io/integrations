"""Generate a deterministic, commit-pinned snapshot of AGT integrations."""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path

CATALOG_VERSION = 1
AGT_REPOSITORY = "https://github.com/microsoft/agent-governance-toolkit"
INTEGRATIONS_PATH = Path("agent-governance-python/agentmesh-integrations")
EXCLUDED_DIRECTORIES = {"template-agentmesh"}

def source_commit(root: Path) -> str:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    commit = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"invalid AGT source commit: {commit!r}")
    return commit

def project_metadata(directory: Path) -> tuple[str, str]:
    pyproject, package_json = directory / "pyproject.toml", directory / "package.json"
    if pyproject.is_file():
        project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    elif package_json.is_file():
        project = json.loads(package_json.read_text(encoding="utf-8"))
    else:
        readme = (directory / "README.md").read_text(encoding="utf-8")
        paragraphs = re.split(r"\n\s*\n", readme)
        description = next((part.strip() for part in paragraphs[1:] if part.strip() and not part.lstrip().startswith(("[![", "##", "```"))), "")
        project = {"name": directory.name, "description": re.sub(r"\s+", " ", description)}
    name, description = project.get("name"), project.get("description")
    if not isinstance(name, str) or not name.strip() or not isinstance(description, str) or not description.strip():
        raise ValueError(f"{directory.name}: package name and description are required")
    return name.strip(), description.strip()

def display_name(directory: Path) -> str:
    readme = directory / "README.md"
    if not readme.is_file():
        raise ValueError(f"{directory.name}: missing README.md")
    match = re.search(r"^#\s+(.+?)(?=##|\r?$)", readme.read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise ValueError(f"{directory.name}: README.md needs an H1 display name")
    heading = re.sub(r"\s*(?:—|\|)\s+.*$", "", match.group(1)).strip()
    if len(heading) > 100:
        heading = directory.name
    if heading.startswith("@") or (" " not in heading and ("-" in heading or "_" in heading)):
        heading = heading.rsplit("/", 1)[-1]
        heading = re.sub(r"^(?:agentmesh[-_])|(?:[-_]agentmesh)$", "", heading, flags=re.IGNORECASE)
        heading = " ".join(word.capitalize() for word in re.split(r"[-_]", heading))
        replacements = {"Ai": "AI", "A2a": "A2A", "Adk": "ADK", "Api": "API", "Avp": "AVP", "Llamaindex": "LlamaIndex", "Mcp": "MCP", "Openai": "OpenAI"}
        heading = " ".join(replacements.get(word, word) for word in heading.split())
    return heading

def mark(name: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", name)
    return "".join(word[0] for word in words[:2]).upper()

def build_catalog(agt_root: Path, commit: str | None = None) -> dict:
    commit = commit or source_commit(agt_root)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full lowercase Git SHA")
    collection = agt_root / INTEGRATIONS_PATH
    if not collection.is_dir():
        raise ValueError(f"AGT integration collection not found at {collection}")
    integrations = []
    for directory in sorted(collection.iterdir(), key=lambda path: path.name.casefold()):
        if not directory.is_dir() or directory.name.startswith(".") or directory.name in EXCLUDED_DIRECTORIES:
            continue
        package_name, description = project_metadata(directory)
        name = display_name(directory)
        path = (INTEGRATIONS_PATH / directory.name).as_posix()
        integrations.append({
            "name": name, "package_name": package_name, "vendor": "Microsoft", "description": description,
            "path": path, "url": f"{AGT_REPOSITORY}/tree/{commit}/{path}", "homepage": None,
            "repository": AGT_REPOSITORY, "tier": "project", "stack": ["AGT"],
            "category": "AGT integrations", "mark": mark(name), "featured": None,
            "keywords": [directory.name, package_name, "Agent Governance Toolkit", "AgentMesh"],
        })
    if not integrations:
        raise ValueError("no AGT integrations discovered")
    integrations.sort(key=lambda item: item["name"].casefold())
    return {"catalog_version": CATALOG_VERSION, "source": AGT_REPOSITORY, "source_commit": commit, "count": len(integrations), "integrations": integrations}

def validate_catalog(catalog: dict) -> None:
    entries = catalog.get("integrations")
    if catalog.get("catalog_version") != CATALOG_VERSION or not isinstance(entries, list):
        raise ValueError("unsupported AGT catalog")
    if catalog.get("count") != len(entries):
        raise ValueError("AGT catalog count does not match its entries")
    commit = catalog.get("source_commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("AGT catalog has an invalid source commit")
    for field in ("name", "package_name", "url"):
        values = [entry.get(field) for entry in entries]
        if any(not isinstance(value, str) or not value for value in values) or len(values) != len(set(values)):
            raise ValueError(f"AGT catalog has missing or duplicate {field}")
    if any(f"/tree/{commit}/" not in entry["url"] for entry in entries):
        raise ValueError("every AGT integration URL must be pinned to source_commit")

def render(agt_root: Path, commit: str | None = None) -> str:
    catalog = build_catalog(agt_root, commit)
    validate_catalog(catalog)
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agt-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "marketplace" / "agt-catalog.json")
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(render(args.agt_root.resolve()).encode("utf-8"))
    print(f"wrote {output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
