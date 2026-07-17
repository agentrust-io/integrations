"""Validate the integration manifest, plugin package, and marketplace entry."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml


REPO = Path(__file__).resolve().parents[3]
PLUGIN = REPO / "plugins" / "agentrust-codex"


def main() -> int:
    schema = json.loads((REPO / "schema" / "integration.schema.json").read_text())
    integration = yaml.safe_load((PLUGIN / "integration.yaml").read_text())
    jsonschema.validate(integration, schema)

    manifest = json.loads(
        (PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    assert manifest["name"] == PLUGIN.name
    assert manifest["skills"] == "./skills/"
    assert (PLUGIN / "hooks" / "hooks.json").is_file()
    assert (PLUGIN / "skills" / "agent-integrity" / "SKILL.md").is_file()

    marketplace = json.loads(
        (REPO / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
    )
    entry = next(
        item for item in marketplace["plugins"] if item["name"] == manifest["name"]
    )
    assert marketplace["name"] == "agentrust"
    assert entry["source"] == {
        "source": "local",
        "path": "./plugins/agentrust-codex",
    }
    assert entry["policy"]["installation"] == "AVAILABLE"
    assert entry["policy"]["authentication"] == "ON_INSTALL"
    assert entry["category"] == "Security"
    print("AgenTrust Codex structure validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
