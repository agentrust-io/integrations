"""Static guard against the drift that broke demo 10.

cMCP hashes description + input schema + output schema on both sides of the
boundary and fail-closes when they differ. A catalog entry that describes an
argument the upstream server does not advertise is a `rug_pull` to the gateway,
so every call comes back 503 and the demo denies everything. Catching that here
costs no ports and no gateway start.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from cmcp_runtime.catalog.loader import definition_digest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def _catalog_entry(demo: str, tool_name: str) -> dict:
    entries = json.loads((ROOT / demo / "catalog.json").read_text(encoding="utf-8"))
    for entry in entries:
        if entry["tool_name"] == tool_name:
            return entry
    pytest.fail(f"{demo}/catalog.json has no entry for {tool_name}")


def test_model_gateway_catalog_matches_the_advertised_tool():
    entry = _catalog_entry("demo-10-model-gateway", "model.chat_completion")
    approved = entry["approved_definition"]
    tool = _load("demo_model_server", "demo-10-model-gateway/model_server.py").TOOL

    assert definition_digest(
        approved["description"],
        approved.get("input_schema"),
        approved.get("output_schema"),
    ) == definition_digest(
        str(tool.get("description", "")),
        tool.get("inputSchema") or {},
        tool.get("outputSchema"),
    ), (
        "catalog.json and model_server.py describe different tools. The gateway "
        "reads that as a rug pull and denies every call."
    )


def test_model_gateway_endpoint_arguments_are_all_in_the_schema():
    """Every argument the endpoint sends must be an approved property.

    This is the specific gap that shipped: the endpoint sent
    ``contains_identifiers``, the Cedar policy read it, and neither schema
    declared it.
    """
    entry = _catalog_entry("demo-10-model-gateway", "model.chat_completion")
    properties = set(entry["approved_definition"]["input_schema"]["properties"])

    source = (ROOT / "demo-10-model-gateway" / "endpoint.py").read_text(encoding="utf-8")
    start = source.index("    args = {")
    block = source[start:source.index("\n    }", start)]
    sent = {line.split('"')[1] for line in block.splitlines() if line.strip().startswith('"')}

    assert sent, "could not parse the endpoint's argument block"
    assert sent <= properties, f"endpoint sends undeclared arguments: {sorted(sent - properties)}"


def test_stored_definition_hashes_are_current():
    """A hand-edited schema with a stale definition_hash fails at catalog load."""
    from cmcp_runtime.catalog.loader import _compute_definition_hash

    for catalog in sorted(ROOT.glob("demo-*/catalog.json")):
        for entry in json.loads(catalog.read_text(encoding="utf-8")):
            if "definition_hash" not in entry:
                continue
            computed = _compute_definition_hash(entry["approved_definition"])
            assert entry["definition_hash"] == computed, (
                f"{catalog.parent.name}/{entry['tool_name']}: stale definition_hash"
            )
