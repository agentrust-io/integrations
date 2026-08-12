from __future__ import annotations

import json
from pathlib import Path

import jsonschema


SCHEMA = json.loads(
    (Path(__file__).parents[1] / "schema" / "integration.schema.json").read_text(encoding="utf-8")
)


def manifest(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "name": "Example",
        "vendor": "Example",
        "integrates_with": ["cmcp"],
        "description": "A technically testable integration.",
        "maintainer": {"github": "example"},
        "repository": "https://example.com/repository",
        "license": "Apache-2.0",
        "tier": "community",
    }
    value.update(overrides)
    return value


def validate(value: dict[str, object]) -> None:
    jsonschema.validate(value, SCHEMA)


def test_trace_integration_declares_its_role() -> None:
    value = manifest(integrates_with=["trace"])

    try:
        validate(value)
    except jsonschema.ValidationError as exc:
        assert "trace_roles" in exc.message
    else:
        raise AssertionError("TRACE integration without trace_roles was accepted")


def test_record_producer_declares_conformance_level() -> None:
    value = manifest(integrates_with=["trace"], trace_roles=["record-producer"])

    try:
        validate(value)
    except jsonschema.ValidationError as exc:
        assert "trace_conformance_level" in exc.message
    else:
        raise AssertionError("TRACE producer without a conformance level was accepted")


def test_external_evidence_source_does_not_claim_record_conformance() -> None:
    validate(
        manifest(
            integrates_with=["trace"],
            trace_roles=["external-evidence-source"],
        )
    )
