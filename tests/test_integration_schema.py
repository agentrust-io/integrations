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
        "marketplace": {"category": "Developer tools", "mark": "EX"},
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


def test_wcm_integration_declares_its_role() -> None:
    value = manifest(integrates_with=["wcm"])

    try:
        validate(value)
    except jsonschema.ValidationError as exc:
        assert "wcm_roles" in exc.message
    else:
        raise AssertionError("WCM integration without wcm_roles was accepted")


def test_wcm_key_broker_declares_conformance_levels() -> None:
    value = manifest(integrates_with=["wcm"], wcm_roles=["key-broker"])

    try:
        validate(value)
    except jsonschema.ValidationError as exc:
        assert "wcm_conformance_levels" in exc.message
    else:
        raise AssertionError("WCM key broker without conformance levels was accepted")


def test_wcm_attestation_source_does_not_claim_manifest_conformance() -> None:
    """An evidence producer verifies no manifest, so it declares no level.

    The same shape as external-evidence-source on the TRACE side: a hardware or
    service adapter hands evidence to a verifier and must not be read as having
    passed the manifest suite itself.
    """
    validate(manifest(integrates_with=["wcm"], wcm_roles=["attestation-source"]))


def test_wcm_conformance_levels_are_per_layer_identifiers() -> None:
    validate(
        manifest(
            integrates_with=["wcm"],
            wcm_roles=["manifest-verifier"],
            wcm_conformance_levels=["L1", "L4"],
        )
    )

    value = manifest(
        integrates_with=["wcm"], wcm_roles=["manifest-verifier"], wcm_conformance_levels=[1]
    )
    try:
        validate(value)
    except jsonschema.ValidationError:
        pass
    else:
        raise AssertionError("a numeric WCM conformance level was accepted")


def test_wcm_package_is_recordable_in_tested_against() -> None:
    validate(
        manifest(
            integrates_with=["wcm"],
            wcm_roles=["manifest-verifier"],
            wcm_conformance_levels=["L1"],
            tested_against={"weight-custody-manifest": "0.26.0"},
        )
    )


def test_marketplace_accepts_the_weight_custody_category() -> None:
    validate(manifest(marketplace={"category": "Model & weight custody", "mark": "WC"}))


def test_marketplace_rejects_unknown_category() -> None:
    value = manifest(marketplace={"category": "Whatever", "mark": "EX"})

    try:
        validate(value)
    except jsonschema.ValidationError as exc:
        assert "Whatever" in exc.message
    else:
        raise AssertionError("unknown Marketplace category was accepted")
