"""Tests for the register review pack. No network: the feed is a pinned fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import air_review  # noqa: E402

HERE = Path(__file__).resolve().parent
FEED = HERE / "register_fixture.json"
MANIFEST = HERE / "sample_manifest.json"


@pytest.fixture(scope="module")
def feed() -> dict:
    return air_review.load_feed(str(FEED))


@pytest.fixture(scope="module")
def manifest():
    return air_review.load_manifest(str(MANIFEST))


def test_feed_fixture_loads(feed):
    assert feed["count"] == len(feed["entries"])
    assert feed["license"].startswith("https://creativecommons.org/licenses/by/4.0")


def test_sample_manifest_triggers_expected_rules(manifest, feed):
    keys = {f.key for f in air_review.review(manifest, feed)}
    assert {
        "dynamic-tool-registration",
        "policy-not-enforced",
        "no-declared-scope",
        "no-human-approval",
        "personal-data",
        "third-party-model",
        "code-and-packages",
    } <= keys


def test_rules_that_should_not_fire(manifest, feed):
    keys = {f.key for f in air_review.review(manifest, feed)}
    # the sample declares no delegation chain, no automated decision-making and,
    # not being a composition-only manifest, no unbound artefacts
    assert "delegated-authority" not in keys
    assert "automated-decisions" not in keys
    assert "unbound-artifacts" not in keys


def test_every_finding_names_the_field_that_triggered_it(manifest, feed):
    for finding in air_review.review(manifest, feed):
        assert finding.because, f"{finding.key} gave no reason"
        assert len(finding.because) > 20


def test_selected_entries_carry_id_and_url(manifest, feed):
    for finding in air_review.review(manifest, feed):
        for entry in finding.entries:
            assert entry["id"].startswith("AIR-")
            assert entry["url"].startswith("https://companyscope.io/register/")


def test_selection_is_field_driven_not_pinned(feed):
    """A new entry in the feed is picked up without touching the code."""
    invented = dict(feed["entries"][0])
    invented.update(
        {
            "id": "AIR-2099-999",
            "title": "Invented entry for the test",
            "url": "https://companyscope.io/register/air-2099-999",
            "owasp_asi": "ASI02 Tool Misuse and Exploitation",
        }
    )
    pool = feed["entries"] + [invented]
    selected = air_review.select(pool, owasp="ASI02")
    assert any(e["id"] == "AIR-2099-999" for e in selected)


def test_json_output_is_valid_and_attributed(manifest, feed):
    payload = json.loads(air_review.as_json(manifest, feed, air_review.review(manifest, feed)))
    assert payload["agent_id"]
    assert "CC BY 4.0" in payload["register"]["attribution"]
    assert payload["findings"]


def test_markdown_output_states_it_is_not_a_verdict(manifest, feed):
    text = air_review.as_markdown(manifest, feed, air_review.review(manifest, feed))
    assert "not a compliance verdict" in text
    assert "CC BY 4.0" in text
