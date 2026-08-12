from pathlib import Path

from scripts.validate_compatibility import validate


def test_rejects_versions_below_support_floor(tmp_path: Path) -> None:
    (tmp_path / "compatibility.yaml").write_text(
        "packages:\n  agentrust-trace:\n    minimum: '0.5.0'\n", encoding="utf-8"
    )
    directory = tmp_path / "integrations" / "example"
    directory.mkdir(parents=True)
    (directory / "integration.yaml").write_text(
        "tested_against:\n  agentrust-trace: '0.4.9'\n", encoding="utf-8"
    )

    assert "below supported floor" in validate(tmp_path)[0]


def test_repository_declarations_meet_policy() -> None:
    assert validate() == []
