"""Source-only OIDC grant baseline for the release-safeguard sweep (.github#54)."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"
# Proposed existing-source baseline, not approval of live environment settings.
OIDC_JOBS = {
    ("capture-core-publish.yml", "publish"),
    ("trace-adapters-publish.yml", "publish"),
    ("scorecard.yml", "scorecard"),
}


def _oidc_write(permissions):
    if isinstance(permissions, str):
        if permissions not in {"read-all", "write-all"}:
            raise ValueError("unsupported permission shorthand")
        return permissions == "write-all"
    if not isinstance(permissions, dict):
        raise ValueError("permissions must be a mapping or supported shorthand")
    if any(not isinstance(key, str) or value not in ("read", "write", "none")
           for key, value in permissions.items()):
        raise ValueError("permission entries must name read, write or none")
    return permissions.get("id-token") == "write"


def check_oidc_permissions(workflows):
    """Refuse source drift even when narrower jobs shadow a broad default.

    Explicit raises are intentional: a direct python -O invocation still refuses.
    actionlint separately validates workflow syntax, expressions and duplicates.
    """
    paths = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    if not paths:
        raise ValueError("no workflows found")
    actual = set()
    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            raise ValueError(f"workflow and jobs must be mappings: {path.name}")
        defaults = workflow.get("permissions", {})
        if _oidc_write(defaults):
            raise ValueError(f"workflow-wide OIDC grant: {path.name}")
        for name, job in workflow["jobs"].items():
            if not isinstance(job, dict):
                raise ValueError(f"job must be a mapping: {path.name}/{name}")
            permissions = job.get("permissions", defaults)
            if permissions == "write-all":
                raise ValueError(f"OIDC write-all job grant: {path.name}/{name}")
            if _oidc_write(permissions):
                actual.add((path.name, name))
    if actual != OIDC_JOBS:
        raise ValueError(f"OIDC job allowance drift: {sorted(actual ^ OIDC_JOBS)}")


def _copy_workflows(destination):
    for source in [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]:
        shutil.copyfile(source, destination / source.name)
    check_oidc_permissions(destination)


def test_real_workflows_match_proposed_oidc_baseline():
    check_oidc_permissions(WORKFLOWS)


@pytest.mark.parametrize("scenario", [
    "new-yml", "new-yaml", "extra-job", "inherited-default", "shadowed-default",
    "default-write-all", "shadowed-write-all", "job-write-all", "allowed-write-all",
    "remove-capture", "remove-adapters", "remove-scorecard", "rename-job", "rename-file",
])
def test_oidc_guard_refuses_each_permission_drift(tmp_path, scenario):
    _copy_workflows(tmp_path)
    path = tmp_path / "capture-core-publish.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    if scenario.startswith("new-"):
        path = tmp_path / ("unexpected." + scenario.removeprefix("new-"))
        workflow = {"permissions": {}, "jobs": {"unexpected": {
            "runs-on": "ubuntu-latest", "permissions": {"id-token": "write"},
            "steps": [{"run": "echo test"}],
        }}}
    elif scenario == "extra-job":
        workflow["jobs"]["unexpected"] = {"permissions": {"id-token": "write"}}
    elif scenario in {"inherited-default", "shadowed-default"}:
        workflow["permissions"] = {"id-token": "write"}
        if scenario == "shadowed-default":
            for job in workflow["jobs"].values():
                job.setdefault("permissions", {})
    elif scenario in {"default-write-all", "shadowed-write-all"}:
        workflow["permissions"] = "write-all"
        if scenario == "shadowed-write-all":
            for job in workflow["jobs"].values():
                job.setdefault("permissions", {})
    elif scenario in {"job-write-all", "allowed-write-all"}:
        job = "build" if scenario == "job-write-all" else "publish"
        workflow["jobs"][job]["permissions"] = "write-all"
    elif scenario.startswith("remove-"):
        path, job = {
            "remove-capture": (tmp_path / "capture-core-publish.yml", "publish"),
            "remove-adapters": (tmp_path / "trace-adapters-publish.yml", "publish"),
            "remove-scorecard": (tmp_path / "scorecard.yml", "scorecard"),
        }[scenario]
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        workflow["jobs"][job]["permissions"].pop("id-token")
    elif scenario == "rename-job":
        workflow["jobs"]["renamed"] = workflow["jobs"].pop("publish")
    elif scenario == "rename-file":
        path.unlink()
        path = tmp_path / "capture-core-publish.yaml"
    path.write_text(yaml.safe_dump(workflow), encoding="utf-8", newline="\n")
    with pytest.raises(ValueError, match="OIDC"):
        check_oidc_permissions(tmp_path)


def test_read_only_inheritance_and_explicit_narrowing_remain_valid(tmp_path):
    _copy_workflows(tmp_path)
    (tmp_path / "read-only.yaml").write_text(
        "permissions: read-all\njobs:\n  inherited: {}\n"
        "  narrow:\n    permissions:\n      contents: read\n", encoding="utf-8",
    )
    check_oidc_permissions(tmp_path)


@pytest.mark.parametrize("permissions", [None, [], 1, "unsupported", {"id-token": True}])
def test_malformed_permissions_fail_closed(permissions):
    with pytest.raises(ValueError):
        _oidc_write(permissions)


@pytest.mark.parametrize("text", ["null", "[]", "jobs: null", "jobs: {test: null}"])
def test_malformed_workflow_shapes_fail_closed(tmp_path, text):
    (tmp_path / "broken.yml").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        check_oidc_permissions(tmp_path)


def test_empty_inventory_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="no workflows"):
        check_oidc_permissions(tmp_path)


def test_optimized_python_has_positive_control_and_refuses_new_oidc_grant(tmp_path):
    _copy_workflows(tmp_path)
    script = (
        "import runpy,sys; from pathlib import Path; "
        "check=runpy.run_path(sys.argv[1])['check_oidc_permissions']; "
        "check(Path(sys.argv[2]))"
    )
    command = [sys.executable, "-O", "-c", script, __file__, str(tmp_path)]
    positive = subprocess.run(command, capture_output=True, text=True, check=False)
    assert positive.returncode == 0, positive.stderr
    (tmp_path / "new.yaml").write_text(
        "permissions: write-all\njobs: {}\n", encoding="utf-8",
    )
    refused = subprocess.run(command, capture_output=True, text=True, check=False)
    assert refused.returncode != 0
    assert "workflow-wide OIDC grant" in refused.stderr


def test_validation_workflow_runs_the_guard():
    workflow = yaml.safe_load((WORKFLOWS / "validate.yml").read_text(encoding="utf-8"))
    commands = [step.get("run", "") for step in workflow["jobs"]["validate"]["steps"]]
    assert any("tests/test_workflow_oidc_permissions.py" in command for command in commands)
