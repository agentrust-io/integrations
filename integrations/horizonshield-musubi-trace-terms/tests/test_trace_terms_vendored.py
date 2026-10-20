"""The vendored files, the evaluator's CLI, and TRACE Level 0 on the consumed records.

SOURCE_COMMIT is the horizon-shield commit the files were copied from, at
workers/hs-ledger/nenrin/trace-terms-v0/.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

from hs_trace_terms_support import MUSUBI_DIRS, VECTORS, VENDOR

SOURCE_COMMIT = "05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a"
VENDORED_SHA256 = {
    "trace_terms_v0.py": "5fbd7dd7a8d7313973673f2b0593c8b06f7f9f5c01381daf95c8faa81853e069",
    "vectors/vectors.json": "a636029b66d66768fbf37ea4e7a61ef0035548d6b0cc407b4c0830a43ac0d38a",
}
# The two Trust Records the vectors consume unchanged, copied from
# agentrust-io/trace-registry (see NOTICE). TT01 uses the first in a
# within_terms verdict, TT16 the second.
REGISTRY_RECORDS = {"TT01": "MlMDcC9FD2XTwcHx_cMV7aTqq8sfXlTcyFNSDkqsgSE",
                    "TT16": "ff3LjX7m5f7vj3YD5NS_LqtEzEa_wkD5ZnNPBpSD3o8"}


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(MUSUBI_DIRS)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _cli(*args):
    return subprocess.run([sys.executable, str(VENDOR / "trace_terms_v0.py"), *args],
                          capture_output=True, text=True, env=_env(), timeout=600)


def test_vendored_files_are_byte_identical_to_the_source_commit():
    for name, digest in VENDORED_SHA256.items():
        assert hashlib.sha256((VENDOR / name).read_bytes()).hexdigest() == digest, name


def test_evaluator_selftest_cli_agrees_on_every_vector():
    run = _cli("--selftest")
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.strip().splitlines()[-1] == "=== 55 / 55 (musubi-trace-terms-v0) ==="


@pytest.mark.parametrize(("vector_id", "exit_code"), [("TT01", 0), ("TT02", 1), ("TT25", 2), ("TT11", 3)])
def test_check_cli_exit_codes(tmp_path, vector_id, exit_code):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps(VECTORS[vector_id]["bundle"]), encoding="utf-8")
    run = _cli("check", str(bundle))
    assert run.returncode == exit_code, run.stdout + run.stderr


@pytest.mark.parametrize("vector_id", sorted(REGISTRY_RECORDS))
def test_consumed_registry_record_passes_trace_level_0(tmp_path, vector_id):
    tool = shutil.which("trace-tests", path=os.path.dirname(sys.executable)) or shutil.which("trace-tests")
    assert tool, "agentrust-trace-tests is not installed"
    record = VECTORS[vector_id]["bundle"]["acts"][0]["trust_record"]
    assert record["cnf"]["jwk"]["x"] == REGISTRY_RECORDS[vector_id]
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    # The registry records were issued in August and September 2026; the
    # freshness window is opened so the check is about the record, not its age.
    run = subprocess.run([tool, "verify", "--record", str(path), "--level", "0", "--max-age", "315360000"],
                         capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Result: PASS" in run.stdout
