"""The vendored files are the horizon-shield files, and the vectors rebuild.

SOURCE_COMMIT is the horizon-shield commit the files were copied from, at
workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/. The rebuild runs
gen_vectors.py in a temporary directory: it signs every credential and
revocation with ca2a-runtime and must reproduce vectors.json byte for byte.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys

from hs_ca2a_support import MUSUBI_DIRS, VECTORS_PATH, VENDOR

SOURCE_COMMIT = "05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a"
VENDORED_SHA256 = {
    "companion_v0.py": "a6e2b2c9d920eda65723e1d863e8e108df642c6b3ece8b40499726bfc425a781",
    "gen_vectors.py": "2904a9310bb8f32d9efd808e1fea0a9cb38d7145c54002b684ebd7946adac005",
    "vectors/vectors.json": "4b4e2362ab6dda3743e5ba1cd76285a0872344f40086bc95b18b3bd34490d2a2",
}


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(MUSUBI_DIRS)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def test_vendored_files_are_byte_identical_to_the_source_commit():
    for name, digest in VENDORED_SHA256.items():
        assert hashlib.sha256((VENDOR / name).read_bytes()).hexdigest() == digest, name


def test_companion_selftest_cli_agrees_on_every_vector():
    run = subprocess.run([sys.executable, str(VENDOR / "companion_v0.py"), "--selftest"],
                         capture_output=True, text=True, env=_env(), timeout=600)
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.strip().splitlines()[-1] == "57/57 vectors agree"


def test_vectors_rebuild_byte_for_byte_with_ca2a_runtime(tmp_path):
    for name in ("companion_v0.py", "gen_vectors.py"):
        shutil.copyfile(VENDOR / name, tmp_path / name)
    run = subprocess.run([sys.executable, str(tmp_path / "gen_vectors.py")],
                         capture_output=True, text=True, env=_env(), timeout=600)
    assert run.returncode == 0, run.stdout + run.stderr
    assert (tmp_path / "vectors" / "vectors.json").read_bytes() == VECTORS_PATH.read_bytes()
