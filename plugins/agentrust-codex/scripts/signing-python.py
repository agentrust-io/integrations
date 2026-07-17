"""Create or reuse the pinned AgenTrust signing environment."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import venv
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = PLUGIN_ROOT / "requirements.txt"
CODEX_HOME = Path(
    os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
).expanduser()
ENV_ROOT = CODEX_HOME / "agentrust" / "signing-venv"
MARKER = ENV_ROOT / ".requirements.sha256"


def _python_path() -> Path:
    if os.name == "nt":
        return ENV_ROOT / "Scripts" / "python.exe"
    return ENV_ROOT / "bin" / "python"


def _require_supported_python(version_info=None) -> None:
    version_info = sys.version_info if version_info is None else version_info
    if version_info < (3, 11):
        raise SystemExit(
            "Signed AgenTrust records require Python 3.11 or newer. "
            "Run this bootstrap with Python 3.11+."
        )


def main() -> int:
    _require_supported_python()
    digest = hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()
    python = _python_path()
    try:
        current = MARKER.read_text(encoding="utf-8").strip()
    except OSError:
        current = ""

    if not python.is_file() or current != digest:
        ENV_ROOT.parent.mkdir(parents=True, exist_ok=True)
        if not python.is_file():
            venv.EnvBuilder(with_pip=True).create(ENV_ROOT)
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--requirement",
                str(REQUIREMENTS),
            ],
            check=True,
        )
        MARKER.write_text(digest + "\n", encoding="utf-8")

    print(python)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
