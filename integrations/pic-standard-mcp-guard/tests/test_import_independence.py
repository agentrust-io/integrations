"""pic_trace_verify must verify with only agentrust_trace + rfc8785 + stdlib."""

from __future__ import annotations

import pathlib
import subprocess
import sys

MODULE_DIR = str(pathlib.Path(__file__).resolve().parent.parent)


def test_pic_trace_verify_does_not_load_producer_dependencies():
    code = (
        "import sys;"
        f"sys.path.insert(0, {MODULE_DIR!r});"
        "import pic_trace_verify;"
        "banned=[m for m in ('pic_standard','agentrust_trace_adapters') if m in sys.modules];"
        "print(','.join(banned));"
        "sys.exit(1 if banned else 0)"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"producer deps leaked: {result.stdout}\n{result.stderr}"
