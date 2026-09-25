#!/usr/bin/python3
"""Fuzz the capture engines' state loader and baseline seal check.

The approved baseline is a file on disk that the engines read at every session
start, from a SessionStart hook. Its documented contract is that a missing,
unreadable or corrupt file reads as absent (None) so the next run re-establishes
it, and that check_seal() never raises. A crash here breaks the hook for every
future session, which trains the user to switch it off.

Properties:
  * load_state() returns None or a dict for any file content.
  * check_seal() on whatever load_state() returned gives one of its three
    declared states and does not raise.
"""
import os
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from agentrust_capture_core import (
        INTEGRITY_BROKEN,
        INTEGRITY_OK,
        INTEGRITY_UNSEALED,
        check_seal,
        load_state,
    )

_STATES = {INTEGRITY_OK, INTEGRITY_UNSEALED, INTEGRITY_BROKEN}
_PATH = Path(os.path.join(tempfile.mkdtemp(prefix="cflite-state-"), "baseline.json"))


def TestOneInput(data: bytes) -> None:
    _PATH.write_bytes(data)
    loaded = load_state(_PATH)
    assert loaded is None or isinstance(loaded, dict)
    assert check_seal(loaded) in _STATES


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
