"""The suite needs the post-quantum verifier (2 Nov 2026). Since the hybrid-signature fix, a required ML-DSA-65 half
that cannot be checked is a strict-mode refusal, not a pass: a label is not a signature. So without `dilithium-py`
every hybrid receipt exits 3 under --require-approval, and these tests would fail by the dozen for the wrong reason
(13 of them did, in a venv that had only pytest). Stop before the first test and say so instead."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_receipt as v  # noqa: E402


def pytest_sessionstart(session):
    if v.ml_dsa_65_verify(b"\x00" * 32, b"m", b"s") is None:
        pytest.exit("these tests need dilithium-py: the verifier checks the ML-DSA-65 half of every hybrid receipt, and "
                    "without it --require-approval refuses every hybrid receipt by design. pip install dilithium-py "
                    "(pure Python, MIT)", returncode=1)
