"""Tests generated from verdict-contract.json (20 Oct 2026; vendored beside the verifier 2 Nov 2026).

The oracle is the contract, not the verifier: each evidence row is deleted and/or tampered in a copy of a real,
genuine receipt, and the verifier must do what the row promises. A row the verifier cannot honour fails here first,
before a reviewer finds it. Run: pytest integrations/xchk-registry/tests -q
"""
from __future__ import annotations

import base64
import copy
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import verify_receipt as v  # noqa: E402

CONTRACT = json.loads((HERE.parent / "verdict-contract.json").read_text(encoding="utf-8"))
BASE = json.loads((HERE.parent / "examples" / "approval-outcome" / CONTRACT["fixture"]).read_text(encoding="utf-8"))
KEY_DOCUMENT = str(HERE.parent / "examples" / "approval-outcome" / CONTRACT["keyDocument"])   # 2 Nov 2026: rows with "keys": true run with --keys


def _walk(doc, path):
    keys = path.split(".")
    node = doc
    for k in keys[:-1]:
        node = node[int(k)] if isinstance(node, list) else node[k]
    last = keys[-1]
    return node, (int(last) if isinstance(node, list) else last)


def _delete(doc, path):
    node, k = _walk(doc, path)
    if isinstance(node, list):
        node.pop(k)
    else:
        node.pop(k)


def _tamper(doc, path):
    node, k = _walk(doc, path)
    val = node[k]
    if isinstance(val, bool):
        node[k] = not val
    elif isinstance(val, int):
        node[k] = val + 1
    elif isinstance(val, str) and val:
        i = len(val) // 2                                  # the middle: never padding, never a prefix
        alphabet = "0123456789abcdef" if all(c in "0123456789abcdef" for c in val) else "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        swap = next(c for c in alphabet if c != val[i])
        node[k] = val[:i] + swap + val[i + 1:]
    else:
        raise AssertionError(f"contract row {path!r} points at a value that cannot be tampered: {val!r}")


def _reb64(original: str, raw: bytes) -> str:
    """Re-encode in the alphabet and padding the bundle used, so only the bytes change."""
    urlsafe = "-" in original or "_" in original
    out = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return out.rstrip("=") if not original.endswith("=") else out


def _clear_user_verified(doc, path):
    """2 Nov 2026 (review of #350, drk-ram): the UV guard is pinned only by clearing the flag itself, bit 0x04 of the
    authenticator data's flags byte (offset 32); a character swap anywhere else fails the signature, not this check."""
    node, k = _walk(doc, path)
    raw = bytearray(v.b64d(node[k]))
    assert raw[32] & 0x04, "the genuine ceremony was user-verified"
    raw[32] &= 0xFB
    node[k] = _reb64(node[k], bytes(raw))


def _retype_as_registration(doc, path):
    node, k = _walk(doc, path)
    cd = json.loads(v.b64d(node[k]).decode("utf-8"))
    assert cd["type"] == "webauthn.get"
    cd["type"] = "webauthn.create"
    node[k] = _reb64(node[k], json.dumps(cd, separators=(",", ":")).encode("utf-8"))


OPS = {"clear-user-verified": _clear_user_verified, "retype-as-registration": _retype_as_registration}


def _run(doc, tmp_path, strict, keys=False):
    p = tmp_path / "c.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code, report = v.verify(str(p), require_approval=strict, keys_path=KEY_DOCUMENT if keys else None)
    return code, report, out.getvalue()


def test_the_genuine_receipt_passes_strict_mode(tmp_path):
    code, report, out = _run(copy.deepcopy(BASE), tmp_path, strict=True)
    assert code == 0, out
    assert report["keyDocument"] is None
    code, report, out = _run(copy.deepcopy(BASE), tmp_path, strict=True, keys=True)
    assert code == 0 and report["keyDocument"]["allPinned"] is True, out


DELETES = [r for r in CONTRACT["evidence"] if r.get("delete")]
TAMPERS = [r for r in CONTRACT["evidence"] if r.get("tamper")]


@pytest.mark.parametrize("row", DELETES, ids=[r["path"] for r in DELETES])
def test_deleting_evidence_never_passes_strict_mode(row, tmp_path):
    doc = copy.deepcopy(BASE)
    for extra in row.get("delete_with", []):
        _delete(doc, extra)
    _delete(doc, row["path"])
    assert row["delete"] in ("strict-refuses", "fails")
    if row["delete"] == "fails":   # 20 Oct 2026: removing it is a failed check even in the default run
        code, report, out = _run(doc, tmp_path, strict=False, keys=row.get("keys", False))
        assert code == 1, f"{row['path']} deleted, default exit {code}: {row['why']}\n{out[-600:]}"
        if row.get("fail_text"):   # 2 Nov 2026: and it is THIS check that failed, not a neighbour
            assert "FAIL " + row["fail_text"] in out, f"{row['path']} deleted: no FAIL line starting {row['fail_text']!r}\n{out[-900:]}"
    code, report, out = _run(doc, tmp_path, strict=True, keys=row.get("keys", False))
    assert code in (1, 3), f"{row['path']} deleted, strict exit {code}: {row['why']}\n{out[-600:]}"


@pytest.mark.parametrize("row", TAMPERS, ids=[r.get("tamper_key", r["path"]) + (":" + r["op"] if r.get("op") else "") for r in TAMPERS])
def test_altering_evidence_fails(row, tmp_path):
    doc = copy.deepcopy(BASE)
    (OPS[row["op"]] if row.get("op") else _tamper)(doc, row.get("tamper_key", row["path"]))
    code, report, out = _run(doc, tmp_path, strict=False, keys=row.get("keys", False))
    assert row["tamper"] == "fails"
    assert code == 1, f"{row.get('tamper_key', row['path'])} altered, exit {code}: {row['why']}\n{out[-600:]}"
    if row.get("fail_text"):   # 2 Nov 2026 (review of #350, drk-ram): exit 1 alone pins nothing; the guard's own line must be there
        assert "FAIL " + row["fail_text"] in out, f"{row['path']} altered: no FAIL line starting {row['fail_text']!r}\n{out[-900:]}"
    assert report["boundIdentity"] is None and report["amendment"] is None
