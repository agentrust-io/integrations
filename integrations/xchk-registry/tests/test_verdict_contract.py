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
FIXTURES = HERE.parent / "examples" / "approval-outcome"
_LOADED: dict = {}


def _fixture(row=None):
    """The genuine receipt a row runs on: its own `fixture` when it names one (2 Nov 2026: the anchor-chain rows need a
    receipt that carries anchor.proof, which no 17 Oct fixture does), else the contract's."""
    name = (row or {}).get("fixture", CONTRACT["fixture"])
    if name not in _LOADED:
        _LOADED[name] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return copy.deepcopy(_LOADED[name])


FIXTURE_NAMES = sorted({CONTRACT["fixture"], *(r["fixture"] for r in CONTRACT["evidence"] if r.get("fixture"))})
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


def _corrupt_op_return_root(doc, path):
    """2 Nov 2026: the OP_RETURN guard is pinned only by altering the 32-byte root the transaction committed (payload
    'xCk' + 6 bytes + root); a swap anywhere else in the raw transaction fails sha256d(transaction) = txid first."""
    node, k = _walk(doc, path)
    tx = bytearray(bytes.fromhex(node[k]))
    i = tx.find(b"xCk")
    assert i >= 0, "the genuine anchor transaction carries an xCk payload"
    tx[i + 9] ^= 0x01
    node[k] = bytes(tx).hex()


def _corrupt_merkle_branch(doc, path):
    """2 Nov 2026: the partial-Merkle-tree guard is pinned by altering the first branch hash, which sits after the
    block header (120 bytes on Ravencoin), the tx count (4) and the hash count (1); a swap in the header part of the
    merkleblock fails the header guard instead."""
    node, k = _walk(doc, path)
    mb = bytearray(bytes.fromhex(node[k]))
    hdr_len = len(bytes.fromhex(doc["anchor"]["proof"]["headerHex"]))
    assert len(mb) > hdr_len + 5 + 32, "the genuine merkleblock carries at least one branch hash"
    mb[hdr_len + 5] ^= 0x01
    node[k] = bytes(mb).hex()


def _shorten_ots_root(doc, path):
    """2 Nov 2026: the 32-byte-root guard is pinned by retagging the final sha256 op before the Bitcoin attestation as
    sha1 (0x02), so the replay ends in 20 bytes; a character swap elsewhere replays to a different 32-byte root, which
    only the chain can contradict, and the verifier rightly reports it as an outside fact."""
    node, k = _walk(doc, path)
    raw = bytearray(base64.b64decode(node[k]))
    i = raw.find(v.OTS_BITCOIN)
    assert i > 2 and raw[i - 1] == 0x00 and raw[i - 2] == 0x08, "the genuine proof ends in sha256 then the Bitcoin attestation"
    raw[i - 2] = 0x02
    node[k] = _reb64(node[k], bytes(raw))


OPS = {"clear-user-verified": _clear_user_verified, "retype-as-registration": _retype_as_registration,
       "corrupt-op-return-root": _corrupt_op_return_root, "corrupt-merkle-branch": _corrupt_merkle_branch,
       "shorten-ots-root": _shorten_ots_root}


def _run(doc, tmp_path, strict, keys=False):
    p = tmp_path / "c.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code, report = v.verify(str(p), require_approval=strict, keys_path=KEY_DOCUMENT if keys else None)
    return code, report, out.getvalue()


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_the_genuine_receipt_passes_strict_mode(name, tmp_path):
    code, report, out = _run(_fixture({"fixture": name}), tmp_path, strict=True)
    assert code == 0, out
    assert report["keyDocument"] is None
    code, report, out = _run(_fixture({"fixture": name}), tmp_path, strict=True, keys=True)
    assert code == 0 and report["keyDocument"]["allPinned"] is True, out
    if name == "anchored.bundle.json":   # 2 Nov 2026: every anchor guard ran and passed on the fixture that pins them
        for text in ("manifest path (", "the raw anchor transaction's OP_RETURN carries that manifest root", "sha256d(transaction) = txid",
                     "merkleblock header is the block header shipped with the bundle", "partial Merkle tree reproduces the header's Merkle root",
                     "OpenTimestamps proof replays from the seal hash to a 32-byte Merkle root"):
            assert "OK   " + text in out, f"the anchored fixture did not run the guard {text!r}\n{out[-900:]}"


DELETES = [r for r in CONTRACT["evidence"] if r.get("delete")]
TAMPERS = [r for r in CONTRACT["evidence"] if r.get("tamper")]


@pytest.mark.parametrize("row", DELETES, ids=[r["path"] for r in DELETES])
def test_deleting_evidence_never_passes_strict_mode(row, tmp_path):
    doc = _fixture(row)
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


@pytest.mark.parametrize("row", TAMPERS, ids=[(r["fixture"].split(".")[0] + "/" if r.get("fixture") else "") + r.get("tamper_key", r["path"]) + (":" + r["op"] if r.get("op") else "") for r in TAMPERS])
def test_altering_evidence_fails(row, tmp_path):
    doc = _fixture(row)
    (OPS[row["op"]] if row.get("op") else _tamper)(doc, row.get("tamper_key", row["path"]))
    code, report, out = _run(doc, tmp_path, strict=False, keys=row.get("keys", False))
    assert row["tamper"] == "fails"
    assert code == 1, f"{row.get('tamper_key', row['path'])} altered, exit {code}: {row['why']}\n{out[-600:]}"
    if row.get("fail_text"):   # 2 Nov 2026 (review of #350, drk-ram): exit 1 alone pins nothing; the guard's own line must be there
        assert "FAIL " + row["fail_text"] in out, f"{row['path']} altered: no FAIL line starting {row['fail_text']!r}\n{out[-900:]}"
    assert report["boundIdentity"] is None and report["amendment"] is None
