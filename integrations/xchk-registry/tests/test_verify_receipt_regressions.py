"""Regressions for the vendored verify_receipt.py (19 Oct 2026).

Two real bundles from the same credential: 01-approval-confirmed (an approved act on ENG-WNP3, 18 Oct 2026) and
03-decision-is-a-denial (a denial, the public trace-spec fixture at f152453e). Every signature in both is genuine.
The mutations below use nothing but the bundles' own bytes — no key, no re-signing — and each one must be refused.

Run: pytest integrations/xchk-registry/tests -q   (the verifier itself is standard-library only)
"""
from __future__ import annotations

import copy
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import verify_receipt as v  # noqa: E402

FX = HERE.parent / "examples" / "approval-outcome"


def load(name):
    return json.loads((FX / name).read_text(encoding="utf-8"))


def run(bundle, tmp_path, name="b.json", **kw):
    p = tmp_path / name
    p.write_text(json.dumps(bundle), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code = v.main(str(p), **kw)
    return code, out.getvalue()


def test_controls_verify(tmp_path):
    good, denied = load("01-approval-confirmed.bundle.json"), load("03-decision-is-a-denial.bundle.json")
    assert good["approver"]["credentialId"] == denied["approver"]["credentialId"], "the two ceremonies share a credential"
    assert good["approver"]["attestationId"] != denied["approver"]["attestationId"], "and are different ceremonies"
    for b in (good, denied):
        code, out = run(b, tmp_path)
        assert code == 0, out
        assert "the signed ask names the ceremony the sealed record commits to" in out
        assert "the signed ask names the ceremony the registry bound to this credential" in out
        assert "FAIL" not in out
    # strict mode: the full approval has every piece of approval evidence
    code, out = run(good, tmp_path, require_approval=True)
    assert code == 0, out


def test_ceremony_transplant_is_refused(tmp_path):
    """Finding 1: a genuine answer to ANOTHER ask by the same credential, beside this record's genuine signed binding.
    Before the fix every check passed and the bundle read as this record's approval."""
    good, denied = load("01-approval-confirmed.bundle.json"), load("03-decision-is-a-denial.bundle.json")
    b = copy.deepcopy(good)
    for k in ("assertion", "challenge", "attestationId"):
        b["approver"][k] = copy.deepcopy(denied["approver"][k])
    b["decision"] = copy.deepcopy(denied["decision"])
    assert b["record"] == good["record"] and b["approver"]["binding"] == good["approver"]["binding"]
    assert b["approver"]["challenge"]["fields"]["attestationId"] == b["approver"]["attestationId"], "the outer field agrees with the transplant"
    code, out = run(b, tmp_path)
    assert code == 1, out
    assert "FAIL the signed ask names the ceremony the sealed record commits to" in out
    assert "FAIL the signed ask names the ceremony the registry bound to this credential" in out
    # the device-side checks still pass on their own: the assertion is real, just not for this record
    assert "OK   passkey assertion signature verifies" in out
    assert "OK   the challenge the device signed is sha256 over the ask" in out


def test_missing_evidence_is_not_an_approval(tmp_path):
    """Finding 2: stripping evidence leaves WAIT steps, exit 0, and a caller that read 0 as 'approval verified' was
    wrong. Default semantics are unchanged (nothing failed); strict mode refuses."""
    good = load("01-approval-confirmed.bundle.json")
    for what, strip in (
        ("approver block", lambda b: b.pop("approver")),
        ("passkey assertion", lambda b: b["approver"].pop("assertion")),
        ("registry-signed identity binding", lambda b: b["approver"].pop("binding")),
        ("ask-v1 challenge", lambda b: b["approver"].pop("challenge")),
    ):
        b = copy.deepcopy(good)
        strip(b)
        code, out = run(b, tmp_path)
        assert code == 0 and "RESULT: verifies offline" in out and "pending" in out, (what, out)
        code, out = run(b, tmp_path, require_approval=True)
        assert code == 3, (what, out)
        assert "does NOT verify AS AN APPROVAL" in out, (what, out)
    stripped = {k: good[k] for k in ("format", "record", "recordHash")}
    code, out = run(stripped, tmp_path, require_approval=True)
    assert code == 3, out


def test_relabelled_identity_is_not_what_is_printed(tmp_path):
    """Finding 3 (the verifier's share of it): the identity line comes from the SIGNED binding, so an unsigned edit of
    the outer email/authLevel changes nothing a reader is shown by the binding check."""
    good = load("01-approval-confirmed.bundle.json")
    b = copy.deepcopy(good)
    b["approver"]["email"] = "synthetic-other-person@example.invalid"
    b["approver"]["authLevel"] = "synthetic-elevated-assurance"
    code, out = run(b, tmp_path)
    assert code == 0
    bound_email = good["approver"]["binding"]["fields"]["approverEmail"]
    assert f"credential ↔ {bound_email}" in out
    assert "synthetic-other-person" not in out.split("identity binding")[1].split("\n")[0]


def test_strict_flag_on_the_command_line(tmp_path):
    import subprocess
    good = load("01-approval-confirmed.bundle.json")
    stripped = {k: good[k] for k in ("format", "record", "recordHash")}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(stripped), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "verify_receipt.py"), str(p), "--require-approval"], capture_output=True, text=True)
    assert r.returncode == 3, r.stdout
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "verify_receipt.py"), str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
