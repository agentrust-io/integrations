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


def test_amendment_is_what_the_sealed_record_commits_to(tmp_path):
    """Finding 3: decision.amendment is unsigned text. 07 is a genuine approval with changes: the sealed record's
    paramsHash recomputes over the amended action binding and the amendment cites the signed ask. An amendment typed
    into the plain approval after issue, an amended command edited after issue, or an amendment citing another ask
    all fail."""
    amended = load("07-amended.bundle.json")
    code, out = run(amended, tmp_path, require_approval=True)
    assert code == 0, out
    assert "OK   the sealed record commits to the amended action binding" in out
    assert "OK   the bound command is the amended command" in out
    assert "OK   the amendment cites the ask the person answered" in out
    assert "approved WITH CHANGES" in out
    good = load("01-approval-confirmed.bundle.json")
    b = copy.deepcopy(good)
    b["decision"]["amendment"] = {"command": "synthetic alternate command", "byEmail": good["decision"]["by"],
                                  "at": good["decision"]["respondedAt"], "originalParamsHash": good["decision"]["actionParamsHash"]}
    code, out = run(b, tmp_path)
    assert code == 1 and "FAIL the sealed record commits to the amended action binding" in out, out
    b = copy.deepcopy(amended)
    b["decision"]["amendment"]["command"] += " ; synthetic extra"
    code, out = run(b, tmp_path)
    assert code == 1 and "FAIL the sealed record commits to the amended action binding" in out, out
    b = copy.deepcopy(amended)
    b["decision"]["amendment"]["originalParamsHash"] = "0" * 64
    code, out = run(b, tmp_path)
    assert code == 1 and "FAIL the amendment cites the ask the person answered" in out, out


def _boundas(bundle):
    """The exact preimage the registry hashed for 07, as a bundle served from 19 Oct 2026 carries it."""
    rec, am = bundle["record"], bundle["decision"]["amendment"]
    return {"tool": rec["tool"], "command": am["command"], "path": None, "summary": rec["summary"], "amount": None, "artifactHash": None}


def test_the_served_preimage_is_checked_against_the_seal_and_the_amendment(tmp_path):
    """amendment.boundAs is unsigned too: it counts only when it hashes to the SEALED paramsHash and its command is the
    amended command. A preimage of another act, or a true preimage beside an edited amendment text, fails."""
    amended = load("07-amended.bundle.json")
    b = copy.deepcopy(amended)
    b["decision"]["amendment"]["boundAs"] = _boundas(amended)
    code, out = run(b, tmp_path, require_approval=True)
    assert code == 0 and "sha256 over amendment.boundAs" in out, out
    b2 = copy.deepcopy(b)
    b2["decision"]["amendment"]["boundAs"]["summary"] = "synthetic other summary"
    code, out = run(b2, tmp_path)
    assert code == 1 and "FAIL the sealed record commits to the amended action binding" in out, out
    b3 = copy.deepcopy(b)
    b3["decision"]["amendment"]["command"] = "synthetic alternate command"
    code, out = run(b3, tmp_path)
    assert code == 1 and "FAIL the bound command is the amended command" in out, out
    for shape in (None, [], "x", {"command": 7}, {"tool": 1.5}):
        b4 = copy.deepcopy(amended)
        b4["decision"]["amendment"]["boundAs"] = shape
        code, out = run(b4, tmp_path)
        assert code in (0, 1) and "Traceback" not in out, (shape, out)


def test_a_long_summary_needs_the_served_preimage():
    """The record keeps the summary capped at 400 chars and trimmed; the registry hashed the full one (up to 2000).
    Rebuilt from the record the binding cannot match; the served preimage does. JS slicing counts UTF-16 units."""
    full = "  " + "\U0001F600" * 300 + "y" * 1600 + "  "
    rec = {"tool": "terminal", "summary": full[:400].strip()}
    am = {"command": "rm -rf build/tmp"}
    served = {"tool": "terminal", "command": "rm -rf build/tmp", "path": None, "summary": v.js_slice(full, 2000), "amount": None, "artifactHash": None}
    rec["paramsHash"] = v.sha256_hex(v.canonical(served))
    rebuilt, was_served = v.amended_binding(rec, am)
    assert not was_served and v.sha256_hex(v.canonical(rebuilt)) != rec["paramsHash"]
    got, was_served = v.amended_binding(rec, dict(am, boundAs=served))
    assert was_served and v.sha256_hex(v.canonical(got)) == rec["paramsHash"]
    assert len(v.js_slice(full, 2000).encode("utf-16-le")) == 4000 and len(v.js_slice(full, 2000)) < 2000


def test_an_escalated_ask_without_a_digest_skips_only_the_citation(tmp_path):
    """A second approver's ask carries no action digest (decision.actionParamsHash null): the citation is reported as
    not checkable, the seal commitment is still required."""
    b = copy.deepcopy(load("07-amended.bundle.json"))
    b.pop("approver")
    b["decision"]["actionParamsHash"] = None
    code, out = run(b, tmp_path)
    assert code == 0 and "citation of it is not checkable" in out and "OK   the sealed record commits" in out, out
    b["decision"]["amendment"]["command"] += " ; synthetic extra"
    code, out = run(b, tmp_path)
    assert code == 1, out


def test_json_report_names_what_ran(tmp_path):
    """Finding 2: a caller acts on the structured report, not on exit 0. `checks` lists only what RAN; a stripped
    bundle has fewer checks, the missing evidence named and exit 3 in strict mode; the amendment's standing is explicit
    (null when none; committed only when the sealed record commits to it)."""
    import subprocess
    good = load("01-approval-confirmed.bundle.json")
    p = tmp_path / "g.json"
    p.write_text(json.dumps(good), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code, rep = v.verify(str(p))
    assert code == 0 and rep["result"] == "verifies" and rep["exit"] == 0 and rep["amendment"] is None
    assert rep["checks"] and all(c["status"] == "OK" for c in rep["checks"]) and rep["approvalEvidenceMissing"] == []
    full = len(rep["checks"])
    stripped = {k: good[k] for k in ("format", "record", "recordHash")}
    p.write_text(json.dumps(stripped), encoding="utf-8")
    with redirect_stdout(out):
        code, rep = v.verify(str(p), require_approval=True)
    assert code == 3 and rep["result"] == "approval-evidence-missing"
    assert "approver block" in rep["approvalEvidenceMissing"] and len(rep["checks"]) < full
    amended = load("07-amended.bundle.json")
    p.write_text(json.dumps(amended), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "verify_receipt.py"), str(p), "--json", "--require-approval"], capture_output=True, text=True, check=False)
    rep = json.loads(r.stdout)
    assert r.returncode == 0 and rep["exit"] == 0 and rep["amendment"]["committed"] is True
    assert rep["amendment"]["command"] == amended["decision"]["amendment"]["command"]
    assert any("approved WITH CHANGES" in line for line in rep["transcript"])


def test_a_decision_that_is_not_an_object_is_a_verdict_not_a_crash(tmp_path):
    good = load("01-approval-confirmed.bundle.json")
    b = copy.deepcopy(good)
    b["decision"] = "string"
    code, out = run(b, tmp_path)
    assert code == 1, out


def test_wrong_types_end_in_a_verdict_never_a_traceback(tmp_path):
    """A type-mutation sweep over every field (19 Oct 2026) found 35 lines that raised on a string where an object
    belongs, a float in a sealed body, a lone surrogate, bad base64. Each now ends in exit 1 and a JSON report."""
    good = load("01-approval-confirmed.bundle.json")
    cases = [(("issuer",), None), (("record",), "x"), (("record", "seq"), 1.5), (("record", "summary"), "\ud83d"),
             (("registrySignature",), "x"), (("registrySignature", "signatures"), [None]), (("seal",), -1),
             (("approver", "binding", "fields"), "x"), (("approver", "challenge"), "x"), (("anchor",), "x"),
             (("legalHolds",), "x")]
    for path, val in cases:
        b = copy.deepcopy(good)
        node = b
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = val
        p = tmp_path / "m.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            code, rep = v.verify(str(p), require_approval=True)
        assert code == 1 and rep["exit"] == 1 and rep["result"] == "fails", (path, val, out.getvalue()[-300:])
        json.dumps(rep)


def test_identity_is_reported_from_the_signed_binding_only(tmp_path):
    """Finding 3, the matrix row 'change only outer approver.email and authLevel': the structured report's identity
    comes from approver.binding.fields; the relabelled bundle reports the bound person, and the transcript says the
    readable labels differ."""
    good = load("01-approval-confirmed.bundle.json")
    bound = good["approver"]["binding"]["fields"]
    b = copy.deepcopy(good)
    b["approver"]["email"] = "synthetic-other-person@example.invalid"
    b["approver"]["authLevel"] = "synthetic-elevated-assurance"
    p = tmp_path / "r.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code, rep = v.verify(str(p), require_approval=True)
    assert code == 0, out.getvalue()
    assert rep["boundIdentity"]["email"] == bound["approverEmail"] and rep["boundIdentity"]["authLevel"] == bound["authLevel"]
    assert "synthetic" not in json.dumps(rep["boundIdentity"])
    assert "readable approver labels differ from the signed binding" in out.getvalue()
    p.write_text(json.dumps(good), encoding="utf-8")
    with redirect_stdout(io.StringIO()) as quiet:
        code, rep = v.verify(str(p))
    assert code == 0 and "labels differ" not in quiet.getvalue()


def test_an_amendment_on_a_record_that_seals_no_digest_is_pending_not_failed(tmp_path):
    """Ceremony records sealed before 19 Sep 2026 carry no paramsHash, so the seal commits to no command. The amendment
    is then not checkable: a WAIT, committed false, and never the 'sealed record commits' FAIL (that falsely failed
    four genuine September receipts). Built from 07 with paramsHash removed: the record hash then fails, as it must,
    and the amendment line is still the WAIT."""
    b = copy.deepcopy(load("07-amended.bundle.json"))
    del b["record"]["paramsHash"]
    p = tmp_path / "nd.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code, rep = v.verify(str(p))
    text = out.getvalue()
    assert rep["amendment"] == {"command": b["decision"]["amendment"]["command"], "checkable": False, "committed": False}
    assert "seals no action digest" in text and "FAIL the sealed record commits" not in text
    assert "FAIL record hash recomputed" in text and code == 1


def test_approval_evidence_without_the_seal_chain_is_not_a_sealed_approval(tmp_path):
    """Review of #350 (noah-ing, 20 Oct 2026): from the valid 01 receipt, deleting only the seal, only the Merkle path,
    both, or only the registry's signature over the seal left the approval evidence intact and strict mode passed.
    Strict mode now also requires the seal chain and says which part is missing; the default run still exits 0 with
    the steps pending, as before."""
    good = load("01-approval-confirmed.bundle.json")
    cases = {
        "seal": (lambda b: b.pop("seal"), "the seal over the record's window"),
        "merkle": (lambda b: b.pop("merkle"), "the Merkle path from the record to the seal"),
        "seal+merkle": (lambda b: (b.pop("seal"), b.pop("merkle")), "the seal over the record's window"),
        "seal signature": (lambda b: [b["registrySignature"].pop(k, None) for k in ("signature", "signatures")], "the registry's signature over the seal"),
    }
    for name, (mutate, missing) in cases.items():
        b = copy.deepcopy(good)
        mutate(b)
        p = tmp_path / "s.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        with redirect_stdout(io.StringIO()) as out:
            code, rep = v.verify(str(p), require_approval=True)
        assert code == 3 and rep["result"] == "seal-chain-incomplete", (name, out.getvalue()[-400:])
        assert missing in rep["sealChainMissing"] and rep["approvalEvidenceMissing"] == [], name
        assert "does NOT verify AS A SEALED APPROVAL" in out.getvalue(), name
        with redirect_stdout(io.StringIO()):
            code, rep = v.verify(str(p))
        assert code == 0 and rep["result"] == "verifies" and missing in rep["sealChainMissing"], name
    p = tmp_path / "g.json"
    p.write_text(json.dumps(good), encoding="utf-8")
    with redirect_stdout(io.StringIO()):
        code, rep = v.verify(str(p), require_approval=True)
    assert code == 0 and rep["sealChainMissing"] == [], "the sealed control still passes strict mode"


def test_a_decision_citing_another_record_is_refused(tmp_path):
    """Section 5b (20 Oct 2026): the decision block must cite the sealed record's attestationHash. The browser verifier
    has checked this since 19 Sep; the Python verifier did not, until a written contract of what each piece of evidence
    must do found the gap. The mutation uses another real ceremony's value, from the denial bundle."""
    good, denied = load("01-approval-confirmed.bundle.json"), load("03-decision-is-a-denial.bundle.json")
    assert good["decision"]["attestationHash"] == good["record"]["attestationHash"]
    b = copy.deepcopy(good)
    b["decision"]["attestationHash"] = denied["decision"]["attestationHash"]
    assert b["decision"]["attestationHash"] != good["record"]["attestationHash"]
    code, out = run(b, tmp_path)
    assert code == 1, out
    assert "the decision block does NOT cite this record's attestation hash" in out
    code, out = run(good, tmp_path)
    assert code == 0 and "the decision block cites this record's attestation hash" in out, out
