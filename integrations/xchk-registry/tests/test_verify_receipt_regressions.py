"""Regressions for the vendored verify_receipt.py (19 Oct 2026).

Two real bundles from the same credential: 01-approval-confirmed (an approved act on ENG-WNP3, 18 Oct 2026) and
03-decision-is-a-denial (a denial, the public trace-spec fixture at f152453e). Every signature in both is genuine.
The mutations below use nothing but the bundles' own bytes — no key, no re-signing — and each one must be refused.

Run: pytest integrations/xchk-registry/tests -q   (the verifier itself is standard-library only)
"""
from __future__ import annotations

import copy
import hashlib
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
    not checkable, the seal commitment is still required. Later on 20 Oct 2026: not checkable means pending and NOT
    committed (it was reported committed before), and strict mode refuses."""
    b = copy.deepcopy(load("07-amended.bundle.json"))
    b.pop("approver")
    b["decision"]["actionParamsHash"] = None
    code, out = run(b, tmp_path)
    assert code == 0 and "the amendment's citation of it cannot be checked" in out and "OK   the sealed record commits" in out, out
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
    assert rep["amendment"] is None   # 2 Nov 2026: the record hash fails below, and a report that does not verify commits to nothing
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


def test_a_decision_without_the_citation_is_refused(tmp_path):
    """Section 5b, later on 20 Oct 2026 (review of #350, private): the check above ran only when the citation was present,
    so a decision block with `attestationHash` removed (or null) skipped it and the verdict stayed approval-confirmed.
    Every ceremony record the registry has written since the ledger began (7 Aug 2026) carries the attestation hash, sealed
    before the record is appended, and every decision block it issues cites it: a decision block with no citation was never
    issued. Its absence is a failed check in the default run and in strict mode, never a pending step."""
    good = load("01-approval-confirmed.bundle.json")
    assert good["decision"]["attestationHash"]
    for mutate in (lambda d: d.pop("attestationHash"), lambda d: d.__setitem__("attestationHash", None), lambda d: d.__setitem__("attestationHash", "")):
        b = copy.deepcopy(good)
        mutate(b["decision"])
        code, out = run(b, tmp_path)
        assert code == 1, out
        assert "the decision block carries NO attestation-hash citation" in out
        code, out = run(b, tmp_path, require_approval=True)
        assert code == 1, out
    code, out = run(good, tmp_path, require_approval=True)
    assert code == 0, out


def test_an_amendment_without_the_asks_digest_is_never_committed(tmp_path):
    """Later on 20 Oct 2026 (review of #350, the class of 5b): without decision.actionParamsHash the citation leg of 5c
    defaulted to 'cites', so a bundle with the digest removed reported the amendment COMMITTED on a check that never ran.
    With the challenge present the removal fails in 5a; without one (a bundle issued before 18 Oct 2026) nothing failed.
    Now: citation pending, never committed, strict mode refuses, and the control still commits."""
    import io as _io
    from contextlib import redirect_stdout as _rs
    good = load("07-amended.bundle.json")
    assert good["decision"]["actionParamsHash"] and good["approver"].get("challenge")

    def rep_of(b, strict=False):
        p = tmp_path / "amend.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        out = _io.StringIO()
        with _rs(out):
            code, rep = v.verify(str(p), require_approval=strict)
        return code, rep, out.getvalue()

    code, rep, _ = rep_of(copy.deepcopy(good))
    assert code == 0 and rep["amendment"]["committed"] is True and rep["amendment"]["citesAsk"] is True
    b = copy.deepcopy(good)
    b["decision"].pop("actionParamsHash")
    b["approver"].pop("challenge")                       # the shape of a bundle issued before 18 Oct 2026
    code, rep, out = rep_of(b)
    assert code == 0, out                                # nothing FAILED: the steps that could not run are pending
    assert rep["amendment"]["committed"] is False and rep["amendment"]["citesAsk"] is None, rep["amendment"]
    assert "the amendment's citation of it cannot be checked" in out
    code, rep, _ = rep_of(b, strict=True)
    assert code == 3 and "the ask's action digest (decision.actionParamsHash), which the amendment must cite" in rep["approvalEvidenceMissing"]
    b = copy.deepcopy(good)
    b["decision"].pop("actionParamsHash")                # challenge kept: the signed ask no longer matches
    code, rep, _ = rep_of(b)
    assert code == 1 and rep["amendment"] is None   # 2 Nov 2026: withheld on a failed verdict


def test_a_hybrid_signature_with_a_half_removed_is_refused(tmp_path):
    """Review of #350 (rajnisht7, 2 Nov 2026): the verifier checked only the signatures a bundle carried, so a hybrid
    signature with either half removed, the list removed down to the legacy single field, or the `alg` label rewritten
    to match, still verified under --require-approval. The required set now comes from signed fields (the sealed
    profile's signing dial; for older seals the seal's windowStart), on the seal, the profile and the binding alike."""
    for name in ("01-approval-confirmed.bundle.json", "07-amended.bundle.json"):
        good = load(name)
        assert [s["alg"] for s in good["registrySignature"]["signatures"]] == ["ed25519", "ml-dsa-65"]
        assert good["profile"]["document"]["dials"]["signing"] == "ed25519+ml-dsa-65"
        for drop in ("ml-dsa-65", "ed25519"):
            b = copy.deepcopy(good)
            b["registrySignature"]["signatures"] = [s for s in b["registrySignature"]["signatures"] if s["alg"] != drop]
            code, out = run(b, tmp_path, require_approval=True)
            assert code == 1 and f"the {drop} signature this receipt requires is missing" in out, out
        b = copy.deepcopy(good)
        del b["registrySignature"]["signatures"]                       # the legacy single Ed25519 field is left
        code, out = run(b, tmp_path)
        assert code == 1 and "ml-dsa-65 signature this receipt requires is missing" in out, out
        b = copy.deepcopy(good)
        b["registrySignature"]["signatures"] = b["registrySignature"]["signatures"][:1]
        b["registrySignature"]["alg"] = "ed25519"                       # relabelled to match: the label is not consulted
        code, out = run(b, tmp_path)
        assert code == 1 and "ml-dsa-65 signature this receipt requires is missing" in out, out
        for where in (("profile", "signature"), ("approver", "binding")):
            b = copy.deepcopy(good)
            obj = b[where[0]][where[1]]
            obj["signatures"] = [s for s in obj["signatures"] if s["alg"] != "ml-dsa-65"]
            code, out = run(b, tmp_path)
            assert code == 1 and "ml-dsa-65 signature this receipt requires is missing" in out, (where, out)


def test_a_report_that_does_not_verify_names_nobody_and_commits_to_nothing(tmp_path):
    """Review of #350 (rajnisht7, 2 Nov 2026): on a receipt whose seal signature is corrupted, boundIdentity and
    amendment.committed were still fully populated, so a caller reading them before the exit code could act on them.
    Both are null on every non-zero exit, strict refusals included."""
    def rep_of(b, strict=False):
        p = tmp_path / "r.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            return v.verify(str(p), require_approval=strict)
    good = load("07-amended.bundle.json")
    code, rep = rep_of(good)
    assert code == 0 and rep["boundIdentity"]["email"] and rep["amendment"]["committed"] is True
    b = copy.deepcopy(good)
    sig = b["registrySignature"]["signatures"][0]["signature"]
    i = len(sig) // 2
    b["registrySignature"]["signatures"][0]["signature"] = sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]
    code, rep = rep_of(b)
    assert code == 1 and rep["failed"] >= 1 and rep["boundIdentity"] is None and rep["amendment"] is None, rep
    b = copy.deepcopy(good)
    del b["seal"]                                                      # strict refuses: nothing failed, nothing is reported either
    code, rep = rep_of(b, strict=True)
    assert code == 3 and rep["boundIdentity"] is None and rep["amendment"] is None, rep


def test_the_verifier_writes_utf8_whatever_the_console_locale(tmp_path):
    """Review of #350 (drk-ram, 2 Nov 2026, Windows): under a cp1252 console the human lines (U+2194, an em dash) and
    the --json report raised UnicodeEncodeError, exit 1 with a traceback — the exit of a failed check. The CLI now
    reconfigures stdout to UTF-8; here PYTHONIOENCODING stands in for the Windows console."""
    import os
    import subprocess
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONUTF8="0", PYTHONLEGACYWINDOWSSTDIO="1")
    bundle = str(FX / "01-approval-confirmed.bundle.json")
    for flags in ([], ["--json", "--require-approval"]):
        r = subprocess.run([sys.executable, str(HERE.parent / "verify_receipt.py"), bundle] + flags, capture_output=True, env=env, timeout=180)
        assert r.returncode == 0 and b"UnicodeEncodeError" not in r.stderr, r.stderr.decode(errors="replace")[-600:]
        if flags:
            assert json.loads(r.stdout.decode("utf-8"))["exit"] == 0


def test_required_algs_reads_signed_fields_only():
    """2 Nov 2026 (review): the profile's signing dial decides when a profile is sealed; the seal's own windowStart
    otherwise; nothing when the bundle is not sealed. The alg label and the key list are never consulted."""
    pre, post = {"windowStart": "2026-09-06T14:55:12.187Z"}, {"windowStart": "2026-10-17T15:44:25.565Z"}
    assert v.required_algs(pre, None) == {"ed25519"}
    assert v.required_algs(post, None) == {"ed25519", "ml-dsa-65"}
    assert v.required_algs(post, {"dials": {"signing": "ed25519"}}) == {"ed25519"}
    assert v.required_algs(pre, {"dials": {"signing": "ed25519+ml-dsa-65"}}) == {"ed25519", "ml-dsa-65"}
    assert v.required_algs(post, {"dials": {"signing": "none"}}) == {"ed25519", "ml-dsa-65"}   # no dial: the date decides
    assert v.required_algs(None, None) is None and v.required_algs({"windowStart": 5}, None) is None
    assert v.binding_required({"signing": "ed25519"}, {"ed25519", "ml-dsa-65"}) == {"ed25519"}
    assert v.binding_required({"approverEmail": "x"}, {"ed25519"}) == {"ed25519"}


def test_an_edited_dial_does_not_relax_the_requirement(tmp_path):
    """The profile's signing dial is read only from a document that hashes to the sealed profileHash, so an editor who
    writes `signing: ed25519` into the bundle and strips the post-quantum half gets BOTH failures: the profile no longer
    hashes, and the date fallback still requires the half. (The review's mutant that skips the genuine-dial branch
    cannot be killed with today's fixtures: every sealed profile is from after the switch and agrees with the date; a
    receipt from a registry whose sealed profile says `ed25519` after the switch would pin it.) A binding that carries
    its own mode inside the signed fields is decided by that mode; editing it fails the binding's signature instead."""
    good = load("01-approval-confirmed.bundle.json")
    b = copy.deepcopy(good)
    b["profile"]["document"]["dials"]["signing"] = "ed25519"
    b["registrySignature"]["signatures"] = b["registrySignature"]["signatures"][:1]
    code, out = run(b, tmp_path)
    assert code == 1 and "FAIL profile document does NOT hash" in out
    assert "registry signature over the seal hash: the ml-dsa-65 signature this receipt requires is missing" in out, out
    b = copy.deepcopy(good)
    b["approver"]["binding"]["fields"]["signing"] = "ed25519"
    b["approver"]["binding"]["signatures"] = b["approver"]["binding"]["signatures"][:1]
    code, out = run(b, tmp_path)
    assert code == 1 and "DOES NOT verify" in out                     # the edited fields no longer match the signature
    assert "identity binding" in out and "this receipt requires is missing" not in out, out


def test_a_required_half_that_cannot_be_checked_here_is_not_a_pass(tmp_path, monkeypatch):
    """Review of round one (2 Nov 2026): without dilithium-py the ML-DSA slot is a WAIT, and a required WAIT counted as
    present, so garbage in that slot passed even --require-approval. Now strict mode refuses and names the half; the
    default run stays a WAIT, as every unverifiable step does. With dilithium-py present the same garbage simply fails."""
    def rep_of(b, strict=False):
        p = tmp_path / "w.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            code, rep = v.verify(str(p), require_approval=strict)
        return code, rep, out.getvalue()
    good = load("01-approval-confirmed.bundle.json")
    b = copy.deepcopy(good)
    b["registrySignature"]["signatures"][1]["signature"] = "AAAA"
    if v.ml_dsa_65_verify(b"\x00" * 32, b"m", b"s") is not None:   # dilithium-py present: the garbage half is a failed check
        code, rep, out = rep_of(b, strict=True)
        assert code == 1 and "ml-dsa-65 signature DOES NOT verify" in out
    monkeypatch.setattr(v, "ml_dsa_65_verify", lambda *a: None)       # the stock install: the half cannot be checked
    code, rep, out = rep_of(b)
    assert code == 0 and rep["pending"] >= 1 and "WAIT registry signature over the seal hash: ml-dsa-65" in out, out
    code, rep, out = rep_of(b, strict=True)
    # with no ML-DSA at all, the binding's and the profile's halves are unverifiable too: strict names every one of them
    assert code == 3 and rep["result"] in ("seal-chain-incomplete", "approval-evidence-missing"), out
    assert any(s.startswith("registry signature over the seal hash: its ml-dsa-65 half, which this receipt requires") for s in rep["sealChainMissing"]), rep
    assert any("identity binding" in s and "ml-dsa-65 half" in s for s in rep["approvalEvidenceMissing"]), rep
    b = copy.deepcopy(good)
    b["approver"]["binding"]["signatures"][1]["signature"] = "AAAA"
    code, rep, out = rep_of(b, strict=True)
    assert code == 3 and any("identity binding" in s and "ml-dsa-65 half" in s for s in rep["approvalEvidenceMissing"]), rep


def test_withheld_names_what_a_failed_report_leaves_out(tmp_path):
    """So a consumer can tell absent from withheld (review of round one): null fields come with `withheld` naming them
    on every non-zero exit, and `withheld` is empty on a verdict of 0."""
    def rep_of(b, strict=False):
        p = tmp_path / "wh.json"
        p.write_text(json.dumps(b), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            return v.verify(str(p), require_approval=strict)
    good = load("07-amended.bundle.json")
    code, rep = rep_of(good)
    assert code == 0 and rep["withheld"] == [] and rep["amendment"]["committed"] is True
    b = copy.deepcopy(good)
    del b["seal"]
    code, rep = rep_of(b, strict=True)
    assert code == 3 and rep["withheld"] == ["boundIdentity", "amendment"] and rep["boundIdentity"] is None


def test_the_artifact_check_pins_the_file(tmp_path):
    """The --artifact path: the file's sha256 against the record's artifactHash. No fixture is a file-write record, so
    the record hash fails here by construction; the two file lines are what this pins (unpinned until 2 Nov 2026)."""
    good = load("01-approval-confirmed.bundle.json")
    f1, f2 = tmp_path / "written.bin", tmp_path / "other.bin"
    f1.write_bytes(b"the bytes this action wrote")
    f2.write_bytes(b"some other bytes")
    b = copy.deepcopy(good)
    b["record"]["artifactHash"] = hashlib.sha256(f1.read_bytes()).hexdigest()
    p = tmp_path / "a.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    for f, want in ((f1, "OK   file"), (f2, "FAIL file")):
        out = io.StringIO()
        with redirect_stdout(out):
            code = v.main(str(p), str(f))
        assert code == 1 and f"{want} {f} is {'the one' if want.startswith('OK') else 'NOT the one'} this action wrote" in out.getvalue(), out.getvalue()
    out = io.StringIO()
    with redirect_stdout(out):
        v.main(str(p), artifact_path=str(f1))                        # the keyword form the CLI uses
    assert "is the one this action wrote" in out.getvalue()
    out = io.StringIO()
    with redirect_stdout(out):
        pg = tmp_path / "g.json"
        pg.write_text(json.dumps(good), encoding="utf-8")
        v.main(str(pg), str(f1))
    assert "FAIL this record carries no artifactHash" in out.getvalue()


KEY_DOCUMENTS = FX / "xchk-keys"   # the registries' /.well-known/xchk-keys.json as served on 2 Nov 2026


def _rep(bundle, tmp_path, strict=False, keys=None):
    p = tmp_path / "k.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        code, rep = v.verify(str(p), require_approval=strict, keys_path=keys)
    return code, rep, out.getvalue()


def test_a_bundle_re_keyed_outside_the_registry_passes_until_the_key_document_is_supplied(tmp_path):
    """Review of #350 (drk-ram, 2 Nov 2026): fixture 01 re-signed under his own Ed25519 and ML-DSA-65 keys, the pinned
    list and the root statement's list rewritten to match, still exited 0 under --require-approval, because every key
    the verifier checks is the one the bundle carries. Fixture 09 is that bundle (verify/tests/rekey_fixture.py). With
    --keys and the registry's published key document, every pinned key fails BY NAME; the genuine receipts pass."""
    rekeyed = load("09-re-keyed-outside-the-registry.bundle.json")
    genuine = load("01-approval-confirmed.bundle.json")
    assert rekeyed["record"] == genuine["record"] and rekeyed["seal"] == genuine["seal"], "the sealed content is untouched"
    own = {k["alg"]: k["keyId"] for k in rekeyed["registrySignature"]["keys"]}
    assert own != {k["alg"]: k["keyId"] for k in genuine["registrySignature"]["keys"]}
    code, rep, out = _rep(rekeyed, tmp_path, strict=True)                       # the finding, reproduced
    assert code == 0 and "FAIL" not in out and rep["keyDocument"] is None, out
    assert "checked against THEMSELVES only" in out
    doc = str(KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json")
    code, rep, out = _rep(rekeyed, tmp_path, strict=True, keys=doc)            # closed
    assert code == 1 and rep["result"] == "fails", out
    for alg, kid in own.items():
        assert f"FAIL the registry's key document does not list pinned key {alg}/{kid}" in out, out
    assert rep["keyDocument"] == {"registry": "https://in.xchk.io", "servedAt": "2026-11-02T03:01:09.306Z", "allPinned": False}
    assert rep["boundIdentity"] is None
    for name in ("01-approval-confirmed", "03-decision-is-a-denial", "07-amended"):
        code, rep, out = _rep(load(name + ".bundle.json"), tmp_path, keys=doc)
        assert code == 0 and rep["keyDocument"]["allPinned"] is True, (name, out)
        assert "lists pinned key ed25519/5ecb3da505414c4f" in out and "is the registry's root key" in out, (name, out)


def test_the_other_registrys_key_document_refuses_this_registrys_receipt(tmp_path):
    """xchk.me publishes its own keys and root: an in.xchk.io receipt checked against it fails on every pinned key and on
    the root. The document the relying party pins decides which registry it trusts."""
    code, rep, out = _rep(load("01-approval-confirmed.bundle.json"), tmp_path, keys=str(KEY_DOCUMENTS / "xchk.me.2026-11-02.json"))
    assert code == 1 and rep["keyDocument"]["allPinned"] is False, out
    assert "FAIL the registry's key document does not list pinned key ed25519/5ecb3da505414c4f" in out
    assert "FAIL the bundle's root key acc7ad1aeb3ef177 is NOT the registry's root key" in out


def test_a_retired_key_still_pins_and_a_revoked_key_fails(tmp_path):
    """A receipt sealed under a key the registry has since retired must keep verifying (the document keeps retired keys);
    one sealed under a key the registry revoked must not. Neither registry has retired or revoked a key yet (2 Nov 2026),
    so the two states are made from the real document."""
    real = json.loads((KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json").read_text(encoding="utf-8"))
    good = load("01-approval-confirmed.bundle.json")
    pinned = {k["keyId"] for k in good["registrySignature"]["keys"]}
    for state, want_code in (("retired", 0), ("revoked", 1)):
        doc = copy.deepcopy(real)
        moved = [k for k in doc["keys"] if k["keyId"] in pinned]
        doc["keys"] = [k for k in doc["keys"] if k["keyId"] not in pinned]        # the revocation-bundle key stays active
        doc[state] = [dict(k, status=state, **({"revokedAt": "2026-11-01T00:00:00Z"} if state == "revoked" else {})) for k in moved]
        p = tmp_path / f"{state}.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        code, rep, out = _rep(good, tmp_path, strict=True, keys=str(p))
        assert code == want_code, (state, out)
        if state == "retired":
            assert "lists pinned key ed25519/5ecb3da505414c4f as retired" in out and rep["keyDocument"]["allPinned"] is True
        else:
            assert "FAIL the registry's key document lists pinned key ed25519/5ecb3da505414c4f as REVOKED since 2026-11-01T00:00:00Z" in out
            assert rep["keyDocument"]["allPinned"] is False


def test_a_key_document_that_cannot_be_read_is_a_refusal_not_a_skipped_check(tmp_path):
    """Fail closed: --keys names a file that is missing, not JSON, or not a key document → exit 2, never a pass."""
    good = load("01-approval-confirmed.bundle.json")
    bad = tmp_path / "notkeys.json"
    for content in (None, "{not json", json.dumps({"registry": "x"}), json.dumps([]), json.dumps({"keys": []})):
        if content is None:
            bad.unlink(missing_ok=True)
        else:
            bad.write_text(content, encoding="utf-8")
        code, rep, out = _rep(good, tmp_path, keys=str(bad))
        assert code == 2 and rep["result"] == "unreadable" and "could not read key document" in out, (content, out)


def test_keys_on_the_command_line(tmp_path):
    import subprocess
    script = str(HERE.parent / "verify_receipt.py")
    bundle = str(FX / "09-re-keyed-outside-the-registry.bundle.json")
    doc = str(KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json")
    r = subprocess.run([sys.executable, "-I", script, bundle, "--require-approval"], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout
    r = subprocess.run([sys.executable, "-I", script, bundle, "--keys", doc, "--require-approval", "--json"], capture_output=True, text=True, check=False)
    rep = json.loads(r.stdout)
    assert r.returncode == 1 and rep["exit"] == 1 and rep["keyDocument"]["allPinned"] is False, r.stdout[-400:]
    assert any("does not list pinned key" in line for line in rep["transcript"])
    r = subprocess.run([sys.executable, "-I", script, "--keys", doc, bundle], capture_output=True, text=True, check=False)   # flag first
    assert r.returncode == 1, r.stdout[-400:]
    for argv in ([bundle, "--keys"], [bundle, "--keys", "--json"], [bundle, "--kyes", doc]):                  # a flag with no file, or a misspelt flag
        r = subprocess.run([sys.executable, "-I", script] + argv, capture_output=True, text=True, check=False)
        assert r.returncode == 2, (argv, r.stdout[-200:])


def test_a_revoked_key_is_refused_however_the_document_says_it(tmp_path):
    """Review of the key-pinning change (2 Nov 2026): list membership alone read `status: revoked` left in place as
    pinned, and a revoked entry published without its public key (the registry serves publicKeyRaw null on revoked
    keys) fell through to "never published", exit 1 for the wrong reason. Three shapes of the same revocation."""
    real = json.loads((KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json").read_text(encoding="utf-8"))
    good = load("01-approval-confirmed.bundle.json")
    ed = next(k for k in real["keys"] if k["alg"] == "ed25519" and k["keyId"] == "5ecb3da505414c4f")
    shapes = {
        "status revoked in place": lambda d: ed.update(status="revoked", revokedAt="2026-11-01T00:00:00Z"),
        "revoked entry with null key still in keys": lambda d: ed.update(status="revoked", revokedAt="2026-11-01T00:00:00Z", publicKeyRaw=None),
        "revoked entry with null key in the revoked list": lambda d: (d["keys"].remove(ed), d["revoked"].append(dict(ed, status="revoked", revokedAt="2026-11-01T00:00:00Z", publicKeyRaw=None))),
    }
    for name, shape in shapes.items():
        doc = copy.deepcopy(real)
        ed = next(k for k in doc["keys"] if k["keyId"] == "5ecb3da505414c4f")
        shape(doc)
        p = tmp_path / "rv.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        code, rep, out = _rep(good, tmp_path, strict=True, keys=str(p))
        assert code == 1 and rep["keyDocument"]["allPinned"] is False, (name, out)
        assert "FAIL the registry's key document lists pinned key ed25519/5ecb3da505414c4f as REVOKED since 2026-11-01T00:00:00Z" in out, (name, out)
        assert "never published" not in out, (name, out)

def test_a_revocation_wins_over_an_active_entry_for_the_same_key(tmp_path):
    """Private review of #350 (noah-ing, 2 Nov 2026, reached us 9 Nov): the document still lists the key as active in
    `keys` AND revokes it in `revoked`. The exact active match was taken first, so the revocation was never consulted:
    exit 0, allPinned true. Now the revocation wins and the contradiction is named, with or without the raw key on the
    revoked entry."""
    real = json.loads((KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json").read_text(encoding="utf-8"))
    good = load("01-approval-confirmed.bundle.json")
    first = good["registrySignature"]["keys"][0]
    for variant, raw in (("without raw key", None), ("with raw key", first["publicKeyRaw"])):
        doc = copy.deepcopy(real)
        doc["revoked"].append({"alg": first["alg"], "keyId": first["keyId"], "publicKeyRaw": raw, "status": "revoked", "revokedAt": "2026-10-16T00:00:00Z"})
        assert any(k["keyId"] == first["keyId"] for k in doc["keys"]), "the active entry stays"
        p = tmp_path / "both.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        code, rep, out = _rep(good, tmp_path, strict=True, keys=str(p))
        assert code == 1 and rep["keyDocument"]["allPinned"] is False and rep["boundIdentity"] is None, (variant, out)
        assert f"FAIL the registry's key document lists pinned key {first['alg']}/{first['keyId']} as REVOKED since 2026-10-16T00:00:00Z — and ALSO as active: the document contradicts itself" in out, (variant, out)
        assert "never published" not in out and "DIFFERENT" not in out, (variant, out)
    # the same revocation written into the active entry's own status, beside a clean retired twin: still refused
    doc = copy.deepcopy(real)
    doc["retired"].append(dict(first, status="retired"))
    next(k for k in doc["keys"] if k["keyId"] == first["keyId"]).update(status="revoked", revokedAt="2026-10-16T00:00:00Z")
    p = tmp_path / "mixed.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    code, rep, out = _rep(good, tmp_path, strict=True, keys=str(p))
    assert code == 1 and rep["keyDocument"]["allPinned"] is False and "as REVOKED" in out, out


def test_the_right_key_id_under_a_different_public_key_fails(tmp_path):
    """The document and the bundle agree on alg and keyId but not on the key: the pinned key is not the one the registry
    published under that id. Asserted on its own (the contract's keyId tamper covers only the id)."""
    real = json.loads((KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json").read_text(encoding="utf-8"))
    doc = copy.deepcopy(real)
    ed = next(k for k in doc["keys"] if k["keyId"] == "5ecb3da505414c4f")
    ed["publicKeyRaw"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="   # 32 zero bytes: a valid Ed25519 key, not the registry's
    p = tmp_path / "diff.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    code, rep, out = _rep(load("01-approval-confirmed.bundle.json"), tmp_path, keys=str(p))
    assert code == 1 and rep["keyDocument"]["allPinned"] is False, out
    assert "FAIL the registry's key document lists keyId 5ecb3da505414c4f with a DIFFERENT ed25519 public key" in out, out


def test_a_root_only_mismatch_is_not_pinned(tmp_path):
    """Every pinned key listed, only the root wrong or absent: allPinned must be False, not merely exit 1 (a mutant that
    dropped the root from allPinned survived the first sweep); a document with no root does not skip the check."""
    real = json.loads((KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json").read_text(encoding="utf-8"))
    other = json.loads((KEY_DOCUMENTS / "xchk.me.2026-11-02.json").read_text(encoding="utf-8"))
    good = load("01-approval-confirmed.bundle.json")
    doc = copy.deepcopy(real)
    doc["root"] = other["root"]
    p = tmp_path / "root.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    code, rep, out = _rep(good, tmp_path, keys=str(p))
    assert code == 1 and rep["keyDocument"]["allPinned"] is False, out
    assert "FAIL the bundle's root key acc7ad1aeb3ef177 is NOT the registry's root key" in out and "lists pinned key ed25519/5ecb3da505414c4f\n" in out, out
    doc = copy.deepcopy(real)
    del doc["root"]
    p.write_text(json.dumps(doc), encoding="utf-8")
    code, rep, out = _rep(good, tmp_path, keys=str(p))
    assert code == 1 and rep["keyDocument"]["allPinned"] is False, out
    assert "FAIL the bundle carries root key acc7ad1aeb3ef177 but the registry's key document publishes no root key" in out, out


def test_key_document_shapes_a_bom_loads_and_non_keys_are_unreadable(tmp_path):
    """A copy saved by an editor with a byte-order mark is the same document; a `keys` list of non-keys is not a key
    document and is exit 2, as the docstring promises, never exit 1 with a null registry."""
    good = load("01-approval-confirmed.bundle.json")
    real = (KEY_DOCUMENTS / "in.xchk.io.2026-11-02.json").read_bytes()
    p = tmp_path / "bom.json"
    p.write_bytes(b"\xef\xbb\xbf" + real)
    code, rep, out = _rep(good, tmp_path, keys=str(p))
    assert code == 0 and rep["keyDocument"]["allPinned"] is True, out
    for shape in ({"keys": [1, 2]}, {"keys": [{"alg": "ed25519"}]}, {"keys": [{"alg": "ed25519", "keyId": "x"}], "revoked": ["y"]}):
        p.write_text(json.dumps(shape), encoding="utf-8")
        code, rep, out = _rep(good, tmp_path, keys=str(p))
        assert code == 2 and rep["result"] == "unreadable" and rep["keyDocument"] is None, (shape, out)
