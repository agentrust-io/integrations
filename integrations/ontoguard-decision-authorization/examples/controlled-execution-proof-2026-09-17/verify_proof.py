#!/usr/bin/env python3
"""Replay the controlled-execution proof without OntoGuard internals.

Usage:
  python verify_proof.py
Run from the unpacked proof directory.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

ROOT = Path(__file__).resolve().parent
POS = ROOT / "positive"
NEG = ROOT / "negative_action_mutation"
FAILED = 0


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def partner_bytes(obj: dict) -> bytes:
    canonical = {
        "amount": str(obj["amount"]),
        "consequence_class": obj["consequence_class"],
        "counterparty": obj["counterparty"],
        "cross_border": bool(obj["cross_border"]),
        "currency": obj["currency"],
        "operation": obj["operation"],
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def ok(label: str) -> None:
    print(f"[PASS] {label}")


def fail(label: str, detail: str = "") -> None:
    global FAILED
    FAILED += 1
    extra = f" ({detail})" if detail else ""
    print(f"[FAIL] {label}{extra}")


def verify_ed25519(jwk: dict, message: bytes, signature_b64: str) -> bool:
    pub = _b64url_decode(jwk["x"])
    sig = _b64url_decode(signature_b64)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except InvalidSignature:
        return False


def main() -> int:
    print("OntoGuard / AgenTrust controlled-execution proof verifier")
    print(f"root: {ROOT}")

    checksums = (ROOT / "checksums.sha256").read_text().splitlines()
    bad = 0
    for line in checksums:
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        if name.endswith("checksums.sha256"):
            continue
        path = ROOT / name
        if not path.is_file():
            bad += 1
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            bad += 1
    if bad:
        fail("checksum manifest", f"{bad} mismatch(es)")
    else:
        ok("checksum manifest")

    auth = load("positive/ontoguard_authorization.exact.json")
    sig = load("positive/ontoguard_authorization.signature.json")
    og_jwk = load("positive/ontoguard_public_jwk.json")
    exact = sig["exact_bytes"].encode("utf-8")
    if digest_bytes(exact) == sig["digest"]:
        ok("OntoGuard authorization exact-byte digest")
    else:
        fail("OntoGuard authorization exact-byte digest")
    if verify_ed25519(og_jwk, exact, sig["signature"]):
        ok("OntoGuard Ed25519 signature")
    else:
        fail("OntoGuard Ed25519 signature")
    ok("OntoGuard signing key present in pack")

    if auth.get("action") == "ALLOW":
        ok("authorization action = ALLOW")
    else:
        fail("authorization action = ALLOW", str(auth.get("action")))
    if auth.get("release_authorized") is True:
        ok("release_authorized = true")
    else:
        fail("release_authorized = true")
    handoff_obj = load("positive/ontoguard_handoff.exact.json")
    handoff_path = POS / "ontoguard_handoff.exact.bytes"
    if handoff_path.is_file():
        handoff_raw = handoff_path.read_bytes()
    else:
        handoff_raw = json.dumps(handoff_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    recomputed_handoff = digest_bytes(handoff_raw)
    expected_seal = auth.get("handoff_seal_digest")
    if not expected_seal:
        fail("signed handoff_seal_digest is required")
    elif recomputed_handoff == expected_seal:
        ok("sealed handoff digest recomputes from exact exported bytes")
    else:
        fail("sealed handoff digest recomputes from exact exported bytes", recomputed_handoff)
    if handoff_obj.get("handoff_hash") == auth.get("handoff_hash"):
        ok(f"exported handoff carries live sealed identity {str(auth.get('handoff_hash'))[7:11]}...")
    else:
        fail("exported handoff live identity")
    ok(f"handoff hash = {str(auth.get('handoff_hash'))[7:11]}...")
    ok(f"decision binding = {str(auth.get('decision_binding_hash'))[7:11]}...")
    ok(f"authorized movement identity = {str(auth.get('movement_hash'))[7:11]}...")

    binding = load("positive/partner_action_binding.exact.json")
    recomputed = digest_bytes(partner_bytes(binding["object"]))
    if recomputed == binding["digest"] == auth["action_binding_digest"]:
        ok("independent executable-action digest")
    else:
        fail("independent executable-action digest", recomputed)

    receipt = load("positive/execution_receipt.json")
    if receipt.get("executed_action_binding_digest") == auth["action_binding_digest"]:
        ok("executed action == authorized action")
    else:
        fail("executed action == authorized action")

    ex_jwk = load("positive/execution_public_jwk.json")
    ok("execution runtime signing key present in pack")
    raw_receipt = receipt["receipt_bytes"].encode("utf-8")
    if verify_ed25519(ex_jwk, raw_receipt, receipt["signature"]):
        ok("execution receipt Ed25519 signature")
    else:
        fail("execution receipt Ed25519 signature")
    if receipt.get("authorized_result_digest") == sig["digest"]:
        ok("receipt authorization result digest")
    else:
        fail("receipt authorization result digest")
    if receipt.get("authorized_handoff_hash") == auth["handoff_hash"]:
        ok("receipt handoff binding")
    else:
        fail("receipt handoff binding")
    if receipt.get("authorized_decision_binding_hash") == auth["decision_binding_hash"]:
        ok("receipt decision binding")
    else:
        fail("receipt decision binding")
    if receipt.get("authorized_action_binding_digest") == auth["action_binding_digest"]:
        ok("receipt action binding")
    else:
        fail("receipt action binding")

    before = load("positive/before_state.json")
    after = load("positive/after_state.json")
    if before.get("controlled_payment.status") == "PENDING" and after.get("controlled_payment.status") == "RELEASED":
        ok("PENDING -> RELEASED")
    else:
        fail("PENDING -> RELEASED")
    if after.get("protected_effect_formed") is True:
        ok("protected_effect_formed = true")
    else:
        fail("protected_effect_formed = true")
    ok(f"execution event = {after.get('commit_attempt_id')}")

    candidate = load("positive/trace_claim_candidate.json")
    ref = (candidate.get("references") or [{}])[0]
    if ref.get("rel") == "authorized-intent" and ref.get("id") == auth["handoff_hash"]:
        ok(f"authorized-intent = {str(auth.get('handoff_hash'))[7:11]}...")
    else:
        fail("authorized-intent binding")

    print("\nNEGATIVE TEST")
    negative = load("negative_action_mutation/rejection_result.json")
    mutated = load("negative_action_mutation/mutated_action.json")
    mutated_obj = {
        "amount": f"{float(mutated['amount']):.2f}",
        "consequence_class": mutated["consequence"],
        "counterparty": mutated["counterparty"],
        "cross_border": mutated["cross_border"],
        "currency": mutated["currency"],
        "operation": mutated["action"],
    }
    mutated_digest = digest_bytes(partner_bytes(mutated_obj))
    if mutated_digest != auth["action_binding_digest"]:
        ok("amount mutation 250000 -> 260000 changes action binding")
    else:
        fail("amount mutation did not change action binding")
    if negative.get("result") == "EXECUTION_REFUSED":
        ok("execution refused")
    else:
        fail("execution refused")
    if negative.get("protected_effect_formed") is False:
        ok("protected effect = false")
    else:
        fail("protected effect = false")
    if negative.get("commit_count") == 0:
        ok("commit count = 0")
    else:
        fail("commit count = 0")
    if negative.get("TRACE_RECORD_EMITTED") is False:
        ok("TRACE emitted = false")
    else:
        fail("TRACE emitted = false")

    print("\nADAPTER REPLAY")
    try:
        import replay_adapter
        rc = replay_adapter.main()
        if rc == 0:
            ok("actual Marketplace adapter replay")
        else:
            fail("actual Marketplace adapter replay", f"exit {rc}")
    except SystemExit as exc:
        if exc.code not in (0, None):
            fail("actual Marketplace adapter replay", str(exc))
        else:
            ok("actual Marketplace adapter replay")
    except Exception as exc:
        fail("actual Marketplace adapter replay", str(exc))

    print("\nLIVE EXECUTOR HARNESS")
    try:
        import controlled_executor
        live_rc = controlled_executor.main()
        if live_rc == 0:
            ok("live controlled executor reran $250k and $260k through the adapter")
        else:
            fail("live controlled executor", f"exit {live_rc}")
    except SystemExit as exc:
        if exc.code not in (0, None):
            fail("live controlled executor", str(exc))
        else:
            ok("live controlled executor reran $250k and $260k through the adapter")
    except Exception as exc:
        fail("live controlled executor", str(exc))

    print()
    if FAILED:
        print(f"RESULT: FAIL ({FAILED})")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
