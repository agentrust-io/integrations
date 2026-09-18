#!/usr/bin/env python3
"""Reproducible controlled executor for the partner-safe $250k / $260k demo.

This is not OntoGuard core, not a bank ledger, and not production L5.
The live path mints a TEST-ONLY authorization at runtime. That object is
harness-only. It is not a live OntoGuard Decision API result.

Sequence (must not commit first):
  mint/verify signed test authorization
      → derive action binding
      → match?
      → only then PENDING→RELEASED
      → fresh execution receipt
      → actual adapter
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

PROOF_DIR = Path(__file__).resolve().parent
ADAPTER_DIR = PROOF_DIR.parents[1]
if str(ADAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(ADAPTER_DIR))

from ontoguard_trace import (  # noqa: E402
    ACTION_BINDING_PROFILE,
    AdapterError,
    bind_authorization,
    partner_action_binding_digest,
    partner_action_binding_object,
    project,
    sha256_digest,
)

AUTHORIZED_ACTION = partner_action_binding_object(
    operation="RELEASE_PAYMENT",
    amount="250000.00",
    currency="USD",
    counterparty="newly added supplier",
    cross_border=True,
    consequence_class="FINANCIAL_COMMITMENT",
)
MUTATED_ACTION = partner_action_binding_object(
    operation="RELEASE_PAYMENT",
    amount="260000.00",
    currency="USD",
    counterparty="newly added supplier",
    cross_border=True,
    consequence_class="FINANCIAL_COMMITMENT",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class ControlledStore:
    status: str = "PENDING"
    commit_count: int = 0
    last_commit_id: str | None = None
    protected_effect_formed: bool = False
    history: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "commit_count": self.commit_count,
            "last_commit_id": self.last_commit_id,
            "protected_effect_formed": self.protected_effect_formed,
        }


class ControlledExecutor:
    def __init__(self, store: ControlledStore | None = None) -> None:
        self.store = store or ControlledStore()
        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key().public_bytes_raw()
        self.kid = "ontoguard-controlled-executor-ephemeral"
        self.public_jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(self._pub),
            "kid": self.kid,
            "test_only": True,
        }
        self.subject = "did:key:z" + _b64url(self._pub)

    def _sign(self, message: bytes) -> str:
        return _b64url(self._priv.sign(message))

    def write_execution_jwks(self, path: Path) -> Path:
        path.write_text(json.dumps({"keys": [self.public_jwk]}, indent=2) + "\n", encoding="utf-8")
        return path

    def attempt(self, proposed: dict[str, Any], authorized_digest: str) -> dict[str, Any]:
        executed_digest = partner_action_binding_digest(proposed)
        if executed_digest != authorized_digest:
            self.store.history.append("REFUSED_BINDING_MISMATCH")
            return {
                "result": "EXECUTION_REFUSED",
                "reason": "executed_action_binding_digest != authorized_action_binding_digest",
                "authorized_action_binding_digest": authorized_digest,
                "executed_action_binding_digest": executed_digest,
                "protected_effect_formed": False,
                "commit_count": self.store.commit_count,
                "status": self.store.status,
                "TRACE_RECORD_EMITTED": False,
            }
        commit_id = "commit-" + secrets.token_hex(8)
        self.store.status = "RELEASED"
        self.store.commit_count += 1
        self.store.last_commit_id = commit_id
        self.store.protected_effect_formed = True
        self.store.history.append("COMMITTED")
        return {
            "result": "EXECUTED",
            "execution_event_id": commit_id,
            "authorized_action_binding_digest": authorized_digest,
            "executed_action_binding_digest": executed_digest,
            "protected_effect_formed": True,
            "commit_count": self.store.commit_count,
            "status": self.store.status,
        }

    def build_receipt(
        self,
        *,
        auth: dict[str, Any],
        result_digest: str,
        attempt: dict[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "appraisal_verifier": "https://ontoguard.ai/trace/software-only",
            "authorized_action": "ALLOW",
            "authorized_action_binding_digest": attempt["authorized_action_binding_digest"],
            "authorized_decision_binding_hash": auth["decision_binding_hash"],
            "authorized_handoff_hash": auth["handoff_hash"],
            "authorized_movement_hash": auth["movement_hash"],
            "authorized_result_digest": result_digest,
            "authorized_trace_id": auth["trace_id"],
            "build_provenance": {
                "builder": "ontoguard-controlled-executor-v1",
                "digest": _sha256(b"ontoguard-controlled-executor-v1"),
                "slsa_level": 0,
            },
            "data_class": "internal",
            "executed": True,
            "executed_action_binding_digest": attempt["executed_action_binding_digest"],
            "executed_movement_hash": auth["movement_hash"],
            "execution_event_id": attempt["execution_event_id"],
            "execution_producer": "ontoguard-controlled-executor-v1",
            "model": {
                "model_id": "v1",
                "provider": "ontoguard-controlled-executor",
                "version": "1",
            },
            "policy": {
                "bundle_hash": _sha256(b"controlled-protected-commit-v1"),
                "enforcement_mode": "enforce",
                "version": "controlled-protected-commit-v1",
            },
            "protected_effect_formed": True,
            "subject": self.subject,
        }
        receipt_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        wrapped = dict(payload)
        wrapped["receipt_bytes"] = receipt_bytes.decode("utf-8")
        wrapped["kid"] = self.kid
        wrapped["public_jwk"] = {k: v for k, v in self.public_jwk.items() if k != "test_only"}
        wrapped["signature"] = self._sign(receipt_bytes)
        return wrapped


class HarnessAuthorizer:
    """Ephemeral TEST-ONLY OntoGuard-shaped authorization. Not a live DAI result."""

    def __init__(self) -> None:
        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key().public_bytes_raw()
        self.kid = "ontoguard-harness-test-only"
        self.public_jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(self._pub),
            "kid": self.kid,
            "test_only": True,
        }

    def mint(self, action_obj: dict[str, Any]) -> dict[str, Any]:
        digest = partner_action_binding_digest(action_obj)
        now = datetime.now(timezone.utc)
        issued = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires = (now + timedelta(days=7)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        seed = json.dumps(action_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        auth = {
            "action": "ALLOW",
            "action_binding_digest": digest,
            "action_binding_profile": ACTION_BINDING_PROFILE,
            "decision_binding_hash": _sha256(b"harness-decision|" + seed),
            "expires_at_utc": expires,
            "handoff_hash": _sha256(b"harness-handoff|" + seed),
            "handoff_seal_digest": _sha256(b"harness-handoff-seal|" + seed),
            "issued_at_utc": issued,
            "movement_hash": _sha256(b"harness-movement|" + seed),
            "release_authorized": True,
            "trace_id": "harness-" + str(uuid.uuid4()),
            "harness_only": True,
            "not_a_live_decision_api_result": True,
        }
        result_bytes = json.dumps(auth, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        signature = _b64url(self._priv.sign(result_bytes))
        return {
            "auth": auth,
            "result_bytes": result_bytes,
            "signature": signature,
            "public_jwk": self.public_jwk,
            "result_digest": sha256_digest(result_bytes),
        }

    def write_ontoguard_jwks(self, path: Path) -> Path:
        path.write_text(json.dumps({"keys": [self.public_jwk]}, indent=2) + "\n", encoding="utf-8")
        return path


def verify_authorization_pre_commit(
    minted: dict[str, Any],
    ontoguard_jwks_path: Path,
) -> dict[str, Any]:
    """Fail closed before any store mutation."""
    return bind_authorization(
        minted["auth"],
        result_bytes=minted["result_bytes"],
        signature_b64url=minted["signature"],
        public_jwk=minted["public_jwk"],
        ontoguard_jwks_path=ontoguard_jwks_path,
        allow_test_keys=True,
    )


def _trace_pem() -> str | None:
    pem = os.environ.get("TRACE_PRIVATE_KEY_PEM")
    if pem:
        return pem
    try:
        key = Ed25519PrivateKey.generate()
        return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
    except Exception:
        return None


def run_live(proof_dir: Path = PROOF_DIR) -> dict[str, Any]:
    del proof_dir  # historical artifacts stay frozen; live path does not consume them
    authorizer = HarnessAuthorizer()
    minted = authorizer.mint(AUTHORIZED_ACTION)
    authorized_digest = minted["auth"]["action_binding_digest"]
    out: dict[str, Any] = {
        "authorized_digest": authorized_digest,
        "authorization_source": "ephemeral-harness-test-only",
        "not_a_live_decision_api_result": True,
        "expires_at_utc": minted["auth"]["expires_at_utc"],
    }

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        og_jwks = authorizer.write_ontoguard_jwks(tmp_path / "ontoguard_jwks.json")

        bound = verify_authorization_pre_commit(minted, og_jwks)
        if bound["action_binding_digest"] != authorized_digest:
            raise RuntimeError("pre-commit authorization digest mismatch")
        if bound["action"] != "ALLOW" or bound["release_authorized"] is not True:
            raise RuntimeError("pre-commit authorization is not ALLOW/release_authorized")

        # Positive $250k — commit only after verification
        pos_exec = ControlledExecutor()
        pos_before = pos_exec.store.snapshot()
        pos_attempt = pos_exec.attempt(AUTHORIZED_ACTION, authorized_digest)
        pos_receipt = pos_exec.build_receipt(
            auth=minted["auth"],
            result_digest=minted["result_digest"],
            attempt=pos_attempt,
        )
        exec_jwks = pos_exec.write_execution_jwks(tmp_path / "execution_jwks.json")
        pem = _trace_pem()
        sign = bool(pem)
        try:
            import agentrust_trace  # noqa: F401
        except ImportError:
            sign = False
        projected = project(
            minted["auth"],
            signature_b64url=minted["signature"],
            public_jwk=minted["public_jwk"],
            result_bytes=minted["result_bytes"],
            execution_receipt=pos_receipt,
            sign_trace=sign,
            private_key_pem=pem if sign else None,
            ontoguard_jwks_path=og_jwks,
            execution_jwks_path=exec_jwks,
            allow_test_keys=True,
        )
        out["positive"] = {
            "before": pos_before,
            "after": pos_exec.store.snapshot(),
            "attempt": pos_attempt,
            "adapter_state": projected.get("state"),
            "trace_record_emitted": bool(projected.get("trace_record_emitted")),
            "signed": bool(projected.get("signed")),
            "authorization_verified_before_commit": True,
        }

        # Negative $260k — new store, same verified authorization
        neg_exec = ControlledExecutor()
        neg_before = neg_exec.store.snapshot()
        neg_attempt = neg_exec.attempt(MUTATED_ACTION, authorized_digest)
        forged = dict(neg_attempt)
        forged["execution_event_id"] = "commit-forged-mutation"
        forged["authorized_action_binding_digest"] = authorized_digest
        forged_receipt = neg_exec.build_receipt(
            auth=minted["auth"],
            result_digest=minted["result_digest"],
            attempt=forged,
        )
        neg_jwks = neg_exec.write_execution_jwks(tmp_path / "neg_execution_jwks.json")
        adapter_rejected = False
        adapter_error = ""
        try:
            project(
                minted["auth"],
                signature_b64url=minted["signature"],
                public_jwk=minted["public_jwk"],
                result_bytes=minted["result_bytes"],
                execution_receipt=forged_receipt,
                sign_trace=False,
                ontoguard_jwks_path=og_jwks,
                execution_jwks_path=neg_jwks,
                allow_test_keys=True,
            )
        except AdapterError as exc:
            adapter_rejected = True
            adapter_error = str(exc)
        no_receipt = project(
            minted["auth"],
            signature_b64url=minted["signature"],
            public_jwk=minted["public_jwk"],
            result_bytes=minted["result_bytes"],
            execution_receipt=None,
            sign_trace=False,
            ontoguard_jwks_path=og_jwks,
            allow_test_keys=True,
        )
        out["negative"] = {
            "before": neg_before,
            "after": neg_exec.store.snapshot(),
            "attempt": neg_attempt,
            "adapter_rejected_mutated_receipt": adapter_rejected,
            "adapter_error": adapter_error,
            "no_receipt_state": no_receipt.get("state"),
            "no_receipt_trace_emitted": bool(no_receipt.get("trace_record_emitted")),
        }
    return out


def main() -> int:
    try:
        live = run_live()
    except Exception as exc:
        print(f"[FAIL] live executor crashed: {exc}")
        print("RESULT: FAIL (1)")
        return 1

    pos = live["positive"]
    neg = live["negative"]
    print("LIVE CONTROLLED EXECUTOR")
    print("authorization_source=ephemeral-harness-test-only")
    print("not_a_live_decision_api_result=true")
    print(f"expires_at_utc={live['expires_at_utc']}")
    print(f"authorized_digest={live['authorized_digest']}")
    failed = 0

    def check(cond: bool, label: str) -> None:
        nonlocal failed
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")
        if not cond:
            failed += 1

    check(pos.get("authorization_verified_before_commit") is True, "authorization verified before commit")
    check(pos["before"]["status"] == "PENDING" and pos["before"]["commit_count"] == 0, "positive start PENDING commit_count=0")
    check(pos["after"]["status"] == "RELEASED", "positive status RELEASED")
    check(pos["after"]["commit_count"] == 1, "positive commit_count=1")
    check(pos["after"]["protected_effect_formed"] is True, "positive protected_effect_formed=true")
    check(pos["adapter_state"] in {"ALLOW_EXECUTION_PROVEN", "ALLOW_EXECUTION_CANDIDATE"}, f"positive adapter state={pos['adapter_state']}")
    if pos["adapter_state"] == "ALLOW_EXECUTION_PROVEN":
        check(pos["trace_record_emitted"] is True, "positive TRACE emitted")
    else:
        print("[NOTE] agentrust-trace not installed in this environment; TRACE signing deferred to CI")
        check(pos["trace_record_emitted"] is False, "positive unsigned path emits no Trust Record")

    check(neg["attempt"]["result"] == "EXECUTION_REFUSED", "negative executor refused $260k")
    check(neg["after"]["status"] == "PENDING", "negative status remains PENDING")
    check(neg["after"]["commit_count"] == 0, "negative commit_count=0")
    check(neg["after"]["protected_effect_formed"] is False, "negative protected_effect_formed=false")
    check(neg["adapter_rejected_mutated_receipt"] is True, "adapter rejected mutated executed receipt")
    check(neg["no_receipt_trace_emitted"] is False, "negative path emits no TRACE")
    print()
    print("RESULT: " + ("PASS" if failed == 0 else f"FAIL ({failed})"))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
