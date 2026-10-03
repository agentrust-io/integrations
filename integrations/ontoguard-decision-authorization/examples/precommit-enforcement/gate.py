"""Bounded pre-commit gate for an external enforcement runtime.

This example contains no OntoGuard semantic engine. It consumes a signed
OntoGuard authorization before a protected mutation.

  destination/tool already admitted by the enforcement runtime
          ↓
  exact proposed request
          ↓
  verify signed OntoGuard handoff + exact action-binding digest
          ↓
  ALLOW + exact binding → enforcement runtime may continue
  BLOCK / ESCALATE / mismatch / expired / tampered / untrusted /
  missing authorization / digest-only caller → DENY
          ↓
  only then may the bounded harness form the protected effect
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ontoguard_trace import (
    ACTION_BINDING_PROFILE,
    AdapterError,
    bind_authorization,
    partner_action_binding_digest,
    partner_action_binding_object,
    sha256_digest,
    validate_partner_action_binding_object,
)


CAPABILITY = "RELEASE_PAYMENT"

ACTION_ALLOW_250K = partner_action_binding_object(
    operation=CAPABILITY,
    amount="250000.00",
    currency="USD",
    counterparty="approved supplier",
    cross_border=True,
    consequence_class="FINANCIAL_COMMITMENT",
)
ACTION_BLOCK_260K = partner_action_binding_object(
    operation=CAPABILITY,
    amount="260000.00",
    currency="USD",
    counterparty="approved supplier",
    cross_border=True,
    consequence_class="FINANCIAL_COMMITMENT",
)
ACTION_ESCALATE_NEW_COUNTERPARTY = partner_action_binding_object(
    operation=CAPABILITY,
    amount="250000.00",
    currency="USD",
    counterparty="newly added supplier",
    cross_border=True,
    consequence_class="FINANCIAL_COMMITMENT",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class GateDecision:
    permit: bool
    reason: str
    action: str | None = None
    action_binding_digest: str | None = None
    validated_action: dict[str, Any] | None = None


class SignedTestAuthorizer:
    """TEST-ONLY signed authorizations. Not a live OntoGuard Decision API result."""

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

    def mint(self, action_obj: dict[str, Any], decision: str = "ALLOW") -> dict[str, Any]:
        if decision not in {"ALLOW", "BLOCK", "ESCALATE"}:
            raise ValueError("decision must be ALLOW, BLOCK, or ESCALATE")
        validated_action = validate_partner_action_binding_object(action_obj)
        digest = partner_action_binding_digest(validated_action)
        now = datetime.now(timezone.utc)
        issued = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires = (now + timedelta(days=7)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        seed = json.dumps(
            {"decision": decision, "action": validated_action},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        auth = {
            "action": decision,
            "action_binding_digest": digest,
            "action_binding_profile": ACTION_BINDING_PROFILE,
            "decision_binding_hash": _sha256(b"precommit-decision|" + seed),
            "expires_at_utc": expires,
            "handoff_hash": _sha256(b"precommit-handoff|" + seed),
            "handoff_seal_digest": _sha256(b"precommit-handoff-seal|" + seed),
            "issued_at_utc": issued,
            "movement_hash": _sha256(b"precommit-movement|" + seed),
            "release_authorized": decision == "ALLOW",
            "trace_id": "precommit-" + str(uuid.uuid4()),
            "harness_only": True,
            "not_a_live_decision_api_result": True,
        }
        result_bytes = json.dumps(auth, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return {
            "auth": auth,
            "result_bytes": result_bytes,
            "signature": _b64url(self._priv.sign(result_bytes)),
            "public_jwk": self.public_jwk,
            "result_digest": sha256_digest(result_bytes),
        }

    def write_ontoguard_jwks(self, path: Path) -> Path:
        path.write_text(json.dumps({"keys": [self.public_jwk]}, indent=2) + "\n", encoding="utf-8")
        return path


def evaluate_precommit(
    proposed_action: dict[str, Any],
    *,
    result_bytes: bytes | None,
    signature_b64url: str | None,
    public_jwk: dict[str, Any] | None,
    ontoguard_jwks_path: Path,
    verification_time_utc: datetime | None = None,
    allow_test_keys: bool | None = None,
) -> GateDecision:
    """Fail closed after strict action validation. Does not execute."""
    try:
        validated_action = validate_partner_action_binding_object(proposed_action)
    except (AdapterError, TypeError, ValueError) as exc:
        return GateDecision(permit=False, reason=str(exc))

    if result_bytes is None or signature_b64url is None or public_jwk is None:
        return GateDecision(permit=False, reason="no OntoGuard authorization")

    try:
        bound = bind_authorization(
            result_bytes=result_bytes,
            signature_b64url=signature_b64url,
            public_jwk=public_jwk,
            ontoguard_jwks_path=ontoguard_jwks_path,
            allow_test_keys=allow_test_keys,
            verification_time_utc=verification_time_utc,
        )
        proposed_digest = partner_action_binding_digest(validated_action)
    except (AdapterError, TypeError, ValueError) as exc:
        return GateDecision(permit=False, reason=str(exc))

    if proposed_digest != bound["action_binding_digest"]:
        return GateDecision(
            permit=False,
            reason="payload mismatch: proposed action is not the bound movement",
            action=bound["action"],
            action_binding_digest=bound["action_binding_digest"],
            validated_action=validated_action,
        )

    if bound["action"] != "ALLOW" or bound["release_authorized"] is not True:
        return GateDecision(
            permit=False,
            reason=f"{bound['action']} is not a releasable authorization",
            action=bound["action"],
            action_binding_digest=bound["action_binding_digest"],
            validated_action=validated_action,
        )

    return GateDecision(
        permit=True,
        reason="ALLOW + exact action binding",
        action=bound["action"],
        action_binding_digest=bound["action_binding_digest"],
        validated_action=validated_action,
    )


def attempt_protected(
    executor: Any,
    proposed_action: dict[str, Any],
    *,
    minted: dict[str, Any] | None,
    ontoguard_jwks_path: Path,
    allow_test_keys: bool | None = None,
    verification_time_utc: datetime | None = None,
) -> dict[str, Any]:
    """Protected wrapper; the executor independently re-verifies at commit."""
    if minted is None:
        decision = GateDecision(permit=False, reason="no OntoGuard authorization")
    else:
        decision = evaluate_precommit(
            proposed_action,
            result_bytes=minted.get("result_bytes"),
            signature_b64url=minted.get("signature"),
            public_jwk=minted.get("public_jwk"),
            ontoguard_jwks_path=ontoguard_jwks_path,
            allow_test_keys=allow_test_keys,
            verification_time_utc=verification_time_utc,
        )

    if not decision.permit:
        return {
            "result": "EXECUTION_REFUSED",
            "reason": decision.reason,
            "action": decision.action,
            "protected_effect_formed": False,
            "commit_count": executor.store.commit_count,
            "status": executor.store.status,
        }

    return executor.attempt(
        decision.validated_action,
        minted,
        ontoguard_jwks_path=ontoguard_jwks_path,
        allow_test_keys=allow_test_keys,
        verification_time_utc=verification_time_utc,
    )
