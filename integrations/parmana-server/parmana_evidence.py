"""Check Parmana's signed records offline and map them to TRACE `references`.

Parmana is an external evidence source (trace-spec §3.1.2). It issues no
TRACE Trust Record. An agent runtime that does issue one points at the
Parmana record for its step:

- `authorized-intent`: the Parmana record of the authorization decision,
  an Execution Trust Record when the action was approved and a Refusal
  Record when it was refused.
- `approval-outcome`: the signed human approval the decision used, when
  there was one.

Each entry's `digest` is the SHA-256 of the RFC 8785 canonical form of the
complete referenced object, as `resolver` retains it. Nothing here is ever
referenced as `observed-effect`: the connector in these fixtures is a mock,
and Parmana does not observe the downstream state change.

Signatures are checked against Parmana's own canonical form, not RFC 8785:
Parmana signs its records itself and TRACE does not re-sign them. Execution
Trust Records are checked with the published `parmana` SDK; Refusal Records
and approvals with the same canonical serializer, which that SDK publishes.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from parmana.crypto.canonical import canonical_serialize
from parmana.crypto.offline_verifier import verify_execution_trust_record_offline

# Large message commitment (v1) from Parmana's KMS signer: a message over
# 4096 bytes may be signed as this prefix plus its SHA-512 digest.
_RAW_MESSAGE_LIMIT = 4096
_COMMITMENT_PREFIX = b"PARMANA-ED25519-LARGE-MESSAGE-V1\x00"

# The fields a Refusal Record's hash and signature cover, in Parmana's
# order (packages/crypto/src/RefusalCrypto.ts). An absent field is left out.
_REFUSAL_FIELDS = (
    "refusalRecordId",
    "businessTransactionId",
    "decision",
    "evaluatedIntent",
    "bindingViolations",
    "submittedBy",
    "policyContentHash",
    "createdAt",
)


@dataclass(frozen=True)
class Check:
    valid: bool
    errors: list[str] = field(default_factory=list)


def _public_key(pem: str) -> Ed25519PublicKey:
    key = load_pem_public_key(pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def _verify(pem: str, signature_b64: str, message: bytes) -> bool:
    key = _public_key(pem)
    signature = base64.b64decode(signature_b64)
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        if len(message) <= _RAW_MESSAGE_LIMIT:
            return False
    try:
        key.verify(signature, _COMMITMENT_PREFIX + hashlib.sha512(message).digest())
        return True
    except InvalidSignature:
        return False


def verify_trust_record(record: dict[str, Any], keys: dict[str, str]) -> Check:
    """An Execution Trust Record, with `keys` mapping keyId to PEM."""
    result = verify_execution_trust_record_offline(record, keys)
    return Check(result.valid, list(result.errors))


def verify_refusal_record(record: dict[str, Any], keys: dict[str, str]) -> Check:
    """A Refusal Record: its hash, and its signature under `keys`."""
    errors: list[str] = []
    message = canonical_serialize({k: record[k] for k in _REFUSAL_FIELDS if k in record})
    if hashlib.sha256(message).hexdigest() != record.get("refusalRecordHash"):
        errors.append("refusalRecordHash does not match the record")
    signature = record.get("signature") or {}
    if signature.get("algorithm") != "ed25519":
        errors.append(f"unsupported algorithm: {signature.get('algorithm')}")
    elif signature.get("keyId") not in keys:
        errors.append(f"no public key for keyId {signature.get('keyId')!r}")
    elif not _verify(keys[signature["keyId"]], signature.get("value", ""), message):
        errors.append("signature does not verify")
    return Check(not errors, errors)


def verify_approval(approval: dict[str, Any], keys: dict[str, str]) -> Check:
    """A signed human approval: its signature over the payload."""
    signature = approval.get("signature") or {}
    key_id = signature.get("keyId")
    if key_id != approval.get("payload", {}).get("issuer", {}).get("keyId"):
        return Check(False, ["signature keyId differs from the payload's issuer keyId"])
    if key_id not in keys:
        return Check(False, [f"no public key for keyId {key_id!r}"])
    message = canonical_serialize(approval["payload"])
    if not _verify(keys[key_id], signature.get("value", ""), message):
        return Check(False, ["signature does not verify"])
    return Check(True)


def digest(obj: dict[str, Any]) -> str:
    """The `digest` of a reference: SHA-256 over RFC 8785 of the whole object."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def references_for(
    record: dict[str, Any], resolver: str, retention: str | None = None
) -> list[dict[str, Any]]:
    """The `references` entries a runtime's Trust Record would carry for one
    Parmana decision. `resolver` is the Parmana deployment that retains it."""

    def entry(rel: str, id_: str, obj: dict[str, Any]) -> dict[str, Any]:
        e = {"rel": rel, "id": id_, "resolver": resolver, "digest": digest(obj)}
        if retention:
            e["retention"] = retention
        return e

    if "trustRecordId" in record:
        refs = [entry("authorized-intent", f"trust-records/{record['businessTransactionId']}", record)]
        approval = record["transaction"]["signals"].get("approvalArtifact")
        if approval is not None:
            # Parmana retains the approval inside the Trust Record it authorized,
            # under the record's signature, so it is resolved from there.
            refs.append(
                entry(
                    "approval-outcome",
                    f"trust-records/{record['businessTransactionId']}"
                    "#/transaction/signals/approvalArtifact",
                    approval,
                )
            )
        return refs
    return [entry("authorized-intent", f"refusal/{record['businessTransactionId']}", record)]
