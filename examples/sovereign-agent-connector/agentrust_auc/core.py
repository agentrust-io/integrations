"""Minimal AUCP composition and offline-verification experiment.

This deliberately does not define a production protocol. It demonstrates the six
bindings identified in docs/standards-gap.md while reusing cA2A delegation
verification and the TRACE Registry inclusion algorithm.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

import rfc8785
from ca2a_runtime.delegation.credential import (
    DelegationCredential,
    new_keypair,
    verify_chain,
)
from ca2a_runtime.errors import CA2AError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from trace_verify import canonical_claim_bytes, verify_inclusion

PROFILE = "https://agentrust-io.com/profiles/aucp/v0.1"
REQUIRED_BOUNDARIES = ("agreement", "delegation", "appraisal", "enforcement")


class BundleError(ValueError):
    """An experiment bundle fails closed."""


@dataclass(frozen=True)
class BundleTrustAnchors:
    """Out-of-band public keys trusted by an AUCP bundle consumer."""

    owner: str
    appraisal_verifier: str
    placement_operator: str
    pep: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BundleTrustAnchors:
        try:
            return cls(**{field: value[field] for field in cls.__dataclass_fields__})
        except (KeyError, TypeError) as exc:
            raise BundleError("base trust anchors are incomplete") from exc


@dataclass(frozen=True)
class ExperimentResult:
    bundle: dict[str, Any]
    dispatched: tuple[str, ...]
    trust_anchors: BundleTrustAnchors


def _canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


def _sign(body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = dict(body)
    signed["issuer_key"] = _public_hex(key)
    signed["signature"] = _b64(key.sign(_canonical(signed)))
    return signed


def _verify_signed(value: dict[str, Any], trusted_key_hex: str) -> None:
    if value.get("issuer_key") != trusted_key_hex:
        raise BundleError("signed artifact issuer does not match its pinned trust key")
    signature = value.get("signature")
    if not isinstance(signature, str):
        raise BundleError("signed artifact has no signature")
    body = {key: item for key, item in value.items() if key != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_key_hex)).verify(
            _unb64(signature), _canonical(body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise BundleError("signed artifact signature is invalid") from exc


def _credential_dict(credential: DelegationCredential) -> dict[str, Any]:
    return {**credential.body(), "signature": credential.signature}


def _verify_chain_pinned(
    chain: list[DelegationCredential], trusted_root_issuer: str
) -> None:
    if not chain or chain[0].issuer != trusted_root_issuer:
        raise BundleError("delegation chain root does not match its trust anchor")
    verify_chain(chain, trusted_root_issuers=(trusted_root_issuer,))


def _merkle_parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _leaf(value: dict[str, Any]) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_claim_bytes(value)).digest()


def _two_leaf_registry(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    left, right = _leaf(first), _leaf(second)
    root = _merkle_parent(left, right)
    return {
        "root": "sha256:" + root.hex(),
        "leaf_count": 2,
        "proofs": [
            {"leaf_index": 0, "audit_path": ["sha256:" + right.hex()]},
            {"leaf_index": 1, "audit_path": ["sha256:" + left.hex()]},
        ],
    }


def _project_agreement(agreement: dict[str, Any]) -> dict[str, frozenset[str]]:
    try:
        constraints = agreement["odrl"]["permission"][0]["constraints"]
        return {
            "actions": frozenset(constraints["actions"]),
            "purposes": frozenset(constraints["purposes"]),
            "jurisdictions": frozenset(constraints["jurisdictions"]),
            "destinations": frozenset(constraints["destinations"]),
            "obligations": frozenset(constraints["obligations"]),
        }
    except (KeyError, IndexError, TypeError) as exc:
        raise BundleError("agreement cannot be projected") from exc


def _effective_policy(
    agreement: dict[str, Any],
    chain: list[DelegationCredential],
    appraisal: dict[str, Any],
    trusted_root_issuer: str,
) -> dict[str, Any]:
    projected = _project_agreement(agreement)
    _verify_chain_pinned(chain, trusted_root_issuer)
    leaf_scope = chain[-1].scope
    actions = projected["actions"].intersection(leaf_scope)
    if not actions:
        raise BundleError("delegated authority has no action permitted by the agreement")
    if appraisal.get("workload_key") != chain[-1].subject:
        raise BundleError("appraisal workload key does not match delegation leaf")
    return {
        "actions": sorted(actions),
        "purposes": sorted(projected["purposes"]),
        "jurisdictions": sorted(projected["jurisdictions"]),
        "destinations": sorted(projected["destinations"]),
        "obligations": sorted(projected["obligations"]),
        "appraised_jurisdiction": appraisal["jurisdiction"],
    }


def _decide(policy: dict[str, Any], action: dict[str, str]) -> tuple[str, str]:
    checks = (
        action["operation"] in policy["actions"],
        action["purpose"] in policy["purposes"],
        action["destination"] in policy["destinations"],
        action["jurisdiction"] in policy["jurisdictions"],
        action["jurisdiction"] == policy["appraised_jurisdiction"],
    )
    return ("allow", "dispatched") if all(checks) else ("deny", "not_dispatched")


def build_experiment(
    dispatch: Callable[[dict[str, str]], None] | None = None,
    *,
    workload_public_key: str | None = None,
    attestation_report: Any | None = None,
    evidence_appraisal: Any | None = None,
    placement_assertion: dict[str, Any] | None = None,
    placement_trust_key: str | None = None,
) -> ExperimentResult:
    """Build one allowed and one denied trajectory using deterministic fixtures."""
    owner_key, owner_public = new_keypair()
    lead_key, lead_public = new_keypair()
    if workload_public_key is None:
        _, child_public = new_keypair()
    else:
        child_public = workload_public_key
    verifier_key, verifier_public = new_keypair()
    placement_key, placement_public = new_keypair()
    pep_key, pep_public = new_keypair()

    agreement = _sign(
        {
            "type": "odrl:Agreement",
            "profile": PROFILE,
            "agreement_id": "urn:uuid:agreement-fr-health-001",
            "assignee_key": lead_public,
            "odrl": {
                "permission": [
                    {
                        "target": "urn:dataset:synthetic-french-health",
                        "action": "use",
                        "constraints": {
                            "actions": ["summary:create"],
                            "purposes": ["clinical-summarization"],
                            "jurisdictions": ["FR"],
                            "destinations": ["approved-model-fr"],
                            "obligations": ["emit:usage-control-receipt"],
                        },
                    }
                ]
            },
        },
        owner_key,
    )
    agreement_hash = _digest(agreement)

    root = DelegationCredential(
        credential_id="delegation-root-001",
        issuer=owner_public,
        subject=lead_public,
        scope=frozenset({"summary:create"}),
        depth=0,
    ).sign(owner_key)
    child = DelegationCredential(
        credential_id="delegation-child-001",
        issuer=lead_public,
        subject=child_public,
        scope=frozenset({"summary:create"}),
        depth=1,
        parent_id=root.credential_id,
    ).sign(lead_key)
    chain = [root, child]
    _verify_chain_pinned(chain, owner_public)
    chain_wire = [_credential_dict(item) for item in chain]
    chain_hash = _digest(chain_wire)

    from cmcp_runtime.tee.base import SoftwareOnlyProvider, make_nonce
    from cmcp_runtime.tee.nras import AppraisalResult

    from .appraisal import AppraisalPolicy, create_attestation_result, make_placement_assertion

    report = attestation_report or SoftwareOnlyProvider().get_attestation_report(
        make_nonce(bytes.fromhex(child_public), b"\x00" * 32)
    )
    now = datetime.now(tz=UTC)
    if placement_assertion is None:
        placement_assertion = make_placement_assertion(
            workload_key=child_public,
            jurisdiction="FR",
            operator="synthetic-fr-operator",
            issued_at=now,
            validity_seconds=300,
            signing_key=placement_key,
        )
    elif placement_trust_key is None:
        raise BundleError("external placement assertion requires its trust key")
    effective_placement_trust_key = placement_trust_key or placement_public
    appraisal = create_attestation_result(
        report=report,
        appraisal=evidence_appraisal
        or AppraisalResult(
            status="warning",
            verifier="urn:agentrust:verifier:software-mve",
            timestamp=now.isoformat(),
            ear_raw={"status": "warning", "reason": "software-only-development-evidence"},
        ),
        workload_key=child_public,
        placement_assertion=placement_assertion,
        placement_trust_key=effective_placement_trust_key,
        policy=AppraisalPolicy("urn:agentrust:appraisal-policy:software-mve-v1"),
        verifier_signing_key=verifier_key,
        now=now,
    )
    policy = _effective_policy(agreement, chain, appraisal, owner_public)
    effective_policy_hash = _digest(policy)

    actions = (
        {
            "action_id": "urn:uuid:action-allowed-001",
            "operation": "summary:create",
            "purpose": "clinical-summarization",
            "destination": "approved-model-fr",
            "jurisdiction": "FR",
        },
        {
            "action_id": "urn:uuid:action-denied-001",
            "operation": "summary:create",
            "purpose": "clinical-summarization",
            "destination": "eu-branded-us",
            "jurisdiction": "US",
        },
    )
    dispatched: list[str] = []
    receipts: list[dict[str, Any]] = []
    for action in actions:
        decision, dispatch_state = _decide(policy, action)
        if decision == "allow":
            dispatched.append(action["action_id"])
            if dispatch is not None:
                dispatch(action)
        receipt = _sign(
            {
                "type": "auc:UsageControlReceipt",
                "profile": PROFILE,
                "workflow_id": "urn:uuid:workflow-fr-health-001",
                "action": action,
                "agreement_hash": agreement_hash,
                "authority_chain_hash": chain_hash,
                "appraisal_hash": _digest(appraisal),
                "effective_policy_hash": effective_policy_hash,
                "decision": decision,
                "dispatch_state": dispatch_state,
                "boundaries": list(REQUIRED_BOUNDARIES),
            },
            pep_key,
        )
        receipts.append(receipt)

    registry = _two_leaf_registry(receipts[0], receipts[1])
    bundle = {
        "bundle_profile": PROFILE,
        "trust": {
            "owner": owner_public,
            "appraisal_verifier": verifier_public,
            "placement_operator": effective_placement_trust_key,
            "pep": pep_public,
        },
        "agreement": agreement,
        "delegation_chain": chain_wire,
        "appraisal": appraisal,
        "placement_assertion": placement_assertion,
        "effective_policy": policy,
        "receipts": receipts,
        "registry": registry,
    }
    trust_anchors = BundleTrustAnchors(
        owner=owner_public,
        appraisal_verifier=verifier_public,
        placement_operator=effective_placement_trust_key,
        pep=pep_public,
    )
    verify_bundle(bundle, trust_anchors)
    return ExperimentResult(
        bundle=bundle, dispatched=tuple(dispatched), trust_anchors=trust_anchors
    )


_MALFORMED_INPUT_ERRORS = (
    KeyError,
    IndexError,
    TypeError,
    AttributeError,
    OverflowError,
    ValueError,
)


def _fail_closed_as_bundle_error(verify: Callable[..., None]) -> Callable[..., None]:
    """Report every rejection of untrusted input as ``BundleError``.

    Structural errors from malformed JSON and cA2A delegation errors would
    otherwise escape the documented error type while still rejecting the input.
    """

    @functools.wraps(verify)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        try:
            verify(*args, **kwargs)
        except BundleError:
            raise
        except CA2AError as exc:
            raise BundleError(f"delegation chain is invalid: {exc}") from exc
        except _MALFORMED_INPUT_ERRORS as exc:
            raise BundleError(f"bundle is malformed: {type(exc).__name__}: {exc}") from exc

    return wrapper


@_fail_closed_as_bundle_error
def verify_bundle(bundle: dict[str, Any], trust_anchors: BundleTrustAnchors) -> None:
    """Verify signatures, bindings, decisions, completeness, and inclusion offline."""
    try:
        trust = bundle["trust"]
        agreement = bundle["agreement"]
        chain_wire = bundle["delegation_chain"]
        appraisal = bundle["appraisal"]
        placement_assertion = bundle["placement_assertion"]
        receipts = bundle["receipts"]
        registry = bundle["registry"]
    except KeyError as exc:
        raise BundleError(f"bundle is missing {exc.args[0]}") from exc

    expected_trust = {
        "owner": trust_anchors.owner,
        "appraisal_verifier": trust_anchors.appraisal_verifier,
        "placement_operator": trust_anchors.placement_operator,
        "pep": trust_anchors.pep,
    }
    if trust != expected_trust:
        raise BundleError("bundle trust keys do not match out-of-band trust anchors")

    _verify_signed(agreement, trust_anchors.owner)
    chain = [DelegationCredential.from_dict(item) for item in chain_wire]
    _verify_chain_pinned(chain, trust_anchors.owner)
    if agreement.get("assignee_key") != chain[0].subject:
        raise BundleError("agreement assignee is not the delegation root subject")

    from .appraisal import verify_attestation_result

    try:
        evaluated_at = datetime.fromtimestamp(appraisal["evaluated_at"], tz=UTC)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise BundleError("appraisal has no valid evaluation time") from exc
    verify_attestation_result(
        appraisal,
        verifier_trust_key=trust_anchors.appraisal_verifier,
        placement_assertion=placement_assertion,
        placement_trust_key=trust_anchors.placement_operator,
        workload_key=chain[-1].subject,
        now=evaluated_at,
    )

    policy = _effective_policy(agreement, chain, appraisal, trust_anchors.owner)
    if policy != bundle.get("effective_policy"):
        raise BundleError("effective policy does not reproduce from source artifacts")

    expected = {
        "agreement_hash": _digest(agreement),
        "authority_chain_hash": _digest(chain_wire),
        "appraisal_hash": _digest(appraisal),
        "effective_policy_hash": _digest(policy),
    }
    if not isinstance(receipts, list) or len(receipts) != 2:
        raise BundleError("experiment requires exactly two action receipts")
    action_ids: set[str] = set()
    root = bytes.fromhex(registry["root"].split(":", 1)[1])
    for index, receipt in enumerate(receipts):
        _verify_signed(receipt, trust_anchors.pep)
        if receipt.get("profile") != PROFILE:
            raise BundleError("receipt profile is not supported")
        if set(receipt.get("boundaries", [])) != set(REQUIRED_BOUNDARIES):
            raise BundleError("receipt has an incomplete protected-boundary set")
        for field, value in expected.items():
            if receipt.get(field) != value:
                raise BundleError(f"receipt {field} does not bind to bundle artifact")
        action = receipt.get("action")
        if not isinstance(action, dict) or action.get("action_id") in action_ids:
            raise BundleError("receipt action is missing or duplicated")
        action_ids.add(action["action_id"])
        decision, dispatch_state = _decide(policy, action)
        if receipt.get("decision") != decision or receipt.get("dispatch_state") != dispatch_state:
            raise BundleError("receipt decision does not reproduce from effective policy")
        proof = registry["proofs"][index]
        path = [bytes.fromhex(item.split(":", 1)[1]) for item in proof["audit_path"]]
        if not verify_inclusion(receipt, proof["leaf_index"], path, registry["leaf_count"], root):
            raise BundleError("receipt is not included in the registry root")

    decisions = {(item["decision"], item["dispatch_state"]) for item in receipts}
    if decisions != {("allow", "dispatched"), ("deny", "not_dispatched")}:
        raise BundleError("experiment lacks the required allowed and pre-dispatch-denied paths")


def write_bundle(path: str, trust_anchors_path: str | None = None) -> ExperimentResult:
    """Generate, verify, and write the deterministic-shape experiment bundle."""
    result = build_experiment()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result.bundle, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if trust_anchors_path is not None:
        with open(trust_anchors_path, "w", encoding="utf-8") as handle:
            json.dump(asdict(result.trust_anchors), handle, indent=2, sort_keys=True)
            handle.write("\n")
    return result
