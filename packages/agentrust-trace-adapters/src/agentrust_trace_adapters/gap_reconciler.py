"""Reconcile a TRACE receipt chain that may contain ``GapDisclosure/1.0``.

This is the library extraction of ``trace-spec`` section 3.3.4
(``trace-spec@b938790f7f46d3a943c76a5360d2de60bb72112c``) for
``agentrust-io/integrations#416``. It does not change ``ca2a`` or ``cmcp``,
and it does not authorize a retry.

Four rules from the contract review are enforced here:

1. A missing required hop with no disclosure is ``receipt_missing_required``.
   ``receipt_gap_disclosed`` requires an authenticated issuer, stream binding,
   and a two-sided splice. A tail disclosure is ``gap_disclosure_unverified``:
   not coverage, and not automatically invalid.
2. A disclosure proves a position in the chain. It does not prove which
   credential ran. Credential coverage is judged only against an independently
   retained ``expected_credential_ids`` inventory, and a disclosure covers an
   inventory entry only when its signed ``credential_id`` binds that entry.
   ``chain[:2]`` does not imply a third credential.
3. ``cause`` and ``receipts_lost_estimate`` are descriptive. A ``lease_id`` in
   ``cause``, or an emitter-asserted fencing epoch, never selects an outcome,
   proves non-execution, or authorizes retry. ``effect_status`` stays
   ``unknown``.
4. ``predecessor_present``, ``successor_present``, ``permitted_ancestor_key_ids``
   and ``claimed_absent_but_present`` are not inputs. Presence, the seal,
   ancestor entitlement and contradiction are derived from authenticated chain
   elements. Untrusted JSON is parsed with duplicate-key, non-finite, depth
   and size bounds.

Ancestor entitlement is not a caller-supplied id list. A ``KeyHierarchy/1.0``
element counts only when the ancestor key verifies its signature. That carrier
is this library's explicit binding for section 3.2.1; it is not a TRACE record
type and it is not a ``ca2a`` wire change.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "COMPLETE",
    "CredentialCoverage",
    "DISCLOSURE_TYPE",
    "DisclosureVerdict",
    "EFFECT_UNKNOWN",
    "GAP_DISCLOSURE_UNVERIFIED",
    "HIERARCHY_TYPE",
    "INVENTORY_NOT_SUPPLIED",
    "MalformedInput",
    "RECEIPT_GAP_DISCLOSED",
    "RECEIPT_INVALID",
    "RECEIPT_MISSING_REQUIRED",
    "RECEIPT_PRESENT",
    "Reconciliation",
    "element_digest",
    "parse_untrusted_json",
    "reconcile_chain",
    "verify_disclosure",
]

RECEIPT_GAP_DISCLOSED = "receipt_gap_disclosed"
RECEIPT_MISSING_REQUIRED = "receipt_missing_required"
GAP_DISCLOSURE_UNVERIFIED = "gap_disclosure_unverified"
RECEIPT_INVALID = "receipt_invalid"
RECEIPT_PRESENT = "receipt_present"
COMPLETE = "complete"
INVENTORY_NOT_SUPPLIED = "inventory_not_supplied"
EFFECT_UNKNOWN = "unknown"
DISCLOSURE_TYPE = "GapDisclosure/1.0"
HIERARCHY_TYPE = "KeyHierarchy/1.0"

_SAFE_INT = 2**53 - 1
_MAX_ELEMENT_BYTES = 65_536
_MAX_CHAIN_ELEMENTS = 256
_MAX_DEPTH = 32
_MAX_KEYS = 64
_MAX_ARRAY = 256
_MAX_STRING = 16_384
_MAX_CAUSE = 512
_MAX_ID = 512
_STATUSES = frozenset(
    {
        RECEIPT_GAP_DISCLOSED,
        RECEIPT_MISSING_REQUIRED,
        GAP_DISCLOSURE_UNVERIFIED,
        RECEIPT_INVALID,
        RECEIPT_PRESENT,
    }
)
_SEVERITY = (
    RECEIPT_INVALID,
    RECEIPT_MISSING_REQUIRED,
    GAP_DISCLOSURE_UNVERIFIED,
    RECEIPT_GAP_DISCLOSED,
    RECEIPT_PRESENT,
)


class MalformedInput(ValueError):
    """Untrusted input failed a bound or a parse rule.

    This is not a verification finding. A finding means the element was read
    and judged. Malformed input is refused before that judgment.
    """


@dataclass(frozen=True)
class DisclosureVerdict:
    """One disclosure, judged from the chain rather than from fixture assertions."""

    status: str
    controller_outcome: str
    effect_status: str
    retry_authorized: bool
    failures: tuple[str, ...]
    warnings: tuple[str, ...]
    consecutive_disclosures: int
    linked_predecessor: str | None
    cause: str | None
    receipts_lost_estimate: int | None
    bound_credential_id: str | None
    derived_predecessor_present: bool
    derived_successor_present: bool
    derived_ancestor_key_ids: tuple[str, ...]
    derived_contradicting_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise MalformedInput(f"internal status {self.status!r} is not a disclosure outcome")
        if self.effect_status != EFFECT_UNKNOWN or self.retry_authorized:
            raise MalformedInput("effect status is unknown and retry is not authorized")
        if self.controller_outcome != EFFECT_UNKNOWN:
            raise MalformedInput("controller outcome is unknown")

    def as_fixture_dict(self) -> dict[str, Any]:
        """The outcome shape pinned by the section 3.3.4 fixtures."""
        return {
            "status": self.status,
            "controller_outcome": self.controller_outcome,
            "failures": list(self.failures),
            "warnings": list(self.warnings),
            "consecutive_disclosures": self.consecutive_disclosures,
            "linked_predecessor": self.linked_predecessor,
            "cause": self.cause,
        }


@dataclass(frozen=True)
class CredentialCoverage:
    """Coverage of one inventory entry. A disclosure does not prove it ran."""

    credential_id: str
    status: str

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise MalformedInput(f"internal status {self.status!r} is not a coverage outcome")


@dataclass(frozen=True)
class Reconciliation:
    """Chain reconciliation. ``retry_authorized`` is always false in this slice."""

    status: str
    effect_status: str
    retry_authorized: bool
    accepted_as_complete: bool
    policy_accepted: bool
    inventory_supplied: bool
    disclosures: tuple[DisclosureVerdict, ...]
    credentials: tuple[CredentialCoverage, ...]
    failures: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.effect_status != EFFECT_UNKNOWN or self.retry_authorized:
            raise MalformedInput("effect status is unknown and retry is not authorized")


def parse_untrusted_json(data: bytes | str) -> dict[str, Any]:
    """Parse one JSON object. Duplicate keys, non-finite numbers and oversize input fail closed."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    else:
        raise MalformedInput("untrusted JSON must be bytes or str")
    if not raw:
        raise MalformedInput("untrusted JSON is empty")
    if len(raw) > _MAX_ELEMENT_BYTES:
        raise MalformedInput("untrusted JSON exceeds the size bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedInput("untrusted JSON is not UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except RecursionError as exc:
        raise MalformedInput("JSON nesting exceeds the bound") from exc
    except MalformedInput:
        raise
    except ValueError as exc:
        raise MalformedInput("untrusted JSON is not a JSON document") from exc
    if not isinstance(parsed, dict):
        raise MalformedInput("untrusted JSON must be an object")
    _walk_bounds(parsed, 0)
    return parsed


def element_digest(element: Mapping[str, Any]) -> str:
    """Chain digest over the element's full canonical form, signature included."""
    try:
        canonical = rfc8785.dumps(dict(element))
    except (TypeError, ValueError) as exc:
        raise MalformedInput("chain element is not RFC 8785 canonicalizable") from exc
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def verify_disclosure(
    disclosure: bytes | str | Mapping[str, Any],
    chain: Sequence[bytes | str | Mapping[str, Any]],
    *,
    session_id: str,
    trusted_issuer_keys: Mapping[str, Mapping[str, Any]],
) -> DisclosureVerdict:
    """Judge one disclosure. Chain facts are derived; fixture booleans are ignored."""
    session = _required_id("session_id", session_id)
    keys = _trust_store(trusted_issuer_keys)
    element = _as_object(disclosure)
    elements = _chain_objects(chain)
    return _judge_disclosure(element, elements, session, keys)


def reconcile_chain(
    elements: Sequence[bytes | str],
    *,
    session_id: str,
    trusted_issuer_keys: Mapping[str, Mapping[str, Any]],
    expected_credential_ids: Sequence[str] | None = None,
    completeness_required: bool = False,
    accept_disclosed_gaps: bool = False,
) -> Reconciliation:
    """Reconcile hop records and disclosures against an optional credential inventory.

    ``expected_credential_ids`` is the independently retained inventory. Omitting
    it does not infer missing hops from ``len(elements)``. A disclosure covers an
    inventory entry only through its signed ``credential_id``. That binding is
    attested absence, not proof the credential ran.
    """
    session = _required_id("session_id", session_id)
    if type(completeness_required) is not bool or type(accept_disclosed_gaps) is not bool:
        raise MalformedInput("policy flags must be bool")
    keys = _trust_store(trusted_issuer_keys)
    parsed = _chain_objects(elements, bytes_only=True)
    inventory = _inventory(expected_credential_ids)
    disclosures = tuple(
        _judge_disclosure(element, parsed, session, keys)
        for element in parsed
        if _is_disclosure_candidate(element)
    )
    credentials = _cover_credentials(parsed, disclosures, inventory, session, keys)
    status = _aggregate(disclosures, credentials, inventory is not None)
    failures = tuple(
        dict.fromkeys(code for verdict in disclosures for code in verdict.failures)
    )
    complete = _is_complete(credentials, disclosures, inventory is not None)
    policy_accepted = _policy_accepted(
        credentials,
        disclosures,
        inventory is not None,
        completeness_required=completeness_required,
        accept_disclosed_gaps=accept_disclosed_gaps,
        complete=complete,
    )
    return Reconciliation(
        status=status,
        effect_status=EFFECT_UNKNOWN,
        retry_authorized=False,
        accepted_as_complete=complete,
        policy_accepted=policy_accepted,
        inventory_supplied=inventory is not None,
        disclosures=disclosures,
        credentials=credentials,
        failures=failures,
    )


def _judge_disclosure(
    disclosure: Mapping[str, Any],
    elements: Sequence[Mapping[str, Any]],
    session_id: str,
    keys: Mapping[str, Ed25519PublicKey],
) -> DisclosureVerdict:
    _reject_descriptive_shape(disclosure)
    digest = element_digest(disclosure)
    indexes = [i for i, element in enumerate(elements) if element_digest(element) == digest]
    disclosure_index = indexes[0] if len(indexes) == 1 else None
    if len(indexes) > 1:
        raise MalformedInput("duplicate chain element digest")

    predecessor = _element_by_digest(elements, disclosure.get("previous_receipt_hash"), disclosure_index)
    successor = _successor(elements, disclosure_index)
    ancestors = _authenticated_ancestors(elements, keys)
    predecessor_issuer = _authenticated_issuer(predecessor, keys)
    derived_ancestors = ancestors.get(predecessor_issuer, ()) if predecessor_issuer else ()
    contradicting = _contradicting(
        elements,
        predecessor,
        successor,
        disclosure_index,
        digest,
    )

    failures: list[str] = []
    warnings: list[str] = []
    issuer_key_id = disclosure.get("issuer_key_id")
    if not isinstance(issuer_key_id, str) or issuer_key_id not in keys:
        warnings.append("disclosure_key_unknown")
    elif not _signature_holds(disclosure, keys[issuer_key_id]):
        failures.append("disclosure_signature_invalid")

    if disclosure.get("type") != DISCLOSURE_TYPE:
        failures.append("disclosure_type_unsupported")
    if _descriptive_malformed(disclosure):
        failures.append("disclosure_descriptive_field_malformed")
    if predecessor is None or predecessor_issuer is None:
        failures.append("disclosure_predecessor_absent")
    elif issuer_key_id not in {predecessor_issuer, *derived_ancestors}:
        failures.append("disclosure_issuer_not_chain_key")
    if disclosure.get("session_id") != session_id:
        failures.append("disclosure_stream_mismatch")
    if contradicting:
        failures.append("disclosure_contradicted")
    if successor is None:
        warnings.append("disclosure_not_yet_sealed")
    elif successor.get("previous_receipt_hash") != digest:
        failures.append("disclosure_not_sealed_by_successor")

    if failures:
        status = RECEIPT_INVALID
    elif warnings:
        status = GAP_DISCLOSURE_UNVERIFIED
    else:
        status = RECEIPT_GAP_DISCLOSED
        warnings = [RECEIPT_GAP_DISCLOSED]

    cause = disclosure.get("cause")
    estimate = disclosure.get("receipts_lost_estimate", None)
    bound = disclosure.get("credential_id")
    return DisclosureVerdict(
        status=status,
        controller_outcome=EFFECT_UNKNOWN,
        effect_status=EFFECT_UNKNOWN,
        retry_authorized=False,
        failures=tuple(failures),
        warnings=tuple(warnings),
        consecutive_disclosures=_consecutive(elements, disclosure_index),
        linked_predecessor=disclosure.get("previous_receipt_hash")
        if isinstance(disclosure.get("previous_receipt_hash"), str)
        else None,
        cause=cause if isinstance(cause, str) else None,
        receipts_lost_estimate=estimate if type(estimate) is int else None,
        bound_credential_id=bound if isinstance(bound, str) else None,
        derived_predecessor_present=predecessor is not None and predecessor_issuer is not None,
        derived_successor_present=successor is not None,
        derived_ancestor_key_ids=tuple(derived_ancestors),
        derived_contradicting_digests=tuple(dict.fromkeys(contradicting)),
    )


def _cover_credentials(
    elements: Sequence[Mapping[str, Any]],
    disclosures: Sequence[DisclosureVerdict],
    inventory: Sequence[str] | None,
    session_id: str,
    keys: Mapping[str, Ed25519PublicKey],
) -> tuple[CredentialCoverage, ...]:
    if inventory is None:
        return ()
    coverage: list[CredentialCoverage] = []
    for credential_id in inventory:
        hops = [
            element
            for element in elements
            if element.get("credential_id") == credential_id and not _skipped_for_coverage(element)
        ]
        verified = [
            element
            for element in hops
            if element.get("session_id") == session_id
            and _hop_signature_holds(element, keys)
        ]
        forged = [
            element
            for element in hops
            if isinstance(element.get("issuer_key_id"), str)
            and element["issuer_key_id"] in keys
            and not _signature_holds(element, keys[element["issuer_key_id"]])
        ]
        bound = [item for item in disclosures if item.bound_credential_id == credential_id]
        if any(item.status == RECEIPT_INVALID for item in bound) or forged or len(verified) > 1:
            # A second verified hop is not a fenced retry. Fence epochs are ignored.
            status = RECEIPT_INVALID
        elif verified:
            status = RECEIPT_PRESENT
        elif any(item.status == RECEIPT_GAP_DISCLOSED for item in bound):
            status = RECEIPT_GAP_DISCLOSED
        elif any(item.status == GAP_DISCLOSURE_UNVERIFIED for item in bound):
            status = GAP_DISCLOSURE_UNVERIFIED
        else:
            status = RECEIPT_MISSING_REQUIRED
        coverage.append(CredentialCoverage(credential_id, status))
    return tuple(coverage)


def _aggregate(
    disclosures: Sequence[DisclosureVerdict],
    credentials: Sequence[CredentialCoverage],
    inventory_supplied: bool,
) -> str:
    if _is_complete(credentials, disclosures, inventory_supplied):
        return COMPLETE
    statuses = [item.status for item in disclosures]
    statuses.extend(item.status for item in credentials)
    for status in _SEVERITY:
        if status in statuses:
            return status
    return INVENTORY_NOT_SUPPLIED


def _is_complete(
    credentials: Sequence[CredentialCoverage],
    disclosures: Sequence[DisclosureVerdict],
    inventory_supplied: bool,
) -> bool:
    return bool(
        inventory_supplied
        and credentials
        and not disclosures
        and all(item.status == RECEIPT_PRESENT for item in credentials)
    )


def _policy_accepted(
    credentials: Sequence[CredentialCoverage],
    disclosures: Sequence[DisclosureVerdict],
    inventory_supplied: bool,
    *,
    completeness_required: bool,
    accept_disclosed_gaps: bool,
    complete: bool,
) -> bool:
    if not inventory_supplied:
        return False
    if completeness_required:
        return complete
    if any(item.status in {RECEIPT_INVALID, RECEIPT_MISSING_REQUIRED, GAP_DISCLOSURE_UNVERIFIED} for item in credentials):
        return False
    if any(item.status in {RECEIPT_INVALID, GAP_DISCLOSURE_UNVERIFIED} for item in disclosures):
        return False
    if any(item.status == RECEIPT_GAP_DISCLOSED for item in (*credentials, *disclosures)):
        return accept_disclosed_gaps
    return complete or bool(credentials)


def _authenticated_ancestors(
    elements: Sequence[Mapping[str, Any]],
    keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, tuple[str, ...]]:
    found: dict[str, list[str]] = {}
    for element in elements:
        if element.get("type") != HIERARCHY_TYPE:
            continue
        ancestor = element.get("ancestor_key_id")
        subject = element.get("subject_key_id")
        issuer = element.get("issuer_key_id")
        if not all(isinstance(value, str) and value for value in (ancestor, subject, issuer)):
            continue
        if ancestor != issuer or ancestor not in keys:
            continue
        if not _signature_holds(element, keys[ancestor]):
            continue
        bucket = found.setdefault(subject, [])
        if ancestor not in bucket:
            bucket.append(ancestor)
    return {subject: tuple(ancestors) for subject, ancestors in found.items()}


def _authenticated_issuer(
    element: Mapping[str, Any] | None,
    keys: Mapping[str, Ed25519PublicKey],
) -> str | None:
    if element is None:
        return None
    issuer = element.get("issuer_key_id")
    if not isinstance(issuer, str) or not issuer:
        return None
    if issuer not in keys:
        # Section 3.3.2: the verifier not holding the key is not proof of forgery.
        # The id is still the id bound into the element digest.
        return issuer
    if not _signature_holds(element, keys[issuer]):
        return None
    return issuer


def _element_by_digest(
    elements: Sequence[Mapping[str, Any]],
    digest: Any,
    skip_index: int | None,
) -> Mapping[str, Any] | None:
    if not isinstance(digest, str):
        return None
    found: list[Mapping[str, Any]] = []
    for index, element in enumerate(elements):
        if index == skip_index:
            continue
        if element_digest(element) == digest:
            found.append(element)
    if len(found) > 1:
        raise MalformedInput("duplicate chain element digest")
    return found[0] if found else None


def _successor(
    elements: Sequence[Mapping[str, Any]],
    disclosure_index: int | None,
) -> Mapping[str, Any] | None:
    if disclosure_index is None:
        return None
    for element in elements[disclosure_index + 1 :]:
        if element.get("type") == HIERARCHY_TYPE:
            continue
        return element
    return None


def _consecutive(elements: Sequence[Mapping[str, Any]], disclosure_index: int | None) -> int:
    if disclosure_index is None:
        return 1
    count = 0
    index = disclosure_index
    while index >= 0:
        element = elements[index]
        if element.get("type") == HIERARCHY_TYPE:
            index -= 1
            continue
        if index != disclosure_index and _gap_type(element) is None:
            break
        count += 1
        index -= 1
    return count


def _contradicting(
    elements: Sequence[Mapping[str, Any]],
    predecessor: Mapping[str, Any] | None,
    successor: Mapping[str, Any] | None,
    disclosure_index: int | None,
    disclosure_digest: str,
) -> list[str]:
    if predecessor is None or disclosure_index is None:
        return []
    predecessor_index = _index_of(elements, predecessor)
    if predecessor_index is None:
        return []
    hits: list[str] = []
    right = disclosure_index
    if successor is not None:
        successor_index = _index_of(elements, successor)
        if successor_index is not None:
            right = successor_index
    start, end = sorted((predecessor_index, right))
    for index in range(start + 1, end):
        if index == disclosure_index:
            continue
        element = elements[index]
        if element.get("type") == HIERARCHY_TYPE or _gap_type(element) is not None:
            continue
        hits.append(element_digest(element))
    predecessor_sequence = _sequence(predecessor)
    successor_sequence = _sequence(successor) if successor is not None else None
    if (
        predecessor_sequence is not None
        and successor_sequence is not None
        and predecessor_sequence < successor_sequence
    ):
        for index, element in enumerate(elements):
            if index in {predecessor_index, disclosure_index} or element is successor:
                continue
            if element.get("type") == HIERARCHY_TYPE or _gap_type(element) is not None:
                continue
            sequence = _sequence(element)
            digest = element_digest(element)
            if sequence is not None and predecessor_sequence < sequence < successor_sequence:
                if digest != disclosure_digest:
                    hits.append(digest)
    return hits


def _index_of(
    elements: Sequence[Mapping[str, Any]],
    target: Mapping[str, Any],
) -> int | None:
    target_digest = element_digest(target)
    for index, element in enumerate(elements):
        if element_digest(element) == target_digest:
            return index
    return None


def _sequence(element: Mapping[str, Any] | None) -> int | None:
    if element is None:
        return None
    value = element.get("sequence")
    if type(value) is int and -_SAFE_INT <= value <= _SAFE_INT:
        return value
    return None


def _gap_type(element: Mapping[str, Any]) -> str | None:
    kind = element.get("type")
    if isinstance(kind, str) and kind.startswith("GapDisclosure"):
        return kind
    return None


def _is_disclosure_candidate(element: Mapping[str, Any]) -> bool:
    """A typed disclosure, or a typeless object with the disclosure members.

    Vector 20 omits ``type``. A presence check would skip it; an equality check
    has to see it. Hop records in this slice carry ``credential_id`` and are
    not candidates.
    """
    if _gap_type(element) is not None:
        return True
    if "type" in element or "credential_id" in element:
        return False
    return all(
        isinstance(element.get(field), str)
        for field in ("previous_receipt_hash", "issuer_key_id", "signature")
    )


def _skipped_for_coverage(element: Mapping[str, Any]) -> bool:
    return element.get("type") == HIERARCHY_TYPE or _gap_type(element) is not None


def _hop_signature_holds(element: Mapping[str, Any], keys: Mapping[str, Ed25519PublicKey]) -> bool:
    issuer = element.get("issuer_key_id")
    if not isinstance(issuer, str) or issuer not in keys:
        return False
    return _signature_holds(element, keys[issuer])


def _signature_holds(element: Mapping[str, Any], key: Ed25519PublicKey) -> bool:
    raw = _canonical_b64url(element.get("signature"))
    if raw is None:
        return False
    body = {field: value for field, value in element.items() if field != "signature"}
    try:
        signed = rfc8785.dumps(body)
    except (TypeError, ValueError):
        return False
    try:
        key.verify(raw, signed)
    except (InvalidSignature, ValueError):
        return False
    return True


def _reject_descriptive_shape(disclosure: Mapping[str, Any]) -> None:
    """Shape gate only. Values that pass are never read again to choose a status."""
    if "credential_id" in disclosure:
        credential_id = disclosure.get("credential_id")
        if type(credential_id) is not str or not credential_id or len(credential_id) > _MAX_ID:
            raise MalformedInput("credential_id binding is malformed")
    cause = disclosure.get("cause", None)
    if "cause" in disclosure and cause is not None and type(cause) is not str:
        return
    if isinstance(cause, str) and len(cause) > _MAX_CAUSE:
        return
    estimate = disclosure.get("receipts_lost_estimate", None)
    if "receipts_lost_estimate" in disclosure and estimate is not None and type(estimate) is not int:
        return
    if type(estimate) is int and not -_SAFE_INT <= estimate <= _SAFE_INT:
        return


def _descriptive_malformed(disclosure: Mapping[str, Any]) -> bool:
    if "cause" in disclosure and disclosure.get("cause") is not None:
        cause = disclosure.get("cause")
        if type(cause) is not str or len(cause) > _MAX_CAUSE:
            return True
    if "receipts_lost_estimate" not in disclosure:
        return False
    estimate = disclosure.get("receipts_lost_estimate")
    if estimate is None:
        return False
    if type(estimate) is not int or not -_SAFE_INT <= estimate <= _SAFE_INT:
        return True
    return False


def _chain_objects(
    chain: Sequence[bytes | str | Mapping[str, Any]],
    *,
    bytes_only: bool = False,
) -> list[dict[str, Any]]:
    if isinstance(chain, (str, bytes, bytearray)) or not isinstance(chain, Sequence):
        raise MalformedInput("chain must be a sequence of elements")
    if len(chain) > _MAX_CHAIN_ELEMENTS:
        raise MalformedInput("chain exceeds the length bound")
    parsed: list[dict[str, Any]] = []
    digests: set[str] = set()
    for element in chain:
        if bytes_only and isinstance(element, Mapping):
            raise MalformedInput("reconcile_chain accepts JSON bytes, not pre-parsed objects")
        obj = _as_object(element)
        digest = element_digest(obj)
        if digest in digests:
            raise MalformedInput("duplicate chain element digest")
        digests.add(digest)
        parsed.append(obj)
    return parsed


def _as_object(element: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(element, Mapping):
        if not isinstance(element, dict):
            element = dict(element)
        _walk_bounds(element, 0)
        return element
    return parse_untrusted_json(element)


def _inventory(expected: Sequence[str] | None) -> tuple[str, ...] | None:
    if expected is None:
        return None
    if isinstance(expected, (str, bytes)) or not isinstance(expected, Sequence):
        raise MalformedInput("expected_credential_ids must be a sequence of credential ids")
    if len(expected) > _MAX_CHAIN_ELEMENTS:
        raise MalformedInput("expected credential inventory exceeds the length bound")
    ids: list[str] = []
    for credential_id in expected:
        ids.append(_required_id("expected credential id", credential_id))
    if len(set(ids)) != len(ids):
        raise MalformedInput("expected credential inventory has a duplicate id")
    return tuple(ids)


def _required_id(name: str, value: Any) -> str:
    if type(value) is not str or not value or len(value) > _MAX_ID or "\x00" in value:
        raise MalformedInput(f"{name} must be a non-empty string")
    return value


def _trust_store(trusted: Mapping[str, Mapping[str, Any]]) -> dict[str, Ed25519PublicKey]:
    if not isinstance(trusted, Mapping):
        raise MalformedInput("trusted_issuer_keys must be a mapping")
    store: dict[str, Ed25519PublicKey] = {}
    for key_id, jwk in trusted.items():
        if type(key_id) is not str or not key_id or len(key_id) > _MAX_ID:
            raise MalformedInput("trusted issuer key id is malformed")
        store[key_id] = _public_key(jwk)
    return store


def _public_key(jwk: Mapping[str, Any]) -> Ed25519PublicKey:
    if not isinstance(jwk, Mapping):
        raise MalformedInput("trusted issuer key is not a JWK object")
    if any(field in jwk for field in ("d", "priv", "p", "q")):
        raise MalformedInput("private key material is not a trust anchor")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise MalformedInput("trusted issuer key is not Ed25519")
    raw = _canonical_b64url(jwk.get("x"))
    if raw is None or len(raw) != 32:
        raise MalformedInput("trusted issuer key has a malformed x")
    return Ed25519PublicKey.from_public_bytes(raw)


def _canonical_b64url(encoded: Any) -> bytes | None:
    if type(encoded) is not str or not encoded or "=" in encoded:
        return None
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if any(char not in alphabet for char in encoded):
        return None
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (binascii.Error, ValueError):
        return None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        return None
    return raw


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MalformedInput(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_non_finite(name: str) -> Any:
    raise MalformedInput(f"non-finite JSON number {name}")


def _walk_bounds(value: Any, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise MalformedInput("JSON nesting exceeds the bound")
    if isinstance(value, dict):
        if len(value) > _MAX_KEYS:
            raise MalformedInput("JSON object exceeds the key bound")
        for key, item in value.items():
            if type(key) is not str or len(key) > _MAX_STRING:
                raise MalformedInput("JSON object key exceeds the bound")
            _walk_bounds(item, depth + 1)
        return
    if isinstance(value, list):
        if len(value) > _MAX_ARRAY:
            raise MalformedInput("JSON array exceeds the length bound")
        for item in value:
            _walk_bounds(item, depth + 1)
        return
    if type(value) is int:
        if not -_SAFE_INT <= value <= _SAFE_INT:
            raise MalformedInput("integer outside the safe range")
        return
    if type(value) is float:
        raise MalformedInput("non-integral JSON number")
    if type(value) is str:
        if len(value) > _MAX_STRING:
            raise MalformedInput("JSON string exceeds the bound")
        return
    if value is None or type(value) is bool:
        return
    raise MalformedInput("unsupported JSON value")
